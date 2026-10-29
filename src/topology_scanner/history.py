"""
history.py
-----------
Guarda cada escaneo en SQLite y compara el resultado actual con el
escaneo anterior del mismo rango: qué hosts son nuevos, cuáles han
dejado de responder, y qué puertos han cambiado de estado.

No sabe nada de nmap, grafos ni HTML - solo trabaja con el mismo
formato de diccionario que produce scanner.py (resultados[ip] con
"puertos": [{"puerto": .., "servicio": ..}, ...]) y lo persiste/compara.
"""

import json
import sqlite3
from contextlib import closing
from datetime import datetime

from .classifier import PUERTOS_SENSIBLES, puertos_sensibles_abiertos

DB_POR_DEFECTO = "historial.db"
# Ruta del historial para la web (en el clúster, el volumen compartido con el CronJob)
VARIABLE_DB = "TOPOLOGY_HISTORY_DB"
# El CronJob y la web escriben en el mismo archivo: si uno está escribiendo,
# el otro espera hasta este tiempo en vez de fallar con "database is locked"
ESPERA_BLOQUEO_SEGUNDOS = 30


class HistoryError(RuntimeError):
    """Error al leer/escribir el historial de escaneos en SQLite."""


def _crear_tablas(conn: sqlite3.Connection):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS escaneos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rango TEXT NOT NULL,
            fecha TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            escaneo_id INTEGER NOT NULL REFERENCES escaneos(id),
            ip TEXT NOT NULL,
            hostname TEXT,
            mac TEXT,
            vendor TEXT,
            categoria TEXT,
            so TEXT
        );
        CREATE TABLE IF NOT EXISTS puertos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL REFERENCES hosts(id),
            puerto INTEGER NOT NULL,
            servicio TEXT
        );
        CREATE TABLE IF NOT EXISTS ejecuciones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha TEXT NOT NULL,
            origen TEXT NOT NULL,
            topologia TEXT
        );
    """)
    _migrar_a_ejecuciones(conn)


def _migrar_a_ejecuciones(conn: sqlite3.Connection):
    """Historiales de antes de la v1.3.0: cada escaneo era suelto. Se añade
    la columna ejecucion_id y cada escaneo antiguo pasa a ser una ejecución
    de un solo rango (origen "antiguo", sin topología), para que salga en la
    lista de la web sin perder nada."""
    columnas = {fila[1] for fila in conn.execute("PRAGMA table_info(escaneos)")}
    if "ejecucion_id" in columnas:
        return
    conn.execute("ALTER TABLE escaneos ADD COLUMN ejecucion_id INTEGER REFERENCES ejecuciones(id)")
    for escaneo_id, fecha in conn.execute("SELECT id, fecha FROM escaneos").fetchall():
        cur = conn.execute("INSERT INTO ejecuciones (fecha, origen) VALUES (?, 'antiguo')", (fecha,))
        conn.execute("UPDATE escaneos SET ejecucion_id = ? WHERE id = ?", (cur.lastrowid, escaneo_id))
    conn.commit()


def _conectar(db_path: str) -> sqlite3.Connection:
    return sqlite3.connect(db_path, timeout=ESPERA_BLOQUEO_SEGUNDOS)


def _ultimo_escaneo(conn: sqlite3.Connection, rango: str, antes_de: int | None = None):
    """Devuelve {ip: {puerto, puerto, ...}} del escaneo más reciente para
    ese rango, o None si todavía no hay ninguno guardado. Con `antes_de`
    (id de un escaneo), el más reciente anterior a ese: para el diff de una
    ejecución vieja reabierta en la web."""
    if antes_de is None:
        fila = conn.execute(
            "SELECT id FROM escaneos WHERE rango = ? ORDER BY fecha DESC, id DESC LIMIT 1",
            (rango,),
        ).fetchone()
    else:
        fila = conn.execute(
            "SELECT id FROM escaneos WHERE rango = ? AND id < ? ORDER BY fecha DESC, id DESC LIMIT 1",
            (rango, antes_de),
        ).fetchone()
    if fila is None:
        return None
    escaneo_id = fila[0]

    hosts = {}
    for host_id, ip in conn.execute("SELECT id, ip FROM hosts WHERE escaneo_id = ?", (escaneo_id,)):
        puertos = {
            fila_puerto[0]
            for fila_puerto in conn.execute("SELECT puerto FROM puertos WHERE host_id = ?", (host_id,))
        }
        hosts[ip] = puertos
    return hosts


def _guardar_escaneo(conn: sqlite3.Connection, resultados: dict, rango: str, ejecucion_id: int, fecha: str):
    cur = conn.execute(
        "INSERT INTO escaneos (rango, fecha, ejecucion_id) VALUES (?, ?, ?)",
        (rango, fecha, ejecucion_id),
    )
    escaneo_id = cur.lastrowid

    for ip, datos in resultados.items():
        cur = conn.execute(
            "INSERT INTO hosts (escaneo_id, ip, hostname, mac, vendor, categoria, so) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                escaneo_id, ip, datos.get("hostname", ""), datos.get("mac", ""),
                datos.get("vendor", ""), datos.get("categoria", ""), datos.get("so", ""),
            ),
        )
        host_id = cur.lastrowid
        for p in datos.get("puertos", []):
            conn.execute(
                "INSERT INTO puertos (host_id, puerto, servicio) VALUES (?, ?, ?)",
                (host_id, p["puerto"], p.get("servicio", "")),
            )


def _comparar(resultados: dict, anterior: dict | None) -> dict:
    if anterior is None:
        return {"primera_vez": True, "hosts_nuevos": [], "hosts_caidos": [], "puertos_cambiados": {}}

    ips_actuales = set(resultados.keys())
    ips_anteriores = set(anterior.keys())

    puertos_cambiados = {}
    for ip in ips_actuales & ips_anteriores:
        puertos_actuales = {p["puerto"] for p in resultados[ip].get("puertos", [])}
        puertos_antes = anterior[ip]
        nuevos = sorted(puertos_actuales - puertos_antes)
        cerrados = sorted(puertos_antes - puertos_actuales)
        if nuevos or cerrados:
            nuevos_sensibles = [
                {"puerto": p, "motivo": PUERTOS_SENSIBLES[p]}
                for p in nuevos
                if p in PUERTOS_SENSIBLES
            ]
            puertos_cambiados[ip] = {
                "nuevos": nuevos,
                "cerrados": cerrados,
                "nuevos_sensibles": nuevos_sensibles,
            }

    return {
        "primera_vez": False,
        "hosts_nuevos": sorted(ips_actuales - ips_anteriores),
        "hosts_caidos": sorted(ips_anteriores - ips_actuales),
        "puertos_cambiados": puertos_cambiados,
    }


MANTENER_ULTIMOS_POR_DEFECTO = 50


def _purgar_antiguos(conn: sqlite3.Connection, rango: str, mantener: int):
    """Borra los escaneos de `rango` más antiguos que los últimos
    `mantener` (y sus hosts/puertos asociados - no hay ON DELETE CASCADE
    activado). Sin esto, historial.db crece sin límite para siempre."""
    ids_a_borrar = [
        fila[0]
        for fila in conn.execute(
            "SELECT id FROM escaneos WHERE rango = ? ORDER BY fecha DESC, id DESC LIMIT -1 OFFSET ?",
            (rango, mantener),
        )
    ]
    if not ids_a_borrar:
        return

    marcadores = ",".join("?" * len(ids_a_borrar))
    conn.execute(
        f"DELETE FROM puertos WHERE host_id IN "
        f"(SELECT id FROM hosts WHERE escaneo_id IN ({marcadores}))",
        ids_a_borrar,
    )
    conn.execute(f"DELETE FROM hosts WHERE escaneo_id IN ({marcadores})", ids_a_borrar)
    conn.execute(f"DELETE FROM escaneos WHERE id IN ({marcadores})", ids_a_borrar)
    # Una ejecución sin escaneos ya no tiene nada que enseñar
    conn.execute("DELETE FROM ejecuciones WHERE id NOT IN "
                 "(SELECT ejecucion_id FROM escaneos WHERE ejecucion_id IS NOT NULL)")


def registrar_y_comparar(
    resultados: dict, rango: str, db_path: str = DB_POR_DEFECTO,
    mantener_ultimos: int = MANTENER_ULTIMOS_POR_DEFECTO,
) -> dict:
    """
    Guarda el escaneo actual en SQLite y devuelve la comparación con el
    escaneo anterior del mismo rango (si existe):
        {
            "primera_vez": bool,
            "hosts_nuevos": [ip, ...],
            "hosts_caidos": [ip, ...],
            "puertos_cambiados": {
                ip: {
                    "nuevos": [puerto, ...],
                    "cerrados": [puerto, ...],
                    "nuevos_sensibles": [{"puerto": .., "motivo": ..}, ...],  # subconjunto de "nuevos"
                }
            },
        }

    También purga los escaneos de este mismo rango más antiguos que los
    últimos `mantener_ultimos` (por defecto 50).
    """
    return registrar_ejecucion({rango: resultados}, db_path=db_path, mantener_ultimos=mantener_ultimos)[rango]


def registrar_ejecucion(
    resultados_por_rango: dict[str, dict], topologia: dict | None = None, origen: str = "cli",
    db_path: str = DB_POR_DEFECTO, mantener_ultimos: int = MANTENER_ULTIMOS_POR_DEFECTO,
) -> dict[str, dict]:
    """Guarda una pasada completa (todos sus rangos y la topología SNMP, si
    la hubo) como una ejecución, y devuelve {rango: diff} con cada rango
    comparado con su propio escaneo anterior (formato de
    registrar_y_comparar). Para mostrar uno solo: combinar_diffs.

    `origen` es "cli" o "web": la web lo enseña en la lista de escaneos."""
    try:
        with closing(_conectar(db_path)) as conn:
            _crear_tablas(conn)
            fecha = datetime.now().isoformat(timespec="seconds")
            cur = conn.execute(
                "INSERT INTO ejecuciones (fecha, origen, topologia) VALUES (?, ?, ?)",
                (fecha, origen, json.dumps(topologia) if topologia is not None else None),
            )
            ejecucion_id = cur.lastrowid
            diffs = {}
            for rango, resultados in resultados_por_rango.items():
                diffs[rango] = _comparar(resultados, _ultimo_escaneo(conn, rango))
                _guardar_escaneo(conn, resultados, rango, ejecucion_id, fecha)
                _purgar_antiguos(conn, rango, mantener_ultimos)
            conn.commit()
            return diffs
    except sqlite3.Error as e:
        raise HistoryError(f"Error accessing the scan history ({db_path}): {e}") from e


def listar_ejecuciones(db_path: str = DB_POR_DEFECTO, limite: int = 20) -> list[dict]:
    """Las últimas `limite` ejecuciones, más reciente primero, para la lista
    de la web:
        [{"id", "fecha", "origen", "rangos": [..], "total_hosts", "alertas"}, ...]
    "alertas" se recalcula con PUERTOS_SENSIBLES sobre los puertos guardados
    (mismo criterio que _comparar), no se guarda aparte."""
    try:
        with closing(_conectar(db_path)) as conn:
            _crear_tablas(conn)
            ejecuciones = conn.execute(
                "SELECT id, fecha, origen FROM ejecuciones ORDER BY fecha DESC, id DESC LIMIT ?", (limite,)
            ).fetchall()
            resultado = []
            for ejecucion_id, fecha, origen in ejecuciones:
                rangos = [fila[0] for fila in conn.execute(
                    "SELECT rango FROM escaneos WHERE ejecucion_id = ? ORDER BY id", (ejecucion_id,))]
                total_hosts = conn.execute(
                    "SELECT COUNT(*) FROM hosts WHERE escaneo_id IN "
                    "(SELECT id FROM escaneos WHERE ejecucion_id = ?)", (ejecucion_id,)
                ).fetchone()[0]
                puertos = conn.execute(
                    "SELECT puerto FROM puertos WHERE host_id IN (SELECT id FROM hosts WHERE escaneo_id IN "
                    "(SELECT id FROM escaneos WHERE ejecucion_id = ?))", (ejecucion_id,)
                ).fetchall()
                resultado.append({
                    "id": ejecucion_id, "fecha": fecha, "origen": origen, "rangos": rangos,
                    "total_hosts": total_hosts,
                    "alertas": sum(1 for (puerto,) in puertos if puerto in PUERTOS_SENSIBLES),
                })
            return resultado
    except sqlite3.Error as e:
        raise HistoryError(f"Error accessing the scan history ({db_path}): {e}") from e


def cargar_ejecucion(ejecucion_id: int, db_path: str = DB_POR_DEFECTO) -> dict:
    """Reabre una ejecución guardada:
        {"id", "fecha", "origen", "rangos": [..], "resultados": {ip: {...}},
         "topologia": dict | None, "diff": dict}
    `resultados` tiene las claves de scanner.parsear_host (con las alertas
    recalculadas; "producto" no se guarda y sale vacío). El diff compara
    cada rango con su escaneo anterior a esta ejecución, no con el último.
    Lanza HistoryError si no existe."""
    try:
        with closing(_conectar(db_path)) as conn:
            _crear_tablas(conn)
            fila = conn.execute(
                "SELECT fecha, origen, topologia FROM ejecuciones WHERE id = ?", (ejecucion_id,)
            ).fetchone()
            if fila is None:
                raise HistoryError(f"Scan {ejecucion_id} is not in the history ({db_path})")
            fecha, origen, topologia = fila

            rangos, resultados, diffs = [], {}, []
            for escaneo_id, rango in conn.execute(
                "SELECT id, rango FROM escaneos WHERE ejecucion_id = ? ORDER BY id", (ejecucion_id,)
            ).fetchall():
                rangos.append(rango)
                resultados_rango = _cargar_hosts(conn, escaneo_id)
                diffs.append(_comparar(resultados_rango, _ultimo_escaneo(conn, rango, antes_de=escaneo_id)))
                resultados.update(resultados_rango)
            return {
                "id": ejecucion_id, "fecha": fecha, "origen": origen, "rangos": rangos,
                "resultados": resultados,
                "topologia": json.loads(topologia) if topologia is not None else None,
                "diff": combinar_diffs(diffs),
            }
    except sqlite3.Error as e:
        raise HistoryError(f"Error accessing the scan history ({db_path}): {e}") from e


def _cargar_hosts(conn: sqlite3.Connection, escaneo_id: int) -> dict:
    resultados = {}
    for host_id, ip, hostname, mac, vendor, categoria, so in conn.execute(
        "SELECT id, ip, hostname, mac, vendor, categoria, so FROM hosts WHERE escaneo_id = ?", (escaneo_id,)
    ).fetchall():
        puertos = [
            {"puerto": puerto, "servicio": servicio or "", "producto": ""}
            for puerto, servicio in conn.execute(
                "SELECT puerto, servicio FROM puertos WHERE host_id = ? ORDER BY puerto", (host_id,))
        ]
        resultados[ip] = {
            "estado": "up", "hostname": hostname or "", "so": so or "", "mac": mac or "",
            "vendor": vendor or "", "categoria": categoria or "", "puertos": puertos,
            "alertas": puertos_sensibles_abiertos(puertos),
        }
    return resultados


def listar_escaneos_recientes(db_path: str = DB_POR_DEFECTO, limite: int = 5) -> list:
    """Devuelve los últimos `limite` escaneos guardados, de cualquier rango,
    más reciente primero:
        [{"rango": .., "fecha": .., "total_hosts": .., "alertas": ..}, ...]

    Pensado para el panel de "historial reciente" del sidebar de webapp.py
    (cli.py no lo usa). "alertas" reutiliza PUERTOS_SENSIBLES sobre los
    puertos ya guardados en vez de añadir una columna aparte - mismo
    criterio que _comparar()."""
    try:
        with closing(_conectar(db_path)) as conn:
            _crear_tablas(conn)
            escaneos = conn.execute(
                "SELECT id, rango, fecha FROM escaneos ORDER BY fecha DESC, id DESC LIMIT ?",
                (limite,),
            ).fetchall()

            resultado = []
            for escaneo_id, rango, fecha in escaneos:
                total_hosts = conn.execute(
                    "SELECT COUNT(*) FROM hosts WHERE escaneo_id = ?", (escaneo_id,)
                ).fetchone()[0]
                puertos = conn.execute(
                    "SELECT puerto FROM puertos WHERE host_id IN "
                    "(SELECT id FROM hosts WHERE escaneo_id = ?)",
                    (escaneo_id,),
                ).fetchall()
                alertas = sum(1 for (puerto,) in puertos if puerto in PUERTOS_SENSIBLES)
                resultado.append(
                    {"rango": rango, "fecha": fecha, "total_hosts": total_hosts, "alertas": alertas}
                )
            return resultado
    except sqlite3.Error as e:
        raise HistoryError(f"Error accessing the scan history ({db_path}): {e}") from e


def hay_cambios(diff: dict) -> bool:
    """True si el diff (ver registrar_y_comparar) tiene algún cambio real
    respecto al escaneo anterior. Única fuente de verdad para esta
    pregunta - export.py y webapp.py la reutilizan en vez de reimplementar
    cada uno su propio `a or b or c`, que no da un bool de verdad si el
    único operando no vacío es un dict (puertos_cambiados)."""
    return bool(diff["hosts_nuevos"] or diff["hosts_caidos"] or diff["puertos_cambiados"])


def combinar_diffs(diffs: list[dict]) -> dict:
    """Une los diffs de varios rangos escaneados a la vez en uno solo, con
    el mismo formato que registrar_y_comparar (cada rango se compara con su
    propio escaneo anterior; esto solo los junta para mostrarlos). Es
    "primera vez" solo si lo es para todos: si un rango tiene historia y
    otro no, sí hay algo que comparar, y el nuevo no aporta cambios."""
    puertos_cambiados = {}
    for diff in diffs:
        puertos_cambiados.update(diff["puertos_cambiados"])
    return {
        "primera_vez": all(diff["primera_vez"] for diff in diffs),
        "hosts_nuevos": sorted(ip for diff in diffs for ip in diff["hosts_nuevos"]),
        "hosts_caidos": sorted(ip for diff in diffs for ip in diff["hosts_caidos"]),
        "puertos_cambiados": puertos_cambiados,
    }
