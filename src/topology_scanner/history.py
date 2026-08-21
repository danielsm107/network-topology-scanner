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

import sqlite3
from contextlib import closing
from datetime import datetime
from typing import Optional

from .classifier import PUERTOS_SENSIBLES

DB_POR_DEFECTO = "historial.db"


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
    """)


def _ultimo_escaneo(conn: sqlite3.Connection, rango: str):
    """Devuelve {ip: {puerto, puerto, ...}} del escaneo más reciente para
    ese rango, o None si todavía no hay ninguno guardado."""
    fila = conn.execute(
        "SELECT id FROM escaneos WHERE rango = ? ORDER BY fecha DESC, id DESC LIMIT 1",
        (rango,),
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


def _guardar_escaneo(conn: sqlite3.Connection, resultados: dict, rango: str):
    cur = conn.execute(
        "INSERT INTO escaneos (rango, fecha) VALUES (?, ?)",
        (rango, datetime.now().isoformat(timespec="seconds")),
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


def _comparar(resultados: dict, anterior: Optional[dict]) -> dict:
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
    try:
        with closing(sqlite3.connect(db_path)) as conn:
            _crear_tablas(conn)
            anterior = _ultimo_escaneo(conn, rango)
            diff = _comparar(resultados, anterior)
            _guardar_escaneo(conn, resultados, rango)
            _purgar_antiguos(conn, rango, mantener_ultimos)
            conn.commit()
            return diff
    except sqlite3.Error as e:
        raise HistoryError(f"Error accediendo al historial ({db_path}): {e}") from e


def listar_escaneos_recientes(db_path: str = DB_POR_DEFECTO, limite: int = 5) -> list:
    """Devuelve los últimos `limite` escaneos guardados, de cualquier rango,
    más reciente primero:
        [{"rango": .., "fecha": .., "total_hosts": .., "alertas": ..}, ...]

    Pensado para el panel de "historial reciente" del sidebar de webapp.py
    (cli.py no lo usa). "alertas" reutiliza PUERTOS_SENSIBLES sobre los
    puertos ya guardados en vez de añadir una columna aparte - mismo
    criterio que _comparar()."""
    try:
        with closing(sqlite3.connect(db_path)) as conn:
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
        raise HistoryError(f"Error accediendo al historial ({db_path}): {e}") from e


def hay_cambios(diff: dict) -> bool:
    """True si el diff (ver registrar_y_comparar) tiene algún cambio real
    respecto al escaneo anterior. Única fuente de verdad para esta
    pregunta - export.py y webapp.py la reutilizan en vez de reimplementar
    cada uno su propio `a or b or c`, que no da un bool de verdad si el
    único operando no vacío es un dict (puertos_cambiados)."""
    return bool(diff["hosts_nuevos"] or diff["hosts_caidos"] or diff["puertos_cambiados"])
