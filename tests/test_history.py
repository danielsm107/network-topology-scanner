"""
Tests de history.py. Cada test usa una base de datos SQLite temporal
(tmp_path) - nunca la de verdad, así no se mezcla con datos reales.
"""

import sqlite3
import threading
import time

import pytest

from topology_scanner.history import (
    HistoryError,
    cargar_ejecucion,
    combinar_diffs,
    hay_cambios,
    listar_ejecuciones,
    listar_escaneos_recientes,
    registrar_ejecucion,
    registrar_y_comparar,
)


def _resultado_fake(hostname="server01", puertos=None):
    return {
        "estado": "up",
        "hostname": hostname,
        "so": "Linux",
        "mac": "AA:BB:CC:DD:EE:FF",
        "vendor": "Dell Inc.",
        "categoria": "pc",
        "puertos": puertos or [],
        "alertas": [],
    }


def test_primer_escaneo_no_tiene_comparacion(tmp_path):
    db = str(tmp_path / "historial.db")

    diff = registrar_y_comparar({"192.168.1.10": _resultado_fake()}, "192.168.1.0/24", db_path=db)

    assert diff["primera_vez"] is True
    assert diff["hosts_nuevos"] == []
    assert diff["hosts_caidos"] == []
    assert diff["puertos_cambiados"] == {}


def test_detecta_host_nuevo(tmp_path):
    db = str(tmp_path / "historial.db")
    registrar_y_comparar({"192.168.1.10": _resultado_fake()}, "192.168.1.0/24", db_path=db)

    diff = registrar_y_comparar(
        {"192.168.1.10": _resultado_fake(), "192.168.1.20": _resultado_fake()},
        "192.168.1.0/24", db_path=db,
    )

    assert diff["hosts_nuevos"] == ["192.168.1.20"]
    assert diff["hosts_caidos"] == []


def test_detecta_host_caido(tmp_path):
    db = str(tmp_path / "historial.db")
    registrar_y_comparar(
        {"192.168.1.10": _resultado_fake(), "192.168.1.20": _resultado_fake()},
        "192.168.1.0/24", db_path=db,
    )

    diff = registrar_y_comparar({"192.168.1.10": _resultado_fake()}, "192.168.1.0/24", db_path=db)

    assert diff["hosts_caidos"] == ["192.168.1.20"]
    assert diff["hosts_nuevos"] == []


def test_detecta_puertos_nuevos_y_cerrados(tmp_path):
    db = str(tmp_path / "historial.db")
    puertos_antes = [{"puerto": 22, "servicio": "ssh", "producto": ""}]
    registrar_y_comparar(
        {"192.168.1.10": _resultado_fake(puertos=puertos_antes)}, "192.168.1.0/24", db_path=db
    )

    puertos_ahora = [{"puerto": 80, "servicio": "http", "producto": ""}]
    diff = registrar_y_comparar(
        {"192.168.1.10": _resultado_fake(puertos=puertos_ahora)}, "192.168.1.0/24", db_path=db
    )

    cambios = diff["puertos_cambiados"]["192.168.1.10"]
    assert cambios["nuevos"] == [80]
    assert cambios["cerrados"] == [22]


def test_puerto_nuevo_sensible_se_marca_como_tal(tmp_path):
    db = str(tmp_path / "historial.db")
    puertos_antes = [{"puerto": 22, "servicio": "ssh", "producto": ""}]
    registrar_y_comparar(
        {"192.168.1.10": _resultado_fake(puertos=puertos_antes)}, "192.168.1.0/24", db_path=db
    )

    puertos_ahora = [
        {"puerto": 22, "servicio": "ssh", "producto": ""},
        {"puerto": 23, "servicio": "telnet", "producto": ""},
    ]
    diff = registrar_y_comparar(
        {"192.168.1.10": _resultado_fake(puertos=puertos_ahora)}, "192.168.1.0/24", db_path=db
    )

    sensibles = diff["puertos_cambiados"]["192.168.1.10"]["nuevos_sensibles"]
    assert len(sensibles) == 1
    assert sensibles[0]["puerto"] == 23
    assert sensibles[0]["motivo"]


def test_puerto_nuevo_no_sensible_no_aparece_en_nuevos_sensibles(tmp_path):
    db = str(tmp_path / "historial.db")
    registrar_y_comparar({"192.168.1.10": _resultado_fake(puertos=[])}, "192.168.1.0/24", db_path=db)

    puertos_ahora = [{"puerto": 80, "servicio": "http", "producto": ""}]
    diff = registrar_y_comparar(
        {"192.168.1.10": _resultado_fake(puertos=puertos_ahora)}, "192.168.1.0/24", db_path=db
    )

    assert diff["puertos_cambiados"]["192.168.1.10"]["nuevos_sensibles"] == []


def test_sin_cambios_no_aparece_en_puertos_cambiados(tmp_path):
    db = str(tmp_path / "historial.db")
    puertos = [{"puerto": 22, "servicio": "ssh", "producto": ""}]
    registrar_y_comparar({"192.168.1.10": _resultado_fake(puertos=puertos)}, "192.168.1.0/24", db_path=db)

    diff = registrar_y_comparar(
        {"192.168.1.10": _resultado_fake(puertos=puertos)}, "192.168.1.0/24", db_path=db
    )

    assert diff["puertos_cambiados"] == {}


def test_rangos_distintos_no_se_mezclan(tmp_path):
    db = str(tmp_path / "historial.db")
    registrar_y_comparar({"192.168.1.10": _resultado_fake()}, "192.168.1.0/24", db_path=db)

    diff = registrar_y_comparar({"10.0.0.5": _resultado_fake()}, "10.0.0.0/24", db_path=db)

    assert diff["primera_vez"] is True


def test_error_de_sqlite_se_convierte_en_historyerror(tmp_path):
    db = str(tmp_path / "carpeta_que_no_existe" / "historial.db")

    with pytest.raises(HistoryError, match="Error accessing the scan history"):
        registrar_y_comparar({"192.168.1.10": _resultado_fake()}, "192.168.1.0/24", db_path=db)


def test_hay_cambios_es_true_si_solo_cambian_puertos():
    """Antes, export.py y webapp.py reimplementaban esto cada uno por su
    lado con `a or b or c` (que no devuelve un bool de verdad si el único
    no vacío es un dict) - único punto de verdad ahora."""
    diff = {
        "primera_vez": False,
        "hosts_nuevos": [],
        "hosts_caidos": [],
        "puertos_cambiados": {"192.168.1.10": {"nuevos": [23], "cerrados": [], "nuevos_sensibles": []}},
    }
    assert hay_cambios(diff) is True


def test_hay_cambios_es_false_si_no_hay_nada():
    diff = {"primera_vez": False, "hosts_nuevos": [], "hosts_caidos": [], "puertos_cambiados": {}}
    assert hay_cambios(diff) is False


def test_hay_cambios_es_true_si_hay_hosts_nuevos_o_caidos():
    diff_nuevos = {"primera_vez": False, "hosts_nuevos": ["192.168.1.20"], "hosts_caidos": [], "puertos_cambiados": {}}
    diff_caidos = {"primera_vez": False, "hosts_nuevos": [], "hosts_caidos": ["192.168.1.20"], "puertos_cambiados": {}}
    assert hay_cambios(diff_nuevos) is True
    assert hay_cambios(diff_caidos) is True


def test_purga_escaneos_mas_antiguos_que_mantener_ultimos(tmp_path):
    db = str(tmp_path / "historial.db")
    for _ in range(5):
        registrar_y_comparar({"192.168.1.10": _resultado_fake()}, "192.168.1.0/24", db_path=db, mantener_ultimos=3)

    with sqlite3.connect(db) as conn:
        total = conn.execute("SELECT COUNT(*) FROM escaneos WHERE rango = ?", ("192.168.1.0/24",)).fetchone()[0]

    assert total == 3


def test_purga_borra_tambien_hosts_y_puertos_asociados(tmp_path):
    db = str(tmp_path / "historial.db")
    puertos = [{"puerto": 22, "servicio": "ssh", "producto": ""}]
    for _ in range(4):
        registrar_y_comparar(
            {"192.168.1.10": _resultado_fake(puertos=puertos)}, "192.168.1.0/24", db_path=db, mantener_ultimos=2
        )

    with sqlite3.connect(db) as conn:
        hosts = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        puertos_guardados = conn.execute("SELECT COUNT(*) FROM puertos").fetchone()[0]

    # 2 escaneos conservados x 1 host x 1 puerto cada uno
    assert hosts == 2
    assert puertos_guardados == 2


def test_purga_no_afecta_a_otros_rangos(tmp_path):
    db = str(tmp_path / "historial.db")
    for _ in range(4):
        registrar_y_comparar({"192.168.1.10": _resultado_fake()}, "192.168.1.0/24", db_path=db, mantener_ultimos=1)
    registrar_y_comparar({"10.0.0.5": _resultado_fake()}, "10.0.0.0/24", db_path=db, mantener_ultimos=1)

    with sqlite3.connect(db) as conn:
        total = conn.execute("SELECT COUNT(*) FROM escaneos").fetchone()[0]

    assert total == 2  # 1 de cada rango


def test_sin_pasar_mantener_ultimos_usa_un_valor_por_defecto_razonable(tmp_path):
    """No debería hacer falta pasar mantener_ultimos a mano para tener
    protección contra un historial.db que crece sin límite."""
    db = str(tmp_path / "historial.db")
    for _ in range(60):
        registrar_y_comparar({"192.168.1.10": _resultado_fake()}, "192.168.1.0/24", db_path=db)

    with sqlite3.connect(db) as conn:
        total = conn.execute("SELECT COUNT(*) FROM escaneos WHERE rango = ?", ("192.168.1.0/24",)).fetchone()[0]

    assert total < 60


def test_listar_escaneos_recientes_vacio_sin_historial(tmp_path):
    db = str(tmp_path / "historial.db")

    assert listar_escaneos_recientes(db_path=db) == []


def test_listar_escaneos_recientes_mas_reciente_primero(tmp_path):
    db = str(tmp_path / "historial.db")
    registrar_y_comparar({"192.168.1.10": _resultado_fake()}, "192.168.1.0/24", db_path=db)
    registrar_y_comparar({"10.0.0.5": _resultado_fake()}, "10.0.0.0/24", db_path=db)

    recientes = listar_escaneos_recientes(db_path=db)

    assert [e["rango"] for e in recientes] == ["10.0.0.0/24", "192.168.1.0/24"]


def test_listar_escaneos_recientes_incluye_total_de_hosts(tmp_path):
    db = str(tmp_path / "historial.db")
    registrar_y_comparar(
        {"192.168.1.10": _resultado_fake(), "192.168.1.20": _resultado_fake()},
        "192.168.1.0/24", db_path=db,
    )

    recientes = listar_escaneos_recientes(db_path=db)

    assert recientes[0]["total_hosts"] == 2


def test_listar_escaneos_recientes_cuenta_puertos_sensibles_como_alertas(tmp_path):
    """Reutiliza PUERTOS_SENSIBLES (igual que _comparar) en vez de guardar
    una columna aparte - un host con Telnet (23) y SSH (22) abiertos cuenta
    1 alerta (solo el 23 es sensible)."""
    db = str(tmp_path / "historial.db")
    puertos = [
        {"puerto": 22, "servicio": "ssh", "producto": ""},
        {"puerto": 23, "servicio": "telnet", "producto": ""},
    ]
    registrar_y_comparar({"192.168.1.10": _resultado_fake(puertos=puertos)}, "192.168.1.0/24", db_path=db)

    recientes = listar_escaneos_recientes(db_path=db)

    assert recientes[0]["alertas"] == 1


def test_listar_escaneos_recientes_respeta_el_limite(tmp_path):
    db = str(tmp_path / "historial.db")
    for _ in range(5):
        registrar_y_comparar({"192.168.1.10": _resultado_fake()}, "192.168.1.0/24", db_path=db)

    assert len(listar_escaneos_recientes(db_path=db, limite=3)) == 3


# --- combinar_diffs (varios rangos en un mismo escaneo) ----------------------

def _diff(primera_vez=False, nuevos=(), caidos=(), puertos=None):
    return {"primera_vez": primera_vez, "hosts_nuevos": list(nuevos), "hosts_caidos": list(caidos),
            "puertos_cambiados": puertos or {}}


def test_combinar_diffs_une_los_cambios_de_cada_rango():
    combinado = combinar_diffs([
        _diff(nuevos=["192.168.1.20"], puertos={"192.168.1.1": {"nuevos": [23], "cerrados": [],
                                                                "nuevos_sensibles": []}}),
        _diff(nuevos=["10.0.10.5"], caidos=["10.0.10.9"]),
    ])

    assert combinado == {
        "primera_vez": False,
        "hosts_nuevos": ["10.0.10.5", "192.168.1.20"],
        "hosts_caidos": ["10.0.10.9"],
        "puertos_cambiados": {"192.168.1.1": {"nuevos": [23], "cerrados": [], "nuevos_sensibles": []}},
    }


def test_combinar_diffs_solo_es_primera_vez_si_lo_es_para_todos():
    """Si un rango es nuevo y otro no, sí hay algo con qué comparar (el
    rango con historia); el nuevo simplemente no aporta cambios."""
    assert combinar_diffs([_diff(primera_vez=True), _diff(nuevos=["10.0.10.5"])])["primera_vez"] is False
    assert combinar_diffs([_diff(primera_vez=True), _diff(primera_vez=True)])["primera_vez"] is True


def test_combinar_un_solo_diff_lo_devuelve_igual():
    diff = _diff(nuevos=["192.168.1.20"])

    assert combinar_diffs([diff]) == diff


# === Ejecuciones: una pasada con todos sus rangos y su topología ============

RED_A = "192.0.2.0/24"
RED_B = "198.51.100.0/24"

TOPOLOGIA_EJEMPLO = {
    "equipos": {"192.0.2.1": {"nombre": "router", "plataforma": "RouterOS", "version": "6.49",
                              "mac": "02:00:00:00:00:01", "consultado": True, "upstream": False}},
    "enlaces": [{"padre": "192.0.2.1", "hijo": "198.51.100.1", "interfaz_padre": "ether3", "interfaz_hijo": ""}],
    "redes": {RED_B: "198.51.100.1"},
    "ubicaciones": {"02:00:00:00:00:10": {"ip": "192.0.2.10", "padre": "192.0.2.1", "interfaz": "ether2"}},
}


def _con_puertos(*puertos):
    return [{"puerto": p, "servicio": "svc"} for p in puertos]


def _por_rango():
    return {
        RED_A: {"192.0.2.10": _resultado_fake(puertos=_con_puertos(22, 23))},
        RED_B: {"198.51.100.20": _resultado_fake(hostname="nas"), "198.51.100.21": _resultado_fake()},
    }


def test_registrar_ejecucion_varios_rangos(tmp_path):
    db = str(tmp_path / "historial.db")

    diffs = registrar_ejecucion(_por_rango(), db_path=db)

    assert set(diffs) == {RED_A, RED_B}
    ejecuciones = listar_ejecuciones(db)
    assert len(ejecuciones) == 1
    assert ejecuciones[0]["rangos"] == [RED_A, RED_B]
    assert ejecuciones[0]["origen"] == "cli"
    assert ejecuciones[0]["total_hosts"] == 3
    assert ejecuciones[0]["alertas"] == 1  # el 23/telnet


def test_cargar_ejecucion_completa(tmp_path):
    db = str(tmp_path / "historial.db")
    registrar_ejecucion(_por_rango(), topologia=TOPOLOGIA_EJEMPLO, origen="web", db_path=db)

    ejecucion = cargar_ejecucion(listar_ejecuciones(db)[0]["id"], db)

    assert ejecucion["origen"] == "web"
    assert ejecucion["rangos"] == [RED_A, RED_B]
    assert ejecucion["topologia"] == TOPOLOGIA_EJEMPLO
    host = ejecucion["resultados"]["192.0.2.10"]
    assert host["hostname"] == "server01"
    assert host["mac"] == "AA:BB:CC:DD:EE:FF"
    assert [p["puerto"] for p in host["puertos"]] == [22, 23]
    assert host["alertas"] == [{"puerto": 23, "motivo": "Telnet (unencrypted)"}]
    assert ejecucion["diff"]["primera_vez"] is True


def test_cargar_ejecucion_sin_topologia(tmp_path):
    """SNMP fallido: la ejecución se guarda igual y se reabre como estrella."""
    db = str(tmp_path / "historial.db")
    registrar_ejecucion(_por_rango(), topologia=None, db_path=db)

    ejecucion = cargar_ejecucion(listar_ejecuciones(db)[0]["id"], db)

    assert ejecucion["topologia"] is None
    assert len(ejecucion["resultados"]) == 3


def test_diff_de_una_ejecucion_antigua(tmp_path):
    """Reabrir la 2.ª de tres compara con la 1.ª, no con la última."""
    db = str(tmp_path / "historial.db")
    host = {"192.0.2.10": _resultado_fake()}
    registrar_ejecucion({RED_A: host}, db_path=db)
    registrar_ejecucion({RED_A: {**host, "192.0.2.11": _resultado_fake()}}, db_path=db)
    registrar_ejecucion({RED_A: {**host, "192.0.2.12": _resultado_fake()}}, db_path=db)

    segunda = listar_ejecuciones(db)[1]  # más reciente primero
    diff = cargar_ejecucion(segunda["id"], db)["diff"]

    assert diff["primera_vez"] is False
    assert diff["hosts_nuevos"] == ["192.0.2.11"]
    assert diff["hosts_caidos"] == []


def test_migra_historial_antiguo(tmp_path):
    """Un historial.db de la v1.2.x se migra al abrirlo, sin perder escaneos."""
    db = str(tmp_path / "historial.db")
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE escaneos (id INTEGER PRIMARY KEY AUTOINCREMENT, rango TEXT NOT NULL, fecha TEXT NOT NULL);
        CREATE TABLE hosts (id INTEGER PRIMARY KEY AUTOINCREMENT, escaneo_id INTEGER NOT NULL REFERENCES escaneos(id),
                            ip TEXT NOT NULL, hostname TEXT, mac TEXT, vendor TEXT, categoria TEXT, so TEXT);
        CREATE TABLE puertos (id INTEGER PRIMARY KEY AUTOINCREMENT, host_id INTEGER NOT NULL REFERENCES hosts(id),
                              puerto INTEGER NOT NULL, servicio TEXT);
        INSERT INTO escaneos (rango, fecha) VALUES ('192.0.2.0/24', '2026-10-01T03:00:00');
        INSERT INTO escaneos (rango, fecha) VALUES ('198.51.100.0/24', '2026-10-02T03:00:00');
        INSERT INTO hosts (escaneo_id, ip, hostname, mac, vendor, categoria, so)
            VALUES (1, '192.0.2.10', 'pc', '02:00:00:00:00:10', 'Dell Inc.', 'pc', 'Linux');
        INSERT INTO puertos (host_id, puerto, servicio) VALUES (1, 22, 'ssh');
    """)
    conn.commit()
    conn.close()

    ejecuciones = listar_ejecuciones(db)

    assert [e["rangos"] for e in ejecuciones] == [[RED_B], [RED_A]]
    assert all(e["origen"] == "antiguo" for e in ejecuciones)
    antigua = cargar_ejecucion(ejecuciones[1]["id"], db)
    assert antigua["resultados"]["192.0.2.10"]["puertos"][0]["puerto"] == 22
    assert antigua["topologia"] is None


def test_purga_borra_ejecuciones_huerfanas(tmp_path):
    db = str(tmp_path / "historial.db")
    for _ in range(3):
        registrar_ejecucion({RED_A: {"192.0.2.10": _resultado_fake()}}, db_path=db, mantener_ultimos=2)

    ejecuciones = listar_ejecuciones(db)

    assert len(ejecuciones) == 2
    assert all(e["total_hosts"] == 1 for e in ejecuciones)


def test_registrar_espera_a_otra_escritura(tmp_path):
    """El CronJob y la web escriben en el mismo historial.db: si uno está
    escribiendo, el otro espera en vez de fallar con "database is locked"."""
    db = str(tmp_path / "historial.db")
    registrar_ejecucion({RED_A: {"192.0.2.10": _resultado_fake()}}, db_path=db)  # crea las tablas
    bloqueada = threading.Event()

    def escritura_larga():
        conn = sqlite3.connect(db, isolation_level=None)
        conn.execute("BEGIN IMMEDIATE")
        bloqueada.set()
        time.sleep(1)
        conn.execute("COMMIT")
        conn.close()

    hilo = threading.Thread(target=escritura_larga)
    hilo.start()
    bloqueada.wait()
    registrar_ejecucion({RED_A: {"192.0.2.10": _resultado_fake()}}, db_path=db)
    hilo.join()

    assert len(listar_ejecuciones(db)) == 2
