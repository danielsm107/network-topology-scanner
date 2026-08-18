"""
Tests de history.py. Cada test usa una base de datos SQLite temporal
(tmp_path) - nunca la de verdad, así no se mezcla con datos reales.
"""

import pytest

from topology_scanner.history import registrar_y_comparar, HistoryError, hay_cambios


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

    with pytest.raises(HistoryError):
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
