"""
Tests de rangos.py: validación de varios objetivos y reparto de hosts por
rango (para el historial, que compara cada rango por separado, y para el
grafo en estrella, que dibuja un centro por rango).
"""

import pytest

from topology_scanner.rangos import parsear_rangos, rango_de, repartir_por_rango


def test_un_solo_objetivo_se_deja_tal_cual():
    """Con un solo objetivo no hace falta repartir nada: se admite
    cualquier sintaxis de nmap, como hasta ahora (192.168.1.1-50,
    192.168.1.1,5, un hostname...)."""
    assert parsear_rangos(["192.168.1.1-50"]) == ["192.168.1.1-50"]
    assert parsear_rangos(["192.168.1.1,5"]) == ["192.168.1.1,5"]


def test_varios_rangos_cidr_se_aceptan_en_orden():
    assert parsear_rangos(["192.168.50.0/24", "10.0.10.0/24"]) == ["192.168.50.0/24", "10.0.10.0/24"]


def test_varios_rangos_admiten_una_ip_suelta():
    assert parsear_rangos(["192.168.50.0/24", "10.0.10.10"]) == ["192.168.50.0/24", "10.0.10.10"]


def test_varios_rangos_quita_duplicados():
    assert parsear_rangos(["10.0.10.0/24", "10.0.10.0/24"]) == ["10.0.10.0/24"]


def test_varios_rangos_con_uno_que_no_es_cidr_es_un_error():
    """Con varios hay que saber a qué rango pertenece cada host, y eso solo
    se puede con IPs/CIDR."""
    with pytest.raises(ValueError, match=r"192\.168\.1\.1-50"):
        parsear_rangos(["10.0.10.0/24", "192.168.1.1-50"])


def test_lista_vacia_es_un_error():
    with pytest.raises(ValueError):
        parsear_rangos([])


def test_rango_de_elige_el_mas_especifico():
    rangos = ["10.0.0.0/8", "10.0.10.0/24"]

    assert rango_de("10.0.10.10", rangos) == "10.0.10.0/24"
    assert rango_de("10.0.20.1", rangos) == "10.0.0.0/8"


def test_rango_de_sin_coincidencia_es_el_primero():
    """No debería pasar (nmap solo devuelve hosts de los objetivos), pero
    un host nunca debe quedarse sin rango."""
    assert rango_de("203.0.113.5", ["192.168.50.0/24", "10.0.10.0/24"]) == "192.168.50.0/24"


def test_rango_de_con_un_solo_objetivo_no_cidr_es_ese():
    assert rango_de("192.168.1.20", ["192.168.1.1-50"]) == "192.168.1.1-50"


def test_repartir_por_rango_incluye_rangos_sin_hosts():
    """Un rango sin hosts vivos también se registra en el historial (así
    sus hosts del escaneo anterior salen como caídos)."""
    resultados = {"192.168.50.1": {"a": 1}, "10.0.10.10": {"b": 2}, "192.168.50.20": {"c": 3}}

    reparto = repartir_por_rango(resultados, ["192.168.50.0/24", "10.0.10.0/24", "172.16.0.0/24"])

    assert reparto == {
        "192.168.50.0/24": {"192.168.50.1": {"a": 1}, "192.168.50.20": {"c": 3}},
        "10.0.10.0/24": {"10.0.10.10": {"b": 2}},
        "172.16.0.0/24": {},
    }
