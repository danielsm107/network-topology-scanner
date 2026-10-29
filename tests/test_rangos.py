"""
Tests de rangos.py: validación de varios objetivos y reparto de hosts por
rango (para el historial, que compara cada rango por separado, y para el
grafo en estrella, que dibuja un centro por rango).
"""

import re

import pytest

from topology_scanner.rangos import (
    parsear_permitidos,
    parsear_rangos,
    rango_de,
    repartir_por_rango,
    validar_permitidos,
)


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
    with pytest.raises(ValueError, match=r"'192\.168\.1\.1-50' is not an IP or CIDR"):
        parsear_rangos(["10.0.10.0/24", "192.168.1.1-50"])


def test_lista_vacia_es_un_error():
    with pytest.raises(ValueError, match="at least one range"):
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


# === Rangos permitidos (web del clúster) ====================================

PERMITIDOS = ["192.0.2.0/24", "198.51.100.0/24"]


def _permitidos():
    return parsear_permitidos(" ".join(PERMITIDOS))


def test_parsear_permitidos_sin_variable():
    """Sin la variable (o vacía) no hay límite: el uso local de siempre."""
    assert parsear_permitidos(None) is None
    assert parsear_permitidos("  ") is None


def test_parsear_permitidos_lista():
    assert [str(red) for red in _permitidos()] == PERMITIDOS


def test_parsear_permitidos_invalida():
    with pytest.raises(ValueError):
        parsear_permitidos("192.0.2.0/24 basura")


def test_validar_permitidos_acepta_contenidos():
    """Una IP suelta o una subred más pequeña dentro de un permitido valen."""
    validar_permitidos(["192.0.2.7", "192.0.2.128/25", "198.51.100.0/24"], _permitidos())


def test_validar_permitidos_rechaza_supered():
    """Un /23 contiene al /24 permitido, pero escanearía también la mitad de fuera."""
    with pytest.raises(ValueError, match=re.escape("192.0.2.0/23")):
        validar_permitidos(["192.0.2.0/23"], _permitidos())


@pytest.mark.parametrize("objetivo", ["203.0.113.0/24", "2001:db8::/64"])
def test_validar_permitidos_rechaza_otra_red_e_ipv6(objetivo):
    with pytest.raises(ValueError, match="outside the allowed ranges"):
        validar_permitidos([objetivo], _permitidos())


def test_validar_permitidos_rechaza_sintaxis_nmap():
    """192.0.2.1-5 no se puede comprobar de forma fiable: con lista de
    permitidos, solo IPs y CIDRs."""
    with pytest.raises(ValueError, match=re.escape("192.0.2.1-5")):
        validar_permitidos(["192.0.2.1-5"], _permitidos())
