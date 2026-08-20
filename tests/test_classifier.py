from topology_scanner.classifier import (
    clasificar_dispositivo,
    icono_para_categoria,
    puertos_sensibles_abiertos,
)


def test_vendor_vacio_es_desconocido():
    assert clasificar_dispositivo("") == "desconocido"
    assert clasificar_dispositivo(None) == "desconocido"


def test_mikrotik_es_router():
    assert clasificar_dispositivo("Mikrotik") == "router"


def test_case_insensitive():
    assert clasificar_dispositivo("MIKROTIK") == "router"
    assert clasificar_dispositivo("mikrotik") == "router"


def test_synology_es_nas():
    assert clasificar_dispositivo("Synology Incorporated") == "nas"


def test_apple_es_apple():
    assert clasificar_dispositivo("Apple, Inc.") == "apple"


def test_vendor_no_reconocido_es_desconocido():
    assert clasificar_dispositivo("Fabricante Inventado XYZ") == "desconocido"


def test_icono_existe_para_cada_categoria_conocida():
    for categoria in ["router", "firewall", "vm", "nas", "printer", "camera", "iot", "mobile", "apple", "pc"]:
        icono = icono_para_categoria(categoria)
        assert "code" in icono
        assert "color" in icono


def test_icono_categoria_desconocida_usa_fallback():
    icono = icono_para_categoria("categoria-que-no-existe")
    assert icono == icono_para_categoria("desconocido")


def test_cada_categoria_tiene_nombre_legible():
    categorias = [
        "router", "firewall", "vm", "nas", "printer", "camera",
        "iot", "mobile", "apple", "pc", "desconocido",
    ]
    for categoria in categorias:
        icono = icono_para_categoria(categoria)
        assert icono["nombre"]


def test_puertos_sensibles_detecta_rdp_telnet_smb():
    puertos = [
        {"puerto": 3389, "servicio": "ms-wbt-server", "producto": ""},
        {"puerto": 23, "servicio": "telnet", "producto": ""},
        {"puerto": 445, "servicio": "microsoft-ds", "producto": ""},
        {"puerto": 80, "servicio": "http", "producto": ""},
    ]
    alertas = puertos_sensibles_abiertos(puertos)
    assert {a["puerto"] for a in alertas} == {3389, 23, 445}


def test_puertos_sensibles_incluye_motivo():
    puertos = [{"puerto": 3389, "servicio": "ms-wbt-server", "producto": ""}]
    alertas = puertos_sensibles_abiertos(puertos)
    assert alertas[0]["motivo"]


def test_puertos_sensibles_vacio_si_no_hay_ninguno_sensible():
    puertos = [{"puerto": 80, "servicio": "http", "producto": ""}]
    assert puertos_sensibles_abiertos(puertos) == []


def test_puertos_sensibles_lista_vacia():
    assert puertos_sensibles_abiertos([]) == []
