from topology_scanner.classifier import clasificar_dispositivo, icono_para_categoria


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
