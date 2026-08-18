from topology_scanner.graph import construir_grafo


def _resultado_fake(hostname="server01", categoria="pc", puertos=None, alertas=None):
    return {
        "estado": "up",
        "hostname": hostname,
        "so": "Linux",
        "mac": "AA:BB:CC:DD:EE:FF",
        "vendor": "Dell Inc.",
        "categoria": categoria,
        "puertos": puertos or [],
        "alertas": alertas or [],
    }


def test_grafo_tiene_nodo_central_de_red():
    resultados = {"192.168.1.10": _resultado_fake()}
    grafo = construir_grafo(resultados, "192.168.1.0/24")
    assert "Red 192.168.1.0/24" in grafo.nodes


def test_grafo_tiene_un_nodo_por_host():
    resultados = {
        "192.168.1.10": _resultado_fake(hostname="server01"),
        "192.168.1.20": _resultado_fake(hostname="server02"),
    }
    grafo = construir_grafo(resultados, "192.168.1.0/24")
    assert "192.168.1.10" in grafo.nodes
    assert "192.168.1.20" in grafo.nodes
    assert grafo.number_of_nodes() == 3  # 2 hosts + nodo central


def test_cada_host_conectado_al_nodo_central():
    resultados = {"192.168.1.10": _resultado_fake()}
    grafo = construir_grafo(resultados, "192.168.1.0/24")
    assert grafo.has_edge("Red 192.168.1.0/24", "192.168.1.10")


def test_categoria_se_propaga_al_nodo():
    resultados = {"192.168.1.1": _resultado_fake(categoria="router")}
    grafo = construir_grafo(resultados, "192.168.1.0/24")
    assert grafo.nodes["192.168.1.1"]["categoria"] == "router"


def test_grafo_vacio_solo_tiene_nodo_central():
    grafo = construir_grafo({}, "192.168.1.0/24")
    assert grafo.number_of_nodes() == 1


def test_alertas_se_propagan_al_nodo():
    alertas = [{"puerto": 3389, "motivo": "RDP (objetivo habitual de fuerza bruta)"}]
    resultados = {"192.168.1.1": _resultado_fake(alertas=alertas)}
    grafo = construir_grafo(resultados, "192.168.1.0/24")
    assert grafo.nodes["192.168.1.1"]["alertas"] == alertas


def test_tooltip_incluye_aviso_si_hay_puertos_sensibles():
    alertas = [{"puerto": 445, "motivo": "SMB (vector típico de ransomware)"}]
    resultados = {"192.168.1.1": _resultado_fake(alertas=alertas)}
    grafo = construir_grafo(resultados, "192.168.1.0/24")
    assert "445" in grafo.nodes["192.168.1.1"]["titulo"]


def test_tooltip_sin_alertas_no_menciona_puertos_sensibles():
    resultados = {"192.168.1.1": _resultado_fake()}
    grafo = construir_grafo(resultados, "192.168.1.0/24")
    assert "sensibles" not in grafo.nodes["192.168.1.1"]["titulo"]
