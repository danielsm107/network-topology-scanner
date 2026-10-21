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


# === Con topología SNMP =====================================================
#
# `topologia` es lo que devuelve snmp.inferir_topologia (aquí escrito a mano:
# graph.py no sabe nada de SNMP, solo de este formato). Red anonimizada:
#
#   Upstream 198.51.100.2 ── Router 192.0.2.1 ─┬─ ether2 ── AP 192.0.2.254 ── PC 192.0.2.20
#                                              ├─ ether3 ── UDM 192.0.2.44 ── LAN B 10.0.10.0/24
#                                              └─ wlan1  ── móvil (solo MAC en nmap)

RANGO = "192.0.2.0/24"


def _equipo(nombre="", consultado=False, upstream=False):
    return {"nombre": nombre, "plataforma": "MikroTik", "version": "6.49", "mac": None,
            "consultado": consultado, "upstream": upstream}


def _topologia():
    return {
        "equipos": {
            "198.51.100.2": _equipo("Upstream", upstream=True),
            "192.0.2.1": _equipo("Router-Casa", consultado=True),
            "192.0.2.254": _equipo("AP-Interior"),
            "192.0.2.44": _equipo(""),
        },
        "enlaces": [
            {"padre": "198.51.100.2", "hijo": "192.0.2.1", "interfaz_padre": None, "interfaz_hijo": "ether1"},
            {"padre": "192.0.2.1", "hijo": "192.0.2.254", "interfaz_padre": "ether2", "interfaz_hijo": None},
            {"padre": "192.0.2.1", "hijo": "192.0.2.44", "interfaz_padre": "ether3", "interfaz_hijo": None},
        ],
        "redes": {"10.0.10.0/24": "192.0.2.44"},
        "ubicaciones": {
            "02:00:00:00:00:20": {"ip": "192.0.2.20", "padre": "192.0.2.254", "interfaz": None},
            "02:00:00:00:00:66": {"ip": None, "padre": "192.0.2.1", "interfaz": "wlan1"},
            "02:00:00:00:00:77": {"ip": "192.0.2.77", "padre": "192.0.2.1", "interfaz": "ether4"},
            "02:00:00:00:00:88": {"ip": None, "padre": "192.0.2.1", "interfaz": "ether5"},
        },
    }


def test_sin_topologia_sigue_siendo_una_estrella():
    grafo = construir_grafo({"192.0.2.20": _resultado_fake()}, RANGO, topologia=None)

    assert set(grafo.nodes) == {f"Red {RANGO}", "192.0.2.20"}


def test_con_topologia_los_equipos_de_red_son_nodos_enlazados_padre_hijo():
    grafo = construir_grafo({}, RANGO, topologia=_topologia())

    assert grafo.nodes["192.0.2.1"]["tipo"] == "equipo"
    assert grafo.nodes["192.0.2.1"]["padre"] == "198.51.100.2"
    assert grafo.nodes["198.51.100.2"]["padre"] is None
    assert grafo.edges["192.0.2.1", "192.0.2.254"]["interfaz"] == "ether2"
    # En el enlace con el upstream solo se conoce el puerto del lado del hijo
    assert grafo.edges["198.51.100.2", "192.0.2.1"]["interfaz"] == "ether1"


def test_equipo_sin_datos_de_nmap_usa_el_nombre_snmp_y_categoria_router():
    grafo = construir_grafo({}, RANGO, topologia=_topologia())
    nodo = grafo.nodes["198.51.100.2"]

    assert nodo["hostname"] == "Upstream"
    assert nodo["categoria"] == "router"
    assert nodo["upstream"] is True
    assert "no consultado" in nodo["titulo"]


def test_equipo_que_tambien_escaneo_nmap_conserva_puertos_y_alertas():
    alerta = [{"puerto": 23, "motivo": "Telnet"}]
    resultados = {"192.0.2.1": _resultado_fake(hostname="", categoria="router",
                                               puertos=[{"puerto": 23, "servicio": "telnet", "producto": ""}],
                                               alertas=alerta)}

    nodo = construir_grafo(resultados, RANGO, topologia=_topologia()).nodes["192.0.2.1"]

    assert nodo["tipo"] == "equipo"
    assert nodo["alertas"] == alerta
    assert nodo["num_puertos"] == 1
    assert nodo["hostname"] == "Router-Casa"
    assert "23/telnet" in nodo["titulo"]


def test_host_de_nmap_ubicado_por_ip_cuelga_de_su_equipo():
    resultados = {"192.0.2.20": _resultado_fake(hostname="pc")}

    grafo = construir_grafo(resultados, RANGO, topologia=_topologia())

    assert grafo.has_edge("192.0.2.254", "192.0.2.20")
    assert grafo.nodes["192.0.2.20"]["padre"] == "192.0.2.254"
    assert "Conectado a: AP-Interior" in grafo.nodes["192.0.2.20"]["titulo"]
    assert f"Red {RANGO}" not in grafo.nodes   # todo ubicado: sin nodo de red


def test_host_de_nmap_ubicado_por_mac_aunque_nmap_la_de_en_mayusculas():
    """La ubicación del móvil no tiene IP (no estaba en la ARP), pero nmap
    sí le ha visto la MAC: se cruzan por MAC, sin distinguir mayúsculas."""
    datos = _resultado_fake(hostname="movil")
    datos["mac"] = "02:00:00:00:00:66".upper()

    grafo = construir_grafo({"192.0.2.66": datos}, RANGO, topologia=_topologia())

    assert grafo.has_edge("192.0.2.1", "192.0.2.66")
    assert grafo.edges["192.0.2.1", "192.0.2.66"]["interfaz"] == "wlan1"
    assert "02:00:00:00:00:66" not in grafo.nodes   # no se duplica como nodo "solo MAC"


def test_host_de_una_red_remota_cuelga_del_router_que_la_sirve():
    grafo = construir_grafo({"10.0.10.10": _resultado_fake(hostname="proxmox")}, RANGO, topologia=_topologia())

    assert grafo.has_edge("192.0.2.44", "10.0.10.10")


def test_host_que_no_encaja_en_nada_cuelga_del_nodo_de_red():
    grafo = construir_grafo({"203.0.113.5": _resultado_fake()}, RANGO, topologia=_topologia())

    assert grafo.nodes[f"Red {RANGO}"]["tipo"] == "red"
    assert grafo.has_edge(f"Red {RANGO}", "203.0.113.5")


def test_hosts_vistos_solo_por_snmp_tambien_se_muestran():
    """Con IP (estaba en la ARP pero nmap no lo detectó) o solo con MAC (ni
    eso): un equipo desconocido en un puerto es justo lo interesante."""
    grafo = construir_grafo({}, RANGO, topologia=_topologia())

    con_ip = grafo.nodes["192.0.2.77"]
    solo_mac = grafo.nodes["02:00:00:00:00:88"]
    assert con_ip["solo_snmp"] is True
    assert solo_mac["solo_snmp"] is True
    assert grafo.has_edge("192.0.2.1", "02:00:00:00:00:88")
    assert "no detectado por nmap" in solo_mac["titulo"]
    assert "ether5" in solo_mac["titulo"]


# === Varios rangos ==========================================================

def test_varios_rangos_en_estrella_un_centro_por_rango():
    resultados = {
        "192.168.181.10": _resultado_fake(),
        "192.168.181.20": _resultado_fake(),
        "10.0.10.10": _resultado_fake(hostname="proxmox"),
    }

    grafo = construir_grafo(resultados, ["192.168.181.0/24", "10.0.10.0/24"])

    assert grafo.has_edge("Red 192.168.181.0/24", "192.168.181.10")
    assert grafo.has_edge("Red 192.168.181.0/24", "192.168.181.20")
    assert grafo.has_edge("Red 10.0.10.0/24", "10.0.10.10")
    assert grafo.nodes["10.0.10.10"]["padre"] == "Red 10.0.10.0/24"
    assert grafo.number_of_nodes() == 5


def test_un_rango_como_lista_es_igual_que_como_texto():
    resultados = {"192.168.1.10": _resultado_fake()}

    con_lista = construir_grafo(resultados, ["192.168.1.0/24"])
    con_texto = construir_grafo(resultados, "192.168.1.0/24")

    assert set(con_lista.nodes) == set(con_texto.nodes) == {"Red 192.168.1.0/24", "192.168.1.10"}


def test_con_topologia_el_host_sin_ubicar_cuelga_del_centro_de_su_rango():
    grafo = construir_grafo({"203.0.113.5": _resultado_fake()}, ["192.0.2.0/24", "203.0.113.0/24"],
                            topologia=_topologia())

    assert grafo.has_edge("Red 203.0.113.0/24", "203.0.113.5")
    assert "Red 192.0.2.0/24" not in grafo.nodes   # sin hosts sin ubicar en ese rango


def test_el_nodo_central_lleva_su_rango():
    """Para que quien dibuje pueda etiquetarlo sin recortar el nombre "Red ..."."""
    grafo = construir_grafo({"10.0.10.10": _resultado_fake()}, ["192.168.181.0/24", "10.0.10.0/24"])

    assert grafo.nodes["Red 10.0.10.0/24"]["rango"] == "10.0.10.0/24"


def test_enlace_entre_equipos_con_las_dos_interfaces_muestra_ambas():
    """LLDP da el puerto del otro extremo: la arista dice por dónde sale
    cada lado (padre ↔ hijo)."""
    topologia = _topologia()
    topologia["enlaces"][1]["interfaz_hijo"] = "bridge/ether1"   # router -> AP

    grafo = construir_grafo({}, RANGO, topologia=topologia)

    assert grafo.edges["192.0.2.1", "192.0.2.254"]["interfaz"] == "ether2 ↔ bridge/ether1"
    assert "Conectado a: Router-Casa (ether2 ↔ bridge/ether1)" in grafo.nodes["192.0.2.254"]["titulo"]
