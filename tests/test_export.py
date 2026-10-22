"""
Tests de export.py. exportar_html usa pyvis de verdad (no se mockea):
es un módulo de exportación puro, más simple y fiable comprobar el HTML
generado de verdad que simular toda la API de pyvis.
"""

import csv
import io
import json

import networkx as nx

from topology_scanner.classifier import icono_para_categoria
from topology_scanner.export import (
    COLOR_ALERTA,
    exportar_csv,
    exportar_diff_texto,
    exportar_html,
    exportar_texto,
    posiciones_circulares,
    posiciones_jerarquicas,
)
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


def test_posiciones_circulares_vacio():
    assert posiciones_circulares(0) == []


def test_posiciones_circulares_una_por_nodo():
    assert len(posiciones_circulares(5)) == 5


def test_posiciones_circulares_reparte_en_un_solo_anillo_si_caben():
    posiciones = posiciones_circulares(6)
    radios = {round((x**2 + y**2) ** 0.5, 3) for x, y in posiciones}
    assert len(radios) == 1


def test_posiciones_circulares_abre_un_segundo_anillo_si_no_caben_en_uno():
    """Con muchos hosts vivos (p.ej. un /24 muy poblado) hace falta más de
    un anillo para que no se amontonen los nodos."""
    posiciones = posiciones_circulares(40)
    radios = {round((x**2 + y**2) ** 0.5, 3) for x, y in posiciones}
    assert len(radios) > 1


def test_posiciones_circulares_no_hay_dos_nodos_en_el_mismo_punto():
    posiciones = posiciones_circulares(25)
    assert len(set(posiciones)) == len(posiciones)


def test_exportar_html_genera_el_archivo_de_salida(tmp_path):
    grafo = construir_grafo({"192.168.1.1": _resultado_fake()}, "192.168.1.0/24")
    salida = tmp_path / "topologia.html"

    exportar_html(grafo, str(salida))

    assert salida.exists()


def test_exportar_html_inyecta_el_cdn_de_fontawesome(tmp_path):
    grafo = construir_grafo({"192.168.1.1": _resultado_fake()}, "192.168.1.0/24")
    salida = tmp_path / "topologia.html"

    exportar_html(grafo, str(salida))

    assert "font-awesome" in salida.read_text(encoding="utf-8")


def test_exportar_html_no_depende_de_la_carpeta_lib_local(tmp_path):
    """Con cdn_resources="local" (el defecto de pyvis) el HTML enlaza
    lib/bindings/utils.js por ruta relativa, que solo existe si alguien ha
    copiado esa carpeta junto al archivo de salida."""
    grafo = construir_grafo({"192.168.1.1": _resultado_fake()}, "192.168.1.0/24")
    salida = tmp_path / "topologia.html"

    exportar_html(grafo, str(salida))

    assert 'src="lib/' not in salida.read_text(encoding="utf-8")


def test_exportar_html_ocupa_toda_la_ventana_del_navegador(tmp_path):
    """pyvis fija #mynetwork a 800px de alto por defecto; el CSS inyectado
    debe pisarlo para que el grafo se adapte a la ventana (ver CLAUDE.md)."""
    grafo = construir_grafo({"192.168.1.1": _resultado_fake()}, "192.168.1.0/24")
    salida = tmp_path / "topologia.html"

    exportar_html(grafo, str(salida))

    html = salida.read_text(encoding="utf-8")
    assert "100vh" in html
    assert "#mynetwork" in html and "!important" in html
    # pyvis mete un <center><h1></h1></center> vacío que, sin ocultar,
    # deja una franja blanca (fondo por defecto del body) por encima del grafo
    assert "center { display: none" in html


def test_exportar_html_usa_el_color_de_icono_de_la_categoria(tmp_path):
    """El color viene de ICONOS_POR_CATEGORIA en classifier.py: nas -> #f1c40f."""
    grafo = construir_grafo({"192.168.1.1": _resultado_fake(categoria="nas")}, "192.168.1.0/24")
    salida = tmp_path / "topologia.html"

    exportar_html(grafo, str(salida))

    assert "f1c40f" in salida.read_text(encoding="utf-8")


def test_exportar_texto_imprime_datos_del_host(capsys):
    resultados = {
        "192.168.1.1": _resultado_fake(
            hostname="router01",
            puertos=[{"puerto": 80, "servicio": "http", "producto": "nginx"}],
        )
    }

    exportar_texto(resultados)

    salida = capsys.readouterr().out
    assert "NETWORK REPORT" in salida
    assert "Estimated OS" in salida
    assert "192.168.1.1" in salida
    assert "router01" in salida
    assert "80/tcp" in salida
    assert "nginx" in salida


def test_exportar_texto_host_sin_puertos_lo_indica(capsys):
    exportar_texto({"192.168.1.1": _resultado_fake(puertos=[])})

    salida = capsys.readouterr().out
    assert "No open ports found" in salida


def test_exportar_diff_texto_primera_vez(capsys):
    diff = {"primera_vez": True, "hosts_nuevos": [], "hosts_caidos": [], "puertos_cambiados": {}}

    exportar_diff_texto(diff)

    assert "first scan of this range" in capsys.readouterr().out.lower()


def test_exportar_diff_texto_muestra_hosts_nuevos_y_caidos(capsys):
    diff = {
        "primera_vez": False,
        "hosts_nuevos": ["192.168.1.20"],
        "hosts_caidos": ["192.168.1.99"],
        "puertos_cambiados": {},
    }

    exportar_diff_texto(diff)

    salida = capsys.readouterr().out
    assert "New hosts: 192.168.1.20" in salida
    assert "Hosts down: 192.168.1.99" in salida


def test_exportar_diff_texto_muestra_puertos_cambiados(capsys):
    diff = {
        "primera_vez": False,
        "hosts_nuevos": [],
        "hosts_caidos": [],
        "puertos_cambiados": {"192.168.1.10": {"nuevos": [80], "cerrados": [22]}},
    }

    exportar_diff_texto(diff)

    salida = capsys.readouterr().out
    assert "[192.168.1.10] new ports: 80" in salida
    assert "[192.168.1.10] closed ports: 22" in salida


def test_exportar_diff_texto_destaca_puertos_nuevos_sensibles(capsys):
    diff = {
        "primera_vez": False,
        "hosts_nuevos": [],
        "hosts_caidos": [],
        "puertos_cambiados": {
            "192.168.1.10": {
                "nuevos": [23],
                "cerrados": [],
                "nuevos_sensibles": [{"puerto": 23, "motivo": "Telnet (unencrypted)"}],
            }
        },
    }

    exportar_diff_texto(diff)

    salida = capsys.readouterr().out
    assert "192.168.1.10" in salida
    assert "23" in salida
    assert "Telnet" in salida
    assert "new AND sensitive port" in salida


def test_exportar_diff_texto_no_revienta_en_consolas_no_utf8(monkeypatch):
    """La consola por defecto de Windows usa cp1252, no UTF-8: print() con
    un carácter fuera de esa tabla (p.ej. el emoji ⚠) lanza
    UnicodeEncodeError y tira el programa. Se reproduce sin depender de
    estar en Windows, sustituyendo sys.stdout por uno codificado en cp1252."""
    consola_cp1252 = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr("sys.stdout", consola_cp1252)

    diff = {
        "primera_vez": False,
        "hosts_nuevos": [],
        "hosts_caidos": [],
        "puertos_cambiados": {
            "192.168.1.10": {
                "nuevos": [23],
                "cerrados": [],
                "nuevos_sensibles": [{"puerto": 23, "motivo": "Telnet (unencrypted)"}],
            }
        },
    }

    exportar_diff_texto(diff)  # no debe lanzar UnicodeEncodeError


def test_exportar_diff_texto_sin_cambios_lo_indica(capsys):
    diff = {"primera_vez": False, "hosts_nuevos": [], "hosts_caidos": [], "puertos_cambiados": {}}

    exportar_diff_texto(diff)

    assert "no changes" in capsys.readouterr().out.lower()


def test_exportar_html_marca_con_color_de_alerta_si_hay_puertos_sensibles(tmp_path):
    alertas = [{"puerto": 3389, "motivo": "RDP (common brute-force target)"}]
    grafo = construir_grafo({"192.168.1.1": _resultado_fake(alertas=alertas)}, "192.168.1.0/24")
    salida = tmp_path / "topologia.html"

    exportar_html(grafo, str(salida))

    html = salida.read_text(encoding="utf-8")
    assert COLOR_ALERTA.replace("#", "") in html


def test_exportar_html_sin_alertas_usa_el_color_normal_de_categoria(tmp_path):
    grafo = construir_grafo({"192.168.1.1": _resultado_fake(categoria="nas")}, "192.168.1.0/24")
    salida = tmp_path / "topologia.html"

    exportar_html(grafo, str(salida))

    html = salida.read_text(encoding="utf-8")
    # La leyenda siempre incluye el color de alerta (entrada "puerto
    # sensible"), así que hay que comprobar solo los datos del nodo, no
    # el HTML completo.
    datos_nodos = html.split("nodes = new vis.DataSet(")[1].split("edges = new vis.DataSet(")[0]
    assert COLOR_ALERTA.replace("#", "") not in datos_nodos


def test_exportar_html_hub_fijo_en_el_centro(tmp_path):
    grafo = construir_grafo({"192.168.1.1": _resultado_fake()}, "192.168.1.0/24")
    salida = tmp_path / "topologia.html"

    exportar_html(grafo, str(salida))

    html = salida.read_text(encoding="utf-8")
    datos_nodos = html.split("nodes = new vis.DataSet(")[1].split("edges = new vis.DataSet(")[0]
    assert '"x": 0' in datos_nodos
    assert '"y": 0' in datos_nodos


def test_exportar_html_hosts_sin_fisica(tmp_path):
    """Layout circular fijo (physics=False por nodo) en vez de la
    simulación barnes_hut anterior - el grafo queda ordenado como una
    estrella en vez de una disposición cambiante, sin perder zoom/arrastre
    nativos de pyvis (el drag manual sigue funcionando con physics=False)."""
    grafo = construir_grafo(
        {"192.168.1.1": _resultado_fake(), "192.168.1.2": _resultado_fake(hostname="pc2")},
        "192.168.1.0/24",
    )
    salida = tmp_path / "topologia.html"

    exportar_html(grafo, str(salida))

    html = salida.read_text(encoding="utf-8")
    datos_nodos = html.split("nodes = new vis.DataSet(")[1].split("edges = new vis.DataSet(")[0]
    assert datos_nodos.count('"physics": false') == 3  # hub + 2 hosts


def test_exportar_csv_incluye_cabecera_y_datos_del_host(tmp_path):
    resultados = {
        "192.168.1.10": _resultado_fake(
            hostname="server01",
            puertos=[{"puerto": 22, "servicio": "ssh", "producto": ""}],
        )
    }
    salida = tmp_path / "inventario.csv"

    exportar_csv(resultados, str(salida))

    with open(salida, encoding="utf-8") as f:
        filas = list(csv.reader(f))

    assert filas[0] == ["ip", "hostname", "mac", "vendor", "category", "os", "ports", "alerts"]
    assert len(filas) == 2
    fila = filas[1]
    assert fila[0] == "192.168.1.10"
    assert fila[1] == "server01"
    assert "22/ssh" in fila[6]


def test_exportar_csv_incluye_alertas(tmp_path):
    alertas = [{"puerto": 3389, "motivo": "RDP (common brute-force target)"}]
    resultados = {"192.168.1.1": _resultado_fake(alertas=alertas)}
    salida = tmp_path / "inventario.csv"

    exportar_csv(resultados, str(salida))

    with open(salida, encoding="utf-8") as f:
        filas = list(csv.reader(f))

    assert "3389" in filas[1][7]
    assert "RDP" in filas[1][7]


def test_exportar_csv_hosts_sin_puertos_ni_alertas_deja_columnas_vacias(tmp_path):
    resultados = {"192.168.1.1": _resultado_fake(puertos=[], alertas=[])}
    salida = tmp_path / "inventario.csv"

    exportar_csv(resultados, str(salida))

    with open(salida, encoding="utf-8") as f:
        filas = list(csv.reader(f))

    assert filas[1][6] == ""
    assert filas[1][7] == ""


def test_exportar_csv_maneja_comas_en_campos_correctamente(tmp_path):
    """El módulo csv debe encargarse del quoting - una coma dentro de un
    campo (p.ej. un vendor con coma en el nombre) no debe romper columnas."""
    resultados = {"192.168.1.1": _resultado_fake(hostname="host, con coma")}
    salida = tmp_path / "inventario.csv"

    exportar_csv(resultados, str(salida))

    with open(salida, encoding="utf-8") as f:
        filas = list(csv.reader(f))

    assert filas[1][1] == "host, con coma"


def test_exportar_csv_ordena_por_ip(tmp_path):
    resultados = {
        "192.168.1.20": _resultado_fake(hostname="segundo"),
        "192.168.1.10": _resultado_fake(hostname="primero"),
    }
    salida = tmp_path / "inventario.csv"

    exportar_csv(resultados, str(salida))

    with open(salida, encoding="utf-8") as f:
        filas = list(csv.reader(f))

    assert [fila[0] for fila in filas[1:]] == ["192.168.1.10", "192.168.1.20"]


def test_exportar_html_incluye_leyenda_con_todas_las_categorias(tmp_path):
    grafo = construir_grafo({"192.168.1.1": _resultado_fake()}, "192.168.1.0/24")
    salida = tmp_path / "topologia.html"

    exportar_html(grafo, str(salida))

    html = salida.read_text(encoding="utf-8")
    for categoria in ["router", "firewall", "vm", "nas", "printer", "camera", "iot", "mobile", "apple", "pc"]:
        nombre = icono_para_categoria(categoria)["nombre"]
        assert nombre in html, f"falta '{nombre}' ({categoria}) en la leyenda"


def test_exportar_html_leyenda_menciona_puertos_sensibles(tmp_path):
    grafo = construir_grafo({"192.168.1.1": _resultado_fake()}, "192.168.1.0/24")
    salida = tmp_path / "topologia.html"

    exportar_html(grafo, str(salida))

    html = salida.read_text(encoding="utf-8")
    assert "Legend" in html
    assert "Open sensitive port" in html


def test_exportar_html_icono_apple_usa_la_fuente_de_marcas(tmp_path):
    """El glyph de Apple (\\uf179) pertenece a 'Font Awesome 5 Brands', no a
    'Font Awesome 5 Free' (que es lo que se usa para el resto de iconos) -
    si se usa la fuente equivocada el icono sale en blanco."""
    grafo = construir_grafo({"192.168.1.1": _resultado_fake(categoria="apple")}, "192.168.1.0/24")
    salida = tmp_path / "topologia.html"

    exportar_html(grafo, str(salida))

    html = salida.read_text(encoding="utf-8")
    datos_nodos = html.split("nodes = new vis.DataSet(")[1].split("edges = new vis.DataSet(")[0]
    assert "Font Awesome 5 Brands" in datos_nodos


def test_exportar_html_leyenda_es_independiente_de_los_hosts_del_grafo(tmp_path):
    """La leyenda es un panel fijo con todas las categorías conocidas, no
    solo las que aparecen en el escaneo actual."""
    grafo = construir_grafo({"192.168.1.1": _resultado_fake(categoria="nas")}, "192.168.1.0/24")
    salida = tmp_path / "topologia.html"

    exportar_html(grafo, str(salida))

    html = salida.read_text(encoding="utf-8")
    assert icono_para_categoria("printer")["nombre"] in html


# === Layout jerárquico (grafo con topología SNMP) ===========================

def _arbol(enlaces):
    """Grafo mínimo como el que genera graph.py con topología: cada nodo
    lleva `padre` y cada arista su `interfaz`. enlaces = [(padre, hijo, interfaz)]."""
    grafo = nx.Graph()
    for padre, hijo, interfaz in enlaces:
        grafo.add_node(padre)
        grafo.nodes[padre].setdefault("padre", None)
        grafo.add_node(hijo, padre=padre)
        grafo.add_edge(padre, hijo, interfaz=interfaz)
    return grafo


def test_posiciones_jerarquicas_un_nivel_por_profundidad():
    grafo = _arbol([("upstream", "router", None), ("router", "ap", "ether2"), ("ap", "pc", None)])

    pos = posiciones_jerarquicas(grafo)

    assert pos["upstream"][1] < pos["router"][1] < pos["ap"][1] < pos["pc"][1]


def test_posiciones_jerarquicas_padre_centrado_sobre_sus_hijos():
    grafo = _arbol([("router", "ap", "ether2"), ("router", "udm", "ether3"),
                    ("ap", "pc1", None), ("udm", "pc2", None)])

    pos = posiciones_jerarquicas(grafo)

    assert pos["router"][0] == (pos["ap"][0] + pos["udm"][0]) / 2


def test_posiciones_jerarquicas_hojas_en_varias_filas_si_son_muchas():
    """20 hosts colgando del mismo router no deben dar un árbol de 20 de
    ancho: las hojas se agrupan en un bloque de pocas columnas."""
    grafo = _arbol([("router", f"host{i:02d}", "wlan1") for i in range(20)])

    pos = posiciones_jerarquicas(grafo)
    xs = {round(pos[f"host{i:02d}"][0]) for i in range(20)}
    ys = {round(pos[f"host{i:02d}"][1]) for i in range(20)}

    assert len(xs) < 20
    assert len(ys) > 1
    assert min(ys) > pos["router"][1]


def test_posiciones_jerarquicas_agrupa_las_hojas_por_interfaz():
    grafo = _arbol([("router", "b-wifi", "wlan1"), ("router", "a-cable", "ether4"),
                    ("router", "c-wifi", "wlan1")])

    pos = posiciones_jerarquicas(grafo)
    orden = sorted(["a-cable", "b-wifi", "c-wifi"], key=lambda n: (pos[n][1], pos[n][0]))

    assert orden == ["a-cable", "b-wifi", "c-wifi"]   # ether4 < wlan1


def test_posiciones_jerarquicas_no_hay_dos_nodos_en_el_mismo_punto():
    enlaces = [("upstream", "router", None), ("router", "ap", "ether2"), ("router", "udm", "ether3")]
    enlaces += [("ap", f"ap-host{i}", None) for i in range(9)]
    enlaces += [("udm", f"udm-host{i}", None) for i in range(3)]
    enlaces += [("router", f"wifi{i}", "wlan1") for i in range(8)]
    grafo = _arbol(enlaces)

    pos = posiciones_jerarquicas(grafo)

    assert set(pos) == set(grafo.nodes)
    assert len({(round(x), round(y)) for x, y in pos.values()}) == grafo.number_of_nodes()


def test_posiciones_jerarquicas_varias_raices_lado_a_lado():
    """El nodo "Network <rango>" de los hosts sin ubicar es otra raíz: no debe
    pisar al árbol principal."""
    grafo = _arbol([("upstream", "router", None), ("router", "pc", "ether2"),
                    ("Network 192.0.2.0/24", "perdido", None)])

    pos = posiciones_jerarquicas(grafo)
    principal = [pos[n][0] for n in ("upstream", "router", "pc")]
    suelto = [pos[n][0] for n in ("Network 192.0.2.0/24", "perdido")]

    assert max(principal) < min(suelto) or max(suelto) < min(principal)


def test_posiciones_jerarquicas_es_determinista():
    grafo = _arbol([("router", f"h{i}", "ether2") for i in range(7)])

    assert posiciones_jerarquicas(grafo) == posiciones_jerarquicas(grafo)


def _nodos_del_html(html: str) -> dict:
    datos = html.split("nodes = new vis.DataSet(")[1].split(");")[0]
    return {nodo["id"]: nodo for nodo in json.loads(datos)}


def _topologia_minima():
    equipo = {"nombre": "Router", "plataforma": "", "version": "", "mac": None,
              "consultado": True, "upstream": False}
    return {
        "equipos": {"192.168.1.1": equipo},
        "enlaces": [],
        "redes": {},
        "ubicaciones": {"02:00:00:00:00:10": {"ip": "192.168.1.10", "padre": "192.168.1.1",
                                              "interfaz": "ether2"}},
    }


def test_exportar_html_con_topologia_usa_el_layout_jerarquico(tmp_path):
    grafo = construir_grafo({"192.168.1.10": _resultado_fake()}, "192.168.1.0/24",
                            topologia=_topologia_minima())
    salida = tmp_path / "topologia.html"

    exportar_html(grafo, str(salida))

    nodos = _nodos_del_html(salida.read_text(encoding="utf-8"))
    assert nodos["192.168.1.1"]["y"] < nodos["192.168.1.10"]["y"]
    assert nodos["192.168.1.1"]["x"] == nodos["192.168.1.10"]["x"]


def test_exportar_html_con_topologia_etiqueta_las_aristas_con_la_interfaz(tmp_path):
    grafo = construir_grafo({"192.168.1.10": _resultado_fake()}, "192.168.1.0/24",
                            topologia=_topologia_minima())
    salida = tmp_path / "topologia.html"

    exportar_html(grafo, str(salida))

    html = salida.read_text(encoding="utf-8")
    aristas = json.loads(html.split("edges = new vis.DataSet(")[1].split(");")[0])
    assert [a.get("label") for a in aristas] == ["ether2"]


def test_exportar_html_con_topologia_una_sola_etiqueta_por_puerto(tmp_path):
    """8 móviles por wlan1 no deben dar 8 etiquetas "wlan1" iguales: basta
    una por padre+interfaz (cada host lo dice además en su tooltip)."""
    topologia = _topologia_minima()
    topologia["ubicaciones"] = {
        f"02:00:00:00:00:{i:02x}": {"ip": f"192.168.1.{i}", "padre": "192.168.1.1", "interfaz": "wlan1"}
        for i in range(10, 18)
    }
    resultados = {f"192.168.1.{i}": _resultado_fake() for i in range(10, 18)}
    grafo = construir_grafo(resultados, "192.168.1.0/24", topologia=topologia)
    salida = tmp_path / "topologia.html"

    exportar_html(grafo, str(salida))

    html = salida.read_text(encoding="utf-8")
    aristas = json.loads(html.split("edges = new vis.DataSet(")[1].split(");")[0])
    assert [a.get("label") for a in aristas].count("wlan1") == 1
    assert len(aristas) == 8


def test_exportar_html_sin_hostname_no_repite_la_ip_en_la_etiqueta(tmp_path):
    grafo = construir_grafo({"192.168.1.10": _resultado_fake(hostname="")}, "192.168.1.0/24")
    salida = tmp_path / "topologia.html"

    exportar_html(grafo, str(salida))

    assert _nodos_del_html(salida.read_text(encoding="utf-8"))["192.168.1.10"]["label"] == "192.168.1.10"


def test_exportar_html_ajusta_la_vista_al_cargar(tmp_path):
    """El encuadre inicial no puede depender de la simulación física: en el
    árbol todos los nodos son fijos y las aristas no son 'dynamic', así que
    vis-network nunca terminaba una estabilización que lo disparase."""
    grafo = construir_grafo({"192.168.1.10": _resultado_fake()}, "192.168.1.0/24",
                            topologia=_topologia_minima())
    salida = tmp_path / "topologia.html"

    exportar_html(grafo, str(salida))

    assert 'network.once("afterDrawing"' in salida.read_text(encoding="utf-8")


# === Varios rangos ==========================================================

def test_exportar_html_con_varios_rangos_usa_el_layout_por_niveles(tmp_path):
    """Con un centro por rango, el círculo no sirve (todos los centros irían
    al origen): cada rango se dibuja como su propia estrella, una al lado de
    otra, con el mismo layout por niveles que el árbol SNMP."""
    resultados = {"192.168.50.10": _resultado_fake(), "10.0.10.10": _resultado_fake()}
    grafo = construir_grafo(resultados, ["192.168.50.0/24", "10.0.10.0/24"])
    salida = tmp_path / "topologia.html"

    exportar_html(grafo, str(salida))

    nodos = _nodos_del_html(salida.read_text(encoding="utf-8"))
    centro_a, centro_b = nodos["Network 192.168.50.0/24"], nodos["Network 10.0.10.0/24"]
    assert centro_a["y"] == centro_b["y"]
    assert centro_a["x"] != centro_b["x"]
    assert nodos["10.0.10.10"]["y"] > centro_b["y"]


def test_exportar_diff_texto_con_rango_lo_indica_en_la_cabecera(capsys):
    exportar_diff_texto({"primera_vez": True, "hosts_nuevos": [], "hosts_caidos": [], "puertos_cambiados": {}},
                        rango="10.0.10.0/24")

    assert "HISTORY - 10.0.10.0/24" in capsys.readouterr().out


def test_posiciones_jerarquicas_ordena_las_ips_como_numeros():
    """Ordenadas como texto salía .1, .10, .11, .2... (visto en una red real)."""
    grafo = _arbol([("router", f"192.0.2.{i}", "wlan1") for i in (10, 2, 1, 11)])

    pos = posiciones_jerarquicas(grafo)
    orden = sorted((n for n in grafo.nodes if n != "router"), key=lambda n: (pos[n][1], pos[n][0]))

    assert orden == ["192.0.2.1", "192.0.2.2", "192.0.2.10", "192.0.2.11"]
