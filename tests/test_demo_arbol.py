"""
Tests de scripts/demo_arbol.py, el generador de la captura del árbol SNMP
del README. No es parte del paquete (no se instala), así que se carga por
ruta. Lo importante es que la captura sea pública: todo dato tiene que ser
inventado, nunca de una red real.
"""

import importlib.util
import ipaddress
from pathlib import Path

from topology_scanner.graph import construir_grafo

RUTA_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "demo_arbol.py"
REDES_DE_DOCUMENTACION = [ipaddress.ip_network(r) for r in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _cargar_demo():
    spec = importlib.util.spec_from_file_location("demo_arbol", RUTA_SCRIPT)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def _es_de_documentacion(ip: str) -> bool:
    return any(ipaddress.ip_address(ip) in red for red in REDES_DE_DOCUMENTACION)


def test_todas_las_ips_y_macs_de_la_demo_son_inventadas():
    resultados, rangos, topologia = _cargar_demo().datos_demo()

    ips = set(resultados) | set(topologia["equipos"]) | set(topologia["redes"].values())
    ips |= {u["ip"] for u in topologia["ubicaciones"].values() if u["ip"]}
    macs = {d["mac"] for d in resultados.values() if d["mac"]} | set(topologia["ubicaciones"])

    assert all(_es_de_documentacion(ip) for ip in ips)
    assert all(any(ipaddress.ip_network(r).subnet_of(red) for red in REDES_DE_DOCUMENTACION) for r in rangos)
    assert all(mac.lower().startswith("02:00:00:") for mac in macs)


def test_la_demo_es_un_arbol_de_varios_niveles():
    resultados, rangos, topologia = _cargar_demo().datos_demo()
    grafo = construir_grafo(resultados, rangos, topologia)

    def profundidad(nodo):
        padre = grafo.nodes[nodo].get("padre")
        return 0 if padre is None else 1 + profundidad(padre)

    # upstream -> router -> switch/AP -> host
    assert max(profundidad(n) for n in grafo.nodes) >= 3
    assert any(at.get("alertas") for _, at in grafo.nodes(data=True))
    assert any(at.get("solo_snmp") for _, at in grafo.nodes(data=True))


def test_generar_escribe_el_html(tmp_path):
    salida = tmp_path / "arbol.html"
    _cargar_demo().generar(str(salida))
    assert "vis-network" in salida.read_text(encoding="utf-8")


def test_los_nombres_de_la_demo_estan_en_ingles():
    """Salen en las capturas del README, que lee un público anglohablante."""
    resultados, _, topologia = _cargar_demo().datos_demo()
    nombres = [d["hostname"] for d in resultados.values()] + [e["nombre"] for e in topologia["equipos"].values()]
    nombres += [u["interfaz"] or "" for u in topologia["ubicaciones"].values()]

    for palabra in ("salon", "planta", "oficina", "impresora", "enchufe", "camara", "jardin", "entrada"):
        assert not any(palabra in nombre for nombre in nombres), palabra
