"""
Tests de export.py. exportar_html usa pyvis de verdad (no se mockea):
es un módulo de exportación puro, más simple y fiable comprobar el HTML
generado de verdad que simular toda la API de pyvis.
"""

from topology_scanner.export import exportar_html, exportar_texto, COLOR_ALERTA
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
    assert "192.168.1.1" in salida
    assert "router01" in salida
    assert "80/tcp" in salida
    assert "nginx" in salida


def test_exportar_texto_host_sin_puertos_lo_indica(capsys):
    exportar_texto({"192.168.1.1": _resultado_fake(puertos=[])})

    salida = capsys.readouterr().out
    assert "Sin puertos abiertos detectados" in salida


def test_exportar_html_marca_con_color_de_alerta_si_hay_puertos_sensibles(tmp_path):
    alertas = [{"puerto": 3389, "motivo": "RDP (objetivo habitual de fuerza bruta)"}]
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
    assert COLOR_ALERTA.replace("#", "") not in html
