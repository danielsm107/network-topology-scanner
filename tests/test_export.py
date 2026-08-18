"""
Tests de export.py. exportar_html usa pyvis de verdad (no se mockea):
es un módulo de exportación puro, más simple y fiable comprobar el HTML
generado de verdad que simular toda la API de pyvis.
"""

import csv
import io

from topology_scanner.export import (
    exportar_html, exportar_texto, exportar_diff_texto, exportar_csv, COLOR_ALERTA,
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


def test_exportar_diff_texto_primera_vez(capsys):
    diff = {"primera_vez": True, "hosts_nuevos": [], "hosts_caidos": [], "puertos_cambiados": {}}

    exportar_diff_texto(diff)

    assert "primer escaneo" in capsys.readouterr().out.lower()


def test_exportar_diff_texto_muestra_hosts_nuevos_y_caidos(capsys):
    diff = {
        "primera_vez": False,
        "hosts_nuevos": ["192.168.1.20"],
        "hosts_caidos": ["192.168.1.99"],
        "puertos_cambiados": {},
    }

    exportar_diff_texto(diff)

    salida = capsys.readouterr().out
    assert "192.168.1.20" in salida
    assert "192.168.1.99" in salida


def test_exportar_diff_texto_muestra_puertos_cambiados(capsys):
    diff = {
        "primera_vez": False,
        "hosts_nuevos": [],
        "hosts_caidos": [],
        "puertos_cambiados": {"192.168.1.10": {"nuevos": [80], "cerrados": [22]}},
    }

    exportar_diff_texto(diff)

    salida = capsys.readouterr().out
    assert "192.168.1.10" in salida
    assert "80" in salida
    assert "22" in salida


def test_exportar_diff_texto_destaca_puertos_nuevos_sensibles(capsys):
    diff = {
        "primera_vez": False,
        "hosts_nuevos": [],
        "hosts_caidos": [],
        "puertos_cambiados": {
            "192.168.1.10": {
                "nuevos": [23],
                "cerrados": [],
                "nuevos_sensibles": [{"puerto": 23, "motivo": "Telnet (sin cifrar)"}],
            }
        },
    }

    exportar_diff_texto(diff)

    salida = capsys.readouterr().out
    assert "192.168.1.10" in salida
    assert "23" in salida
    assert "Telnet" in salida
    assert "sensible" in salida.lower()


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
                "nuevos_sensibles": [{"puerto": 23, "motivo": "Telnet (sin cifrar)"}],
            }
        },
    }

    exportar_diff_texto(diff)  # no debe lanzar UnicodeEncodeError


def test_exportar_diff_texto_sin_cambios_lo_indica(capsys):
    diff = {"primera_vez": False, "hosts_nuevos": [], "hosts_caidos": [], "puertos_cambiados": {}}

    exportar_diff_texto(diff)

    assert "sin cambios" in capsys.readouterr().out.lower()


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

    assert filas[0] == ["ip", "hostname", "mac", "vendor", "categoria", "so", "puertos", "alertas"]
    assert len(filas) == 2
    fila = filas[1]
    assert fila[0] == "192.168.1.10"
    assert fila[1] == "server01"
    assert "22/ssh" in fila[6]


def test_exportar_csv_incluye_alertas(tmp_path):
    alertas = [{"puerto": 3389, "motivo": "RDP (objetivo habitual de fuerza bruta)"}]
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
