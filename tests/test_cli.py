"""
Tests de cli.py: solo la orquestación de errores (que main() convierta
las excepciones de scanner/export en sys.exit con mensaje claro).
El parseo de argumentos y el resto de lógica vive en scanner/graph/export
y ya está cubierto en sus propios tests.
"""

from unittest.mock import patch

import pytest

from topology_scanner.cli import main
from topology_scanner.scanner import ScannerError
from topology_scanner.export import ExportError


def _run_main_con_argv(argv):
    with patch("sys.argv", ["topology-scanner"] + argv):
        main()


@patch("topology_scanner.cli.escanear_red")
def test_main_sale_con_mensaje_claro_si_falla_el_escaneo(mock_escanear_red):
    mock_escanear_red.side_effect = ScannerError("Error de nmap (¿ejecutas con sudo?): boom")

    with pytest.raises(SystemExit) as excinfo:
        _run_main_con_argv(["192.168.1.0/24"])

    assert "boom" in str(excinfo.value)


@patch("topology_scanner.cli.exportar_html")
@patch("topology_scanner.cli.exportar_texto")
@patch("topology_scanner.cli.construir_grafo")
@patch("topology_scanner.cli.escanear_red")
def test_main_sale_con_mensaje_claro_si_falla_la_exportacion(
    mock_escanear_red, mock_construir_grafo, mock_exportar_texto, mock_exportar_html
):
    mock_escanear_red.return_value = {"192.168.1.10": {"puertos": [], "hostname": "", "so": "", "mac": "", "vendor": "", "categoria": "desconocido"}}
    mock_exportar_html.side_effect = ExportError("Falta pyvis. Instala con: pip install pyvis")

    with pytest.raises(SystemExit) as excinfo:
        _run_main_con_argv(["192.168.1.0/24"])

    assert "pyvis" in str(excinfo.value)
