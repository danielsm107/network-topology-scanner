"""
Tests de cli.py: la orquestación de errores (que main() convierta las
excepciones de scanner/export en sys.exit con mensaje claro) y la
combinación de flags de construir_parser()/_resolver_argumentos_nmap().
"""

from unittest.mock import patch

import pytest

from topology_scanner.cli import main, construir_parser, _resolver_argumentos_nmap
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


def _parsear(argv):
    return construir_parser().parse_args(argv)


def test_nmap_args_por_defecto_es_sv_t4():
    parser = construir_parser()
    args = _parsear(["192.168.1.0/24"])
    assert _resolver_argumentos_nmap(args, parser) == "-sV -T4"


def test_con_so_añade_flags_de_deteccion_de_so():
    parser = construir_parser()
    args = _parsear(["192.168.1.0/24", "--con-so"])
    assert _resolver_argumentos_nmap(args, parser) == "-sV -T4 -O --osscan-guess"


def test_nmap_args_personalizado_se_respeta():
    parser = construir_parser()
    args = _parsear(["192.168.1.0/24", "--nmap-args", "-p 22"])
    assert _resolver_argumentos_nmap(args, parser) == "-p 22"


def test_rapido_usa_preset_t4():
    parser = construir_parser()
    args = _parsear(["192.168.1.0/24", "--rapido"])
    assert _resolver_argumentos_nmap(args, parser) == "-T4"


def test_rapido_con_con_so_es_un_error_no_un_override_silencioso():
    parser = construir_parser()
    args = _parsear(["192.168.1.0/24", "--rapido", "--con-so"])
    with pytest.raises(SystemExit):
        _resolver_argumentos_nmap(args, parser)


def test_rapido_con_nmap_args_es_un_error_no_un_override_silencioso():
    parser = construir_parser()
    args = _parsear(["192.168.1.0/24", "--rapido", "--nmap-args", "-p 22"])
    with pytest.raises(SystemExit):
        _resolver_argumentos_nmap(args, parser)
