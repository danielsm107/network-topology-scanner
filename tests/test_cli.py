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
from topology_scanner.history import HistoryError


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
        _run_main_con_argv(["192.168.1.0/24", "--sin-historial"])

    assert "pyvis" in str(excinfo.value)


def _resultado_dummy():
    return {"192.168.1.10": {"puertos": [], "hostname": "", "so": "", "mac": "", "vendor": "", "categoria": "desconocido"}}


@patch("topology_scanner.cli.exportar_diff_texto")
@patch("topology_scanner.cli.registrar_y_comparar")
@patch("topology_scanner.cli.exportar_html")
@patch("topology_scanner.cli.exportar_texto")
@patch("topology_scanner.cli.construir_grafo")
@patch("topology_scanner.cli.escanear_red")
def test_main_guarda_historial_y_muestra_el_diff(
    mock_escanear_red, mock_construir_grafo, mock_exportar_texto,
    mock_exportar_html, mock_registrar, mock_exportar_diff,
):
    mock_escanear_red.return_value = _resultado_dummy()
    diff_falso = {"primera_vez": True, "hosts_nuevos": [], "hosts_caidos": [], "puertos_cambiados": {}}
    mock_registrar.return_value = diff_falso

    _run_main_con_argv(["192.168.1.0/24", "--history-db", "db_de_prueba.sqlite"])

    mock_registrar.assert_called_once_with(mock_escanear_red.return_value, "192.168.1.0/24", db_path="db_de_prueba.sqlite")
    mock_exportar_diff.assert_called_once_with(diff_falso)


@patch("topology_scanner.cli.exportar_diff_texto")
@patch("topology_scanner.cli.registrar_y_comparar")
@patch("topology_scanner.cli.exportar_html")
@patch("topology_scanner.cli.exportar_texto")
@patch("topology_scanner.cli.construir_grafo")
@patch("topology_scanner.cli.escanear_red")
def test_main_no_llama_al_historial_con_sin_historial(
    mock_escanear_red, mock_construir_grafo, mock_exportar_texto,
    mock_exportar_html, mock_registrar, mock_exportar_diff,
):
    mock_escanear_red.return_value = _resultado_dummy()

    _run_main_con_argv(["192.168.1.0/24", "--sin-historial"])

    mock_registrar.assert_not_called()
    mock_exportar_diff.assert_not_called()


@patch("topology_scanner.cli.exportar_diff_texto")
@patch("topology_scanner.cli.registrar_y_comparar")
@patch("topology_scanner.cli.exportar_html")
@patch("topology_scanner.cli.exportar_texto")
@patch("topology_scanner.cli.construir_grafo")
@patch("topology_scanner.cli.escanear_red")
def test_main_continua_si_falla_el_historial(
    mock_escanear_red, mock_construir_grafo, mock_exportar_texto,
    mock_exportar_html, mock_registrar, mock_exportar_diff,
):
    """Un fallo guardando el historial no debe tirar un escaneo que sí ha
    funcionado: se avisa y se sigue exportando el HTML con normalidad."""
    mock_escanear_red.return_value = _resultado_dummy()
    mock_registrar.side_effect = HistoryError("no se pudo abrir historial.db")

    _run_main_con_argv(["192.168.1.0/24"])

    mock_exportar_diff.assert_not_called()
    mock_exportar_html.assert_called_once()


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
