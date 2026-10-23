"""
Tests de cli.py: la orquestación de errores (que main() convierta las
excepciones de scanner/export en sys.exit con mensaje claro), la
combinación de flags de construir_parser()/_resolver_argumentos_nmap() y
la topología opcional por SNMP (--snmp + TOPOLOGY_SNMP_COMMUNITY).
"""

from unittest.mock import patch

import pytest

from topology_scanner.cli import VARIABLE_COMMUNITY, _resolver_argumentos_nmap, construir_parser, main
from topology_scanner.export import ExportError
from topology_scanner.history import HistoryError
from topology_scanner.scanner import ScannerError
from topology_scanner.snmp import CredencialesV3, SnmpError


def _run_main_con_argv(argv):
    with patch("sys.argv", ["topology-scanner", *argv]):
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
    mock_escanear_red.return_value = {
        "192.168.1.10": {
            "puertos": [], "hostname": "", "so": "", "mac": "",
            "vendor": "", "categoria": "unknown",
        }
    }
    mock_exportar_html.side_effect = ExportError("pyvis is missing. Install it with: pip install pyvis")

    with pytest.raises(SystemExit) as excinfo:
        _run_main_con_argv(["192.168.1.0/24", "--no-history"])

    assert "pyvis" in str(excinfo.value)


@patch("topology_scanner.cli.exportar_html")
@patch("topology_scanner.cli.exportar_csv")
@patch("topology_scanner.cli.exportar_texto")
@patch("topology_scanner.cli.construir_grafo")
@patch("topology_scanner.cli.escanear_red")
def test_main_sale_con_mensaje_claro_si_no_puede_escribir_el_csv(
    mock_escanear_red, mock_construir_grafo, mock_exportar_texto, mock_exportar_csv, mock_exportar_html
):
    mock_escanear_red.return_value = _resultado_dummy()
    mock_exportar_csv.side_effect = ExportError("Could not write x.csv: Permission denied")

    with pytest.raises(SystemExit) as excinfo:
        _run_main_con_argv(["192.168.1.0/24", "--no-history", "--csv", "x.csv"])

    assert str(excinfo.value) == "Could not write x.csv: Permission denied"


def _resultado_dummy():
    return {
        "192.168.1.10": {
            "puertos": [], "hostname": "", "so": "", "mac": "",
            "vendor": "", "categoria": "unknown",
        }
    }


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

    mock_registrar.assert_called_once_with(
        mock_escanear_red.return_value, "192.168.1.0/24", db_path="db_de_prueba.sqlite"
    )
    mock_exportar_diff.assert_called_once_with(diff_falso, rango=None)


@patch("topology_scanner.cli.exportar_diff_texto")
@patch("topology_scanner.cli.registrar_y_comparar")
@patch("topology_scanner.cli.exportar_html")
@patch("topology_scanner.cli.exportar_texto")
@patch("topology_scanner.cli.construir_grafo")
@patch("topology_scanner.cli.escanear_red")
def test_main_no_llama_al_historial_con_no_history(
    mock_escanear_red, mock_construir_grafo, mock_exportar_texto,
    mock_exportar_html, mock_registrar, mock_exportar_diff,
):
    mock_escanear_red.return_value = _resultado_dummy()

    _run_main_con_argv(["192.168.1.0/24", "--no-history"])

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


@patch("topology_scanner.cli.exportar_csv")
@patch("topology_scanner.cli.exportar_html")
@patch("topology_scanner.cli.exportar_texto")
@patch("topology_scanner.cli.construir_grafo")
@patch("topology_scanner.cli.escanear_red")
def test_main_exporta_csv_si_se_pide(
    mock_escanear_red, mock_construir_grafo, mock_exportar_texto,
    mock_exportar_html, mock_exportar_csv,
):
    mock_escanear_red.return_value = _resultado_dummy()

    _run_main_con_argv(["192.168.1.0/24", "--no-history", "--csv", "inventario.csv"])

    mock_exportar_csv.assert_called_once_with(mock_escanear_red.return_value, "inventario.csv")


@patch("topology_scanner.cli.exportar_csv")
@patch("topology_scanner.cli.exportar_html")
@patch("topology_scanner.cli.exportar_texto")
@patch("topology_scanner.cli.construir_grafo")
@patch("topology_scanner.cli.escanear_red")
def test_main_no_exporta_csv_por_defecto(
    mock_escanear_red, mock_construir_grafo, mock_exportar_texto,
    mock_exportar_html, mock_exportar_csv,
):
    mock_escanear_red.return_value = _resultado_dummy()

    _run_main_con_argv(["192.168.1.0/24", "--no-history"])

    mock_exportar_csv.assert_not_called()


def _parsear(argv):
    return construir_parser().parse_args(argv)


def test_nmap_args_por_defecto_es_sv_t4():
    parser = construir_parser()
    args = _parsear(["192.168.1.0/24"])
    assert _resolver_argumentos_nmap(args, parser) == "-sV -T4"


def test_os_detection_añade_flags_de_deteccion_de_so():
    parser = construir_parser()
    args = _parsear(["192.168.1.0/24", "--os-detection"])
    assert _resolver_argumentos_nmap(args, parser) == "-sV -T4 -O --osscan-guess"


def test_nmap_args_personalizado_se_respeta():
    parser = construir_parser()
    args = _parsear(["192.168.1.0/24", "--nmap-args", "-p 22"])
    assert _resolver_argumentos_nmap(args, parser) == "-p 22"


def test_fast_usa_preset_t4():
    parser = construir_parser()
    args = _parsear(["192.168.1.0/24", "--fast"])
    assert _resolver_argumentos_nmap(args, parser) == "-T4"


def test_fast_con_os_detection_es_un_error_no_un_override_silencioso():
    parser = construir_parser()
    args = _parsear(["192.168.1.0/24", "--fast", "--os-detection"])
    with pytest.raises(SystemExit):
        _resolver_argumentos_nmap(args, parser)


def test_fast_con_nmap_args_es_un_error_no_un_override_silencioso():
    parser = construir_parser()
    args = _parsear(["192.168.1.0/24", "--fast", "--nmap-args", "-p 22"])
    with pytest.raises(SystemExit):
        _resolver_argumentos_nmap(args, parser)


def test_fast_con_os_detection_explica_el_conflicto_en_ingles(capsys):
    parser = construir_parser()
    args = _parsear(["192.168.1.0/24", "--fast", "--os-detection"])
    with pytest.raises(SystemExit):
        _resolver_argumentos_nmap(args, parser)

    assert "--fast cannot be combined with --os-detection or --nmap-args" in capsys.readouterr().err


# === Flags en inglés, con los antiguos en español como alias ocultos ========

@pytest.mark.parametrize(("antiguo", "nuevo"), [
    ("--rapido", "--fast"),
    ("--con-so", "--os-detection"),
    ("--sin-2-fases", "--no-discovery"),
    ("--sin-historial", "--no-history"),
])
def test_los_flags_en_español_siguen_funcionando_como_alias(antiguo, nuevo):
    """La v1.0 ya está en PyPI con los flags en español: quien los tenga en
    un script o un cron no debe romperse al actualizar."""
    assert _parsear(["192.168.1.0/24", antiguo]) == _parsear(["192.168.1.0/24", nuevo])


def test_la_ayuda_esta_en_ingles_y_no_muestra_los_alias_en_español():
    ayuda = construir_parser().format_help()

    assert "Scans a network and generates an interactive topology graph" in ayuda
    for flag in ("--fast", "--os-detection", "--no-discovery", "--no-history"):
        assert flag in ayuda
    for alias in ("--rapido", "--con-so", "--sin-2-fases", "--sin-historial"):
        assert alias not in ayuda


def test_el_html_por_defecto_se_llama_network_topology():
    assert _parsear(["192.168.1.0/24"]).output == "network_topology.html"


@patch("topology_scanner.cli.escanear_red")
def test_snmp_sin_credenciales_lo_explica_en_ingles(mock_escanear_red, monkeypatch, capsys):
    monkeypatch.delenv(VARIABLE_COMMUNITY, raising=False)
    monkeypatch.delenv("TOPOLOGY_SNMP_USER", raising=False)

    with pytest.raises(SystemExit):
        _run_main_con_argv(["192.168.1.0/24", "--snmp", "192.168.1.1"])

    assert "--snmp needs credentials" in capsys.readouterr().err


@patch("topology_scanner.cli.escanear_red")
def test_sin_hosts_lo_avisa_en_ingles(mock_escanear_red, caplog):
    mock_escanear_red.return_value = {}

    _run_main_con_argv(["192.168.1.0/24", "--no-history"])

    assert "No hosts found" in caplog.text


# === Topología por SNMP (--snmp) ============================================

def test_snmp_acepta_una_lista_de_ips_separadas_por_comas():
    args = construir_parser().parse_args(["192.168.1.0/24", "--snmp", "192.168.1.1, 192.168.1.2"])

    assert args.snmp == ["192.168.1.1", "192.168.1.2"]


def test_snmp_por_defecto_no_consulta_nada():
    assert construir_parser().parse_args(["192.168.1.0/24"]).snmp is None


def test_snmp_con_una_ip_no_valida_es_un_error():
    with pytest.raises(SystemExit):
        construir_parser().parse_args(["192.168.1.0/24", "--snmp", "192.168.1.1,router-casa"])


@patch("topology_scanner.cli.escanear_red")
def test_snmp_sin_community_falla_antes_de_escanear(mock_escanear_red, monkeypatch, capsys):
    """La community va por variable de entorno, nunca como argumento (se
    vería en `ps` y en el historial de la shell). Si falta, se avisa antes
    de lanzar un escaneo de nmap que puede tardar minutos."""
    monkeypatch.delenv(VARIABLE_COMMUNITY, raising=False)

    with pytest.raises(SystemExit):
        _run_main_con_argv(["192.168.1.0/24", "--snmp", "192.168.1.1"])

    mock_escanear_red.assert_not_called()
    assert VARIABLE_COMMUNITY in capsys.readouterr().err


@patch("topology_scanner.cli.exportar_html")
@patch("topology_scanner.cli.exportar_texto")
@patch("topology_scanner.cli.construir_grafo")
@patch("topology_scanner.snmp.inferir_topologia")
@patch("topology_scanner.snmp.consultar_equipo")
@patch("topology_scanner.cli.escanear_red")
def test_snmp_consulta_los_equipos_y_pasa_la_topologia_al_grafo(
    mock_escanear_red, mock_consultar, mock_inferir, mock_construir_grafo,
    mock_exportar_texto, mock_exportar_html, monkeypatch,
):
    monkeypatch.setenv(VARIABLE_COMMUNITY, "community-de-prueba")
    mock_escanear_red.return_value = _resultado_dummy()
    mock_consultar.side_effect = lambda ip, community: {"ip": ip}
    topologia = {"equipos": {}, "enlaces": [], "redes": {}, "ubicaciones": {}}
    mock_inferir.return_value = topologia

    _run_main_con_argv(["192.168.1.0/24", "--no-history", "--snmp", "192.168.1.1,192.168.1.2"])

    assert [c.args for c in mock_consultar.call_args_list] == [
        ("192.168.1.1", "community-de-prueba"), ("192.168.1.2", "community-de-prueba"),
    ]
    mock_inferir.assert_called_once_with([{"ip": "192.168.1.1"}, {"ip": "192.168.1.2"}])
    mock_construir_grafo.assert_called_once_with(_resultado_dummy(), ["192.168.1.0/24"], topologia=topologia)


@patch("topology_scanner.cli.exportar_html")
@patch("topology_scanner.cli.exportar_texto")
@patch("topology_scanner.cli.construir_grafo")
@patch("topology_scanner.snmp.inferir_topologia")
@patch("topology_scanner.snmp.consultar_equipo")
@patch("topology_scanner.cli.escanear_red")
def test_snmp_un_equipo_que_no_responde_se_salta_y_se_sigue_con_los_demas(
    mock_escanear_red, mock_consultar, mock_inferir, mock_construir_grafo,
    mock_exportar_texto, mock_exportar_html, monkeypatch, caplog,
):
    monkeypatch.setenv(VARIABLE_COMMUNITY, "community-de-prueba")
    mock_escanear_red.return_value = _resultado_dummy()
    mock_consultar.side_effect = [SnmpError("192.168.1.1 is not responding over SNMP"), {"ip": "192.168.1.2"}]

    _run_main_con_argv(["192.168.1.0/24", "--no-history", "--snmp", "192.168.1.1,192.168.1.2"])

    mock_inferir.assert_called_once_with([{"ip": "192.168.1.2"}])
    assert "not responding" in caplog.text


@patch("topology_scanner.cli.exportar_html")
@patch("topology_scanner.cli.exportar_texto")
@patch("topology_scanner.cli.construir_grafo")
@patch("topology_scanner.snmp.inferir_topologia")
@patch("topology_scanner.snmp.consultar_equipo")
@patch("topology_scanner.cli.escanear_red")
def test_snmp_si_no_responde_ninguno_se_dibuja_la_estrella(
    mock_escanear_red, mock_consultar, mock_inferir, mock_construir_grafo,
    mock_exportar_texto, mock_exportar_html, monkeypatch, caplog,
):
    """Mismo criterio que el historial: el escaneo de nmap ya ha funcionado,
    perder la topología SNMP no es motivo para no generar nada."""
    monkeypatch.setenv(VARIABLE_COMMUNITY, "community-de-prueba")
    mock_escanear_red.return_value = _resultado_dummy()
    mock_consultar.side_effect = SnmpError("192.168.1.1 is not responding over SNMP")

    _run_main_con_argv(["192.168.1.0/24", "--no-history", "--snmp", "192.168.1.1"])

    mock_inferir.assert_not_called()
    mock_construir_grafo.assert_called_once_with(_resultado_dummy(), ["192.168.1.0/24"], topologia=None)
    mock_exportar_html.assert_called_once()
    assert "star layout" in caplog.text


@patch("topology_scanner.cli.exportar_html")
@patch("topology_scanner.cli.exportar_texto")
@patch("topology_scanner.cli.construir_grafo")
@patch("topology_scanner.snmp.consultar_equipo")
@patch("topology_scanner.cli.escanear_red")
def test_sin_snmp_no_se_consulta_nada(
    mock_escanear_red, mock_consultar, mock_construir_grafo, mock_exportar_texto, mock_exportar_html,
):
    mock_escanear_red.return_value = _resultado_dummy()

    _run_main_con_argv(["192.168.1.0/24", "--no-history"])

    mock_consultar.assert_not_called()
    mock_construir_grafo.assert_called_once_with(_resultado_dummy(), ["192.168.1.0/24"], topologia=None)


# === Varios rangos ==========================================================

def test_acepta_varios_rangos_como_argumentos():
    args = construir_parser().parse_args(["192.168.50.0/24", "10.0.10.0/24"])

    assert args.rango == ["192.168.50.0/24", "10.0.10.0/24"]


@patch("topology_scanner.cli.escanear_red")
def test_varios_rangos_con_uno_no_valido_falla_antes_de_escanear(mock_escanear_red, capsys):
    with pytest.raises(SystemExit):
        _run_main_con_argv(["10.0.10.0/24", "192.168.1.1-50"])

    mock_escanear_red.assert_not_called()
    assert "192.168.1.1-50" in capsys.readouterr().err


@patch("topology_scanner.cli.exportar_diff_texto")
@patch("topology_scanner.cli.registrar_y_comparar")
@patch("topology_scanner.cli.exportar_html")
@patch("topology_scanner.cli.exportar_texto")
@patch("topology_scanner.cli.construir_grafo")
@patch("topology_scanner.cli.escanear_red")
def test_varios_rangos_se_escanean_juntos_y_el_historial_va_por_rango(
    mock_escanear_red, mock_construir_grafo, mock_exportar_texto,
    mock_exportar_html, mock_registrar, mock_exportar_diff,
):
    """nmap recibe todos los objetivos de una vez; el historial guarda y
    compara cada rango por separado (rangos distintos no se mezclan), así
    que un rango que antes se escaneaba solo sigue comparándose bien."""
    lan_a = {"192.168.50.10": _resultado_dummy()["192.168.1.10"]}
    lan_b = {"10.0.10.10": _resultado_dummy()["192.168.1.10"]}
    mock_escanear_red.return_value = {**lan_a, **lan_b}
    mock_registrar.return_value = {"primera_vez": True}

    _run_main_con_argv(["192.168.50.0/24", "10.0.10.0/24"])

    assert mock_escanear_red.call_args.args[0] == "192.168.50.0/24 10.0.10.0/24"
    assert [c.args[:2] for c in mock_registrar.call_args_list] == [
        (lan_a, "192.168.50.0/24"), (lan_b, "10.0.10.0/24"),
    ]
    assert [c.kwargs.get("rango") for c in mock_exportar_diff.call_args_list] == ["192.168.50.0/24", "10.0.10.0/24"]
    assert mock_construir_grafo.call_args.args[1] == ["192.168.50.0/24", "10.0.10.0/24"]


@patch("topology_scanner.cli.exportar_diff_texto")
@patch("topology_scanner.cli.registrar_y_comparar")
@patch("topology_scanner.cli.exportar_html")
@patch("topology_scanner.cli.exportar_texto")
@patch("topology_scanner.cli.construir_grafo")
@patch("topology_scanner.cli.escanear_red")
def test_un_solo_rango_no_cambia_la_salida_del_historial(
    mock_escanear_red, mock_construir_grafo, mock_exportar_texto,
    mock_exportar_html, mock_registrar, mock_exportar_diff,
):
    mock_escanear_red.return_value = _resultado_dummy()
    mock_registrar.return_value = {"primera_vez": True}

    _run_main_con_argv(["192.168.1.0/24"])

    mock_registrar.assert_called_once()
    assert mock_exportar_diff.call_args.kwargs.get("rango") is None


# === SNMPv3 =================================================================

@patch("topology_scanner.cli.exportar_html")
@patch("topology_scanner.cli.exportar_texto")
@patch("topology_scanner.cli.construir_grafo")
@patch("topology_scanner.snmp.inferir_topologia")
@patch("topology_scanner.snmp.consultar_equipo")
@patch("topology_scanner.cli.escanear_red")
def test_snmp_v3_si_hay_usuario_en_el_entorno(
    mock_escanear_red, mock_consultar, mock_inferir, mock_construir_grafo,
    mock_exportar_texto, mock_exportar_html, monkeypatch,
):
    monkeypatch.setenv("TOPOLOGY_SNMP_USER", "lector")
    monkeypatch.setenv("TOPOLOGY_SNMP_AUTH_KEY", "clave-auth")
    monkeypatch.setenv("TOPOLOGY_SNMP_PRIV_KEY", "clave-priv")
    mock_escanear_red.return_value = _resultado_dummy()
    mock_consultar.return_value = {"ip": "192.168.1.1"}
    mock_inferir.return_value = {"equipos": {}, "enlaces": [], "redes": {}, "ubicaciones": {}}

    _run_main_con_argv(["192.168.1.0/24", "--no-history", "--snmp", "192.168.1.1"])

    assert mock_consultar.call_args.args == ("192.168.1.1", CredencialesV3("lector", "clave-auth", "clave-priv"))


@patch("topology_scanner.cli.escanear_red")
def test_snmp_v3_mal_configurado_falla_antes_de_escanear(mock_escanear_red, monkeypatch, capsys):
    monkeypatch.setenv("TOPOLOGY_SNMP_USER", "lector")
    monkeypatch.setenv("TOPOLOGY_SNMP_AUTH_KEY", "corta")

    with pytest.raises(SystemExit):
        _run_main_con_argv(["192.168.1.0/24", "--snmp", "192.168.1.1"])

    mock_escanear_red.assert_not_called()
    assert "at least 8 characters" in capsys.readouterr().err
