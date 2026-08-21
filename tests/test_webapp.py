"""
Tests de webapp.py. streamlit es una dependencia opcional (extra "web"),
así que este módulo entero se salta si no está instalado - no debe romper
`pytest tests/ -v` para quien solo instaló el CLI.

La lógica pura (_argumentos_nmap_desde_formulario, _construir_comando_nmap,
_procesar_salida_nmap, _finalizar_resultados, _filas_para_tabla) se testea
con pytest normal, mockeando los mismos puntos que test_cli.py. El
renderizado de widgets se comprueba con
streamlit.testing.v1.AppTest, que ejecuta el script sin navegador - pero
sin llegar a lanzar un escaneo real (eso no se prueba aquí, solo a mano
en el navegador, igual que el resto de cambios de UI de este proyecto).
"""

import logging
import os
import tempfile
from unittest.mock import MagicMock, patch

import nmap
import pytest

pytest.importorskip("streamlit", reason='pip install "topology-scanner[web]" para probar la interfaz web')

from topology_scanner.history import HistoryError
from topology_scanner.scanner import ScannerError
from topology_scanner.webapp import (
    _argumentos_nmap_desde_formulario,
    _construir_comando_nmap,
    _detectar_rango_local,
    _ejecutar_proceso_nmap,
    _filas_para_tabla,
    _finalizar_resultados,
    _formatear_tiempo_transcurrido,
    _generar_cambios_html,
    _generar_chips_categorias_html,
    _generar_css,
    _generar_encabezado_html,
    _generar_estado_vacio_html,
    _generar_kpis_html,
    _generar_progreso_html,
    _generar_tabla_inventario_html,
    _procesar_salida_nmap,
)


@pytest.fixture(autouse=True)
def _sin_historial_real(tmp_path, monkeypatch):
    """Los tests con AppTest renderizan el sidebar entero, incluido el
    historial reciente - que por defecto lee/crea historial.db en el cwd.
    Sin este chdir a un directorio temporal, solo con ejecutar
    `pytest tests/ -v` ya se creaba (o se leía) el historial.db real del
    proyecto en la raíz del repo, el mismo problema de archivos huérfanos
    que _finalizar_resultados/_generar_csv_bytes ya solucionan para
    .html/.csv."""
    monkeypatch.chdir(tmp_path)


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


def test_rapido_devuelve_preset_t4():
    assert _argumentos_nmap_desde_formulario(rapido=True, con_so=False) == "-T4"


def test_rapido_gana_si_se_marca_con_so_tambien():
    """A diferencia del CLI, aquí no hay --nmap-args libre con el que rápido
    pueda entrar en conflicto - simplemente gana, sin necesidad de cortar
    con un error como hace cli.py._resolver_argumentos_nmap."""
    assert _argumentos_nmap_desde_formulario(rapido=True, con_so=True) == "-T4"


def test_sin_rapido_usa_el_preset_por_defecto():
    assert _argumentos_nmap_desde_formulario(rapido=False, con_so=False) == "-sV -T4"


def test_con_so_anade_flags_de_deteccion():
    assert _argumentos_nmap_desde_formulario(rapido=False, con_so=True) == "-sV -T4 -O --osscan-guess"


@patch("topology_scanner.webapp.socket.socket")
def test_detectar_rango_local_asume_slash_24(mock_socket_cls):
    mock_sock = mock_socket_cls.return_value.__enter__.return_value
    mock_sock.getsockname.return_value = ("192.168.1.42", 54321)

    assert _detectar_rango_local() == "192.168.1.0/24"


@patch("topology_scanner.webapp.socket.socket")
def test_detectar_rango_local_devuelve_none_si_no_hay_red(mock_socket_cls):
    mock_socket_cls.return_value.__enter__.return_value.connect.side_effect = OSError("network unreachable")

    assert _detectar_rango_local() is None


@patch("topology_scanner.webapp.nmap.PortScanner")
def test_construir_comando_nmap_incluye_hosts_puertos_y_argumentos(mock_portscanner_cls):
    mock_portscanner_cls.return_value._nmap_path = "/usr/bin/nmap"

    comando = _construir_comando_nmap("192.168.1.1 192.168.1.2", "22,80", "-sV -T4")

    assert comando == ["/usr/bin/nmap", "-oX", "-", "192.168.1.1", "192.168.1.2", "-p", "22,80", "-sV", "-T4"]


@patch("topology_scanner.webapp.nmap.PortScanner")
def test_construir_comando_nmap_reutiliza_la_ruta_resuelta_por_python_nmap(mock_portscanner_cls):
    """No usa shutil.which("nmap") - reutiliza nmap.PortScanner()._nmap_path,
    la misma resolución de ruta que ya usa descubrir_hosts_vivos (fase 1),
    para no divergir si una encuentra el binario y la otra no."""
    mock_portscanner_cls.return_value._nmap_path = "C:\\Program Files (x86)\\Nmap\\nmap.exe"

    comando = _construir_comando_nmap("192.168.1.1", "22", "-T4")

    assert comando[0] == "C:\\Program Files (x86)\\Nmap\\nmap.exe"


@patch("topology_scanner.webapp.nmap.PortScanner")
def test_construir_comando_nmap_error_claro_si_nmap_no_esta_disponible(mock_portscanner_cls):
    mock_portscanner_cls.side_effect = nmap.PortScannerError("nmap program was not found in path")

    with pytest.raises(ScannerError):
        _construir_comando_nmap("192.168.1.1", "22", "-T4")


@patch("topology_scanner.webapp.subprocess.Popen")
def test_ejecutar_proceso_nmap_rellena_el_contenedor(mock_popen_cls):
    mock_proceso = MagicMock()
    mock_proceso.communicate.return_value = (b"<xml/>", b"")
    mock_popen_cls.return_value = mock_proceso

    contenedor = {"proceso": None, "salida": None}
    _ejecutar_proceso_nmap(["nmap", "-oX", "-"], contenedor)

    assert contenedor["proceso"] is mock_proceso
    assert contenedor["salida"] == b"<xml/>"
    assert contenedor.get("error") is None


@patch("topology_scanner.webapp.subprocess.Popen")
def test_ejecutar_proceso_nmap_guarda_el_error_si_popen_falla(mock_popen_cls):
    """Si no se puede lanzar nmap (ruta inválida, permisos...), el hilo no
    debe morir en silencio - antes de este fix, contenedor["salida"] se
    quedaba en None y _procesar_salida_nmap(None) reventaba más adelante
    con una excepción sin controlar (no era nmap.PortScannerError)."""
    mock_popen_cls.side_effect = OSError("No such file or directory")

    contenedor = {"proceso": None, "salida": None}
    _ejecutar_proceso_nmap(["nmap-que-no-existe"], contenedor)

    assert "No such file or directory" in contenedor["error"]


class _HostInfoFalso(dict):
    def __init__(self, estado="up", hostname=""):
        super().__init__()
        self._estado = estado
        self._hostname = hostname
        self["addresses"] = {"ipv4": "192.168.1.10"}

    def state(self):
        return self._estado

    def hostname(self):
        return self._hostname


@patch("topology_scanner.webapp.nmap.PortScanner")
def test_procesar_salida_nmap_reutiliza_parsear_host(mock_portscanner_cls):
    mock_nm = MagicMock()
    mock_nm.all_hosts.return_value = ["192.168.1.10"]
    mock_nm.__getitem__.return_value = _HostInfoFalso(hostname="server01")
    mock_nm.scaninfo.return_value = {}
    mock_portscanner_cls.return_value = mock_nm

    resultados = _procesar_salida_nmap(b"<xml/>")

    mock_nm.analyse_nmap_xml_scan.assert_called_once_with(nmap_xml_output=b"<xml/>")
    assert resultados["192.168.1.10"]["hostname"] == "server01"


@patch("topology_scanner.webapp.nmap.PortScanner")
def test_procesar_salida_nmap_avisa_si_nmap_reporto_error(mock_portscanner_cls, caplog):
    """El escaneo cancelable de webapp.py no pasa por scanner.escanear_red(),
    así que sin esto se perdía el aviso de errores internos de nmap que sí
    tiene el CLI."""
    mock_nm = MagicMock()
    mock_nm.all_hosts.return_value = []
    mock_nm.scaninfo.return_value = {"error": ["Failed to resolve given hostname/IP"]}
    mock_portscanner_cls.return_value = mock_nm

    with caplog.at_level(logging.WARNING):
        _procesar_salida_nmap(b"<xml/>")

    assert "Failed to resolve given hostname/IP" in caplog.text


@patch("topology_scanner.webapp.exportar_html")
@patch("topology_scanner.webapp.construir_grafo")
def test_finalizar_resultados_sin_hosts_no_construye_grafo(mock_construir_grafo, mock_exportar_html):
    resultado = _finalizar_resultados({}, "192.168.1.0/24", guardar_historial=False)

    assert resultado["resultados"] == {}
    mock_construir_grafo.assert_not_called()
    mock_exportar_html.assert_not_called()


@patch("topology_scanner.webapp.exportar_html")
@patch("topology_scanner.webapp.construir_grafo")
def test_finalizar_resultados_no_llama_al_historial_si_no_se_pide(mock_construir_grafo, mock_exportar_html):
    resultados = {"192.168.1.10": _resultado_fake()}

    with patch("topology_scanner.webapp.registrar_y_comparar") as mock_registrar:
        resultado = _finalizar_resultados(resultados, "192.168.1.0/24", guardar_historial=False)

    mock_registrar.assert_not_called()
    assert resultado["diff"] is None


@patch("topology_scanner.webapp.exportar_html")
@patch("topology_scanner.webapp.construir_grafo")
@patch("topology_scanner.webapp.registrar_y_comparar")
def test_finalizar_resultados_continua_si_falla_el_historial(
    mock_registrar, mock_construir_grafo, mock_exportar_html
):
    """Mismo criterio que cli.py: un fallo guardando el historial no debe
    tirar un escaneo que sí ha funcionado."""
    resultados = {"192.168.1.10": _resultado_fake()}
    mock_registrar.side_effect = HistoryError("no se pudo abrir historial.db")

    resultado = _finalizar_resultados(resultados, "192.168.1.0/24", guardar_historial=True)

    assert resultado["diff"] is None
    mock_exportar_html.assert_called_once()


@patch("topology_scanner.webapp.exportar_html")
@patch("topology_scanner.webapp.construir_grafo")
def test_finalizar_resultados_incluye_el_rango(mock_construir_grafo, mock_exportar_html):
    """La vista de resultados (KPIs) necesita el rango escaneado para el
    KPI "Hosts detectados" ("en 192.168.1.0/24") - antes no viajaba en el
    dict de resultado, solo se usaba internamente para el historial."""
    resultados = {"192.168.1.10": _resultado_fake()}

    resultado = _finalizar_resultados(resultados, "192.168.1.0/24", guardar_historial=False)

    assert resultado["rango"] == "192.168.1.0/24"


@patch("topology_scanner.webapp.exportar_html")
@patch("topology_scanner.webapp.construir_grafo")
def test_finalizar_resultados_borra_el_html_temporal(mock_construir_grafo, mock_exportar_html):
    """Antes de este fix, el .html temporal (NamedTemporaryFile(delete=False))
    nunca se borraba - cada escaneo dejaba basura en el directorio temporal
    del sistema para siempre."""
    resultados = {"192.168.1.10": _resultado_fake()}
    rutas_creadas = []
    ntf_original = tempfile.NamedTemporaryFile

    def _capturar_ruta(*args, **kwargs):
        f = ntf_original(*args, **kwargs)
        rutas_creadas.append(f.name)
        return f

    with patch("topology_scanner.webapp.tempfile.NamedTemporaryFile", side_effect=_capturar_ruta):
        _finalizar_resultados(resultados, "192.168.1.0/24", guardar_historial=False)

    assert rutas_creadas
    assert not os.path.exists(rutas_creadas[-1])


def test_generar_csv_bytes_borra_el_csv_temporal():
    """Mismo problema que el .html: el .csv temporal del botón de descarga
    tampoco se borraba."""
    from topology_scanner.webapp import _generar_csv_bytes

    resultados = {"192.168.1.10": _resultado_fake()}
    rutas_creadas = []
    ntf_original = tempfile.NamedTemporaryFile

    def _capturar_ruta(*args, **kwargs):
        f = ntf_original(*args, **kwargs)
        rutas_creadas.append(f.name)
        return f

    with patch("topology_scanner.webapp.tempfile.NamedTemporaryFile", side_effect=_capturar_ruta):
        contenido = _generar_csv_bytes(resultados)

    assert b"192.168.1.10" in contenido
    assert rutas_creadas
    assert not os.path.exists(rutas_creadas[-1])


# hay_cambios() ya no vive aquí - se movió a history.py (única fuente de
# verdad, la reutilizan export.py y webapp.py) y sus tests están en
# test_history.py.


def test_filas_para_tabla_una_fila_por_host():
    resultados = {
        "192.168.1.10": _resultado_fake(hostname="a"),
        "192.168.1.20": _resultado_fake(hostname="b"),
    }
    filas = _filas_para_tabla(resultados)
    assert len(filas) == 2
    assert [f["IP"] for f in filas] == ["192.168.1.10", "192.168.1.20"]


def test_filas_para_tabla_cuenta_alertas():
    alertas = [{"puerto": 23, "motivo": "Telnet (sin cifrar)"}]
    resultados = {"192.168.1.1": _resultado_fake(alertas=alertas)}
    filas = _filas_para_tabla(resultados)
    assert filas[0]["Alertas"] == 1


def test_generar_css_incluye_el_color_de_acento():
    """El acento se recibe como parámetro (leído de theme.primaryColor en
    tiempo de ejecución) en vez de repetirse a mano en el CSS, para no
    desincronizarse si se cambia .streamlit/config.toml."""
    css = _generar_css("#123456")
    assert "#123456" in css


def test_generar_encabezado_html_incluye_version_y_acento():
    html = _generar_encabezado_html(version="0.3.0", accent="#00D2D3")
    assert "v0.3.0" in html
    assert "#00D2D3" in html


def test_formatear_tiempo_transcurrido_bajo_un_minuto():
    assert _formatear_tiempo_transcurrido(47) == "00:47"


def test_formatear_tiempo_transcurrido_con_minutos():
    assert _formatear_tiempo_transcurrido(125) == "02:05"


def test_generar_progreso_html_incluye_solo_datos_reales():
    """No debe fabricar progreso host a host de la fase 2 (nmap no da
    resultados incrementales - ver docstring de _generar_progreso_html):
    solo cifras que la app conoce de verdad en ese momento."""
    html = _generar_progreso_html(
        rango="192.168.1.0/24", hosts_vivos=12, argumentos_nmap="-sV -T4", tiempo="00:47"
    )
    assert "192.168.1.0/24" in html
    assert "12" in html
    assert "-sV -T4" in html
    assert "00:47" in html


def test_generar_chips_categorias_agrupa_por_categoria():
    resultados = {
        "192.168.1.1": _resultado_fake(categoria="pc"),
        "192.168.1.2": _resultado_fake(categoria="pc"),
        "192.168.1.3": _resultado_fake(categoria="router"),
    }
    html = _generar_chips_categorias_html(resultados)
    assert "pc 2" in html
    assert "router 1" in html


def test_generar_chips_categorias_limita_y_resume_el_resto():
    categorias = ["router", "firewall", "vm", "nas", "printer", "camera", "iot", "mobile", "apple", "pc"]
    resultados = {f"192.168.1.{i}": _resultado_fake(categoria=c) for i, c in enumerate(categorias)}

    html = _generar_chips_categorias_html(resultados, limite=8)

    assert "+2 categorías más" in html


def test_generar_kpis_html_incluye_hosts_y_rango():
    resultados = {"192.168.1.10": _resultado_fake()}
    html = _generar_kpis_html(resultados, rango="192.168.1.0/24", diff=None, accent="#00D2D3")
    assert "192.168.1.0/24" in html
    assert "sin alertas" in html


def test_generar_kpis_html_puertos_sensibles_cuenta_alertas():
    resultados = {
        "192.168.1.10": _resultado_fake(alertas=[{"puerto": 3389, "motivo": "RDP"}]),
    }
    html = _generar_kpis_html(resultados, rango="192.168.1.0/24", diff=None, accent="#00D2D3")
    assert "requieren revisión" in html


def test_generar_kpis_html_primera_vez_no_muestra_cambios_fabricados():
    resultados = {"192.168.1.10": _resultado_fake()}
    diff = {"primera_vez": True, "hosts_nuevos": [], "hosts_caidos": [], "puertos_cambiados": {}}
    html = _generar_kpis_html(resultados, rango="192.168.1.0/24", diff=diff, accent="#00D2D3")
    assert "primer escaneo" in html


def test_generar_tabla_inventario_html_marca_fila_con_alertas():
    resultados = {
        "192.168.1.10": _resultado_fake(
            puertos=[{"puerto": 3389, "servicio": "ms-wbt-server", "producto": ""}],
            alertas=[{"puerto": 3389, "motivo": "RDP"}],
        )
    }
    html = _generar_tabla_inventario_html(resultados)
    assert 'class="sensitive"' in html
    assert '"sens' in html  # el chip del puerto 3389 lleva la clase port-chip.sens


def test_generar_tabla_inventario_html_host_sin_alertas_no_se_marca():
    resultados = {"192.168.1.10": _resultado_fake(puertos=[{"puerto": 80, "servicio": "http", "producto": ""}])}
    html = _generar_tabla_inventario_html(resultados)
    assert 'class="sensitive"' not in html


def test_generar_cambios_html_incluye_host_nuevo_con_su_categoria():
    diff = {"primera_vez": False, "hosts_nuevos": ["192.168.1.31"], "hosts_caidos": [], "puertos_cambiados": {}}
    resultados = {"192.168.1.31": _resultado_fake(hostname="galaxy-s23", categoria="mobile")}

    html = _generar_cambios_html(diff, resultados)

    assert "192.168.1.31" in html
    assert "galaxy-s23" in html
    assert "mobile" in html


def test_generar_cambios_html_incluye_host_caido_sin_inventar_datos():
    """El host caído ya no está en `resultados` (por eso ha caído) - el
    texto no debe fabricar hostname/categoría que no tenemos."""
    diff = {"primera_vez": False, "hosts_nuevos": [], "hosts_caidos": ["192.168.1.40"], "puertos_cambiados": {}}

    html = _generar_cambios_html(diff, {})

    assert "192.168.1.40" in html
    assert "no respondió" in html


def test_generar_cambios_html_puerto_nuevo_sensible_se_marca_como_warn():
    diff = {
        "primera_vez": False, "hosts_nuevos": [], "hosts_caidos": [],
        "puertos_cambiados": {
            "192.168.1.14": {
                "nuevos": [445], "cerrados": [],
                "nuevos_sensibles": [{"puerto": 445, "motivo": "SMB (vector típico de ransomware)"}],
            }
        },
    }
    html = _generar_cambios_html(diff, {})
    assert "chg-item warn" in html
    assert "ransomware" in html


def test_generar_cambios_html_sin_cambios_lo_indica():
    diff = {"primera_vez": False, "hosts_nuevos": [], "hosts_caidos": [], "puertos_cambiados": {}}
    assert "Sin cambios" in _generar_cambios_html(diff, {})


def test_generar_estado_vacio_html_incluye_el_acento():
    html = _generar_estado_vacio_html("#123456")
    assert "#123456" in html
    assert "Listo para escanear" in html


def test_la_app_carga_sin_excepciones():
    """Smoke test: el script se ejecuta sin lanzar excepciones y muestra
    el formulario (en el sidebar, ver punto 2 del roadmap de UI), sin
    necesidad de navegador ni de un escaneo real."""
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file("../src/topology_scanner/webapp.py")
    at.run()

    assert not at.exception
    assert "Network Topology Scanner" in at.title[0].value
    assert len(at.sidebar.text_input) == 1
    assert len(at.sidebar.checkbox) == 3
    assert len(at.sidebar.button) == 3  # Escanear, Parar escaneo, Detectar mi red
    # El estado vacío (sin escaneo ni resultado) vive en el panel principal,
    # no en el sidebar.
    assert "Listo para escanear" in at.main.markdown[-1].value


def test_la_app_avisa_si_se_escanea_sin_rango():
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file("../src/topology_scanner/webapp.py")
    at.run()
    boton_escanear = next(b for b in at.button if b.label == "Escanear")
    boton_escanear.click().run()

    assert not at.exception
    assert any("CIDR" in w.value for w in at.warning)


def test_la_app_parar_escaneo_empieza_deshabilitado():
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file("../src/topology_scanner/webapp.py")
    at.run()

    boton_parar = next(b for b in at.button if b.label == "⏹ Parar escaneo")
    assert boton_parar.disabled is True


def test_la_app_detecta_mi_red_al_pulsar_el_boton():
    """AppTest ejecuta el script de forma aislada (no reutiliza
    sys.modules["topology_scanner.webapp"], ver el comentario sobre imports
    absolutos en webapp.py), así que mockear
    "topology_scanner.webapp._detectar_rango_local" no llega a afectar lo
    que AppTest ejecuta. socket.socket sí es el mismo objeto cacheado en
    sys.modules independientemente de quién lo importe."""
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file("../src/topology_scanner/webapp.py")
    at.run()
    with patch("socket.socket") as mock_socket_cls:
        mock_socket_cls.return_value.__enter__.return_value.getsockname.return_value = ("192.168.1.42", 0)
        boton_detectar = next(b for b in at.button if b.label == "📍 Detectar mi red")
        boton_detectar.click().run()

    assert not at.exception
    assert at.text_input[0].value == "192.168.1.0/24"
