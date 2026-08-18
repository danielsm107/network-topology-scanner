"""
Tests de webapp.py. streamlit es una dependencia opcional (extra "web"),
así que este módulo entero se salta si no está instalado - no debe romper
`pytest tests/ -v` para quien solo instaló el CLI.

La lógica pura (_argumentos_nmap_desde_formulario, _construir_comando_nmap,
_procesar_salida_nmap, _finalizar_resultados, _filas_para_tabla,
_hay_cambios) se testea con pytest normal, mockeando los mismos puntos que
test_cli.py. El renderizado de widgets se comprueba con
streamlit.testing.v1.AppTest, que ejecuta el script sin navegador - pero
sin llegar a lanzar un escaneo real (eso no se prueba aquí, solo a mano
en el navegador, igual que el resto de cambios de UI de este proyecto).
"""

import os
import tempfile
from unittest.mock import MagicMock, patch

import nmap
import pytest

pytest.importorskip("streamlit", reason='pip install "topology-scanner[web]" para probar la interfaz web')

from topology_scanner.webapp import (
    _argumentos_nmap_desde_formulario,
    _construir_comando_nmap,
    _detectar_rango_local,
    _ejecutar_proceso_nmap,
    _filas_para_tabla,
    _finalizar_resultados,
    _hay_cambios,
    _procesar_salida_nmap,
)
from topology_scanner.history import HistoryError
from topology_scanner.scanner import ScannerError


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

    contenedor = {"proceso": None, "salida": None, "terminado": False}
    _ejecutar_proceso_nmap(["nmap", "-oX", "-"], contenedor)

    assert contenedor["proceso"] is mock_proceso
    assert contenedor["salida"] == b"<xml/>"
    assert contenedor["terminado"] is True
    assert contenedor.get("error") is None


@patch("topology_scanner.webapp.subprocess.Popen")
def test_ejecutar_proceso_nmap_guarda_el_error_si_popen_falla(mock_popen_cls):
    """Si no se puede lanzar nmap (ruta inválida, permisos...), el hilo no
    debe morir en silencio - antes de este fix, contenedor["salida"] se
    quedaba en None y _procesar_salida_nmap(None) reventaba más adelante
    con una excepción sin controlar (no era nmap.PortScannerError)."""
    mock_popen_cls.side_effect = OSError("No such file or directory")

    contenedor = {"proceso": None, "salida": None, "terminado": False}
    _ejecutar_proceso_nmap(["nmap-que-no-existe"], contenedor)

    assert contenedor["terminado"] is True
    assert "No such file or directory" in contenedor["error"]
    assert contenedor["terminado"] is True


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
    mock_portscanner_cls.return_value = mock_nm

    resultados = _procesar_salida_nmap(b"<xml/>")

    mock_nm.analyse_nmap_xml_scan.assert_called_once_with(nmap_xml_output=b"<xml/>")
    assert resultados["192.168.1.10"]["hostname"] == "server01"


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


def test_hay_cambios_es_true_si_solo_cambian_puertos():
    """Bug real (TypeError en st.expander): `a or b or c` no devuelve un
    bool, devuelve el primer operando truthy - si solo puertos_cambiados
    tenía contenido, hay_cambios acababa siendo un dict, no True."""
    diff = {
        "primera_vez": False,
        "hosts_nuevos": [],
        "hosts_caidos": [],
        "puertos_cambiados": {"192.168.1.10": {"nuevos": [23], "cerrados": [], "nuevos_sensibles": []}},
    }
    assert _hay_cambios(diff) is True


def test_hay_cambios_es_false_si_no_hay_nada():
    diff = {"primera_vez": False, "hosts_nuevos": [], "hosts_caidos": [], "puertos_cambiados": {}}
    assert _hay_cambios(diff) is False


def test_hay_cambios_es_true_si_hay_hosts_nuevos():
    diff = {"primera_vez": False, "hosts_nuevos": ["192.168.1.20"], "hosts_caidos": [], "puertos_cambiados": {}}
    assert _hay_cambios(diff) is True


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


def test_la_app_carga_sin_excepciones():
    """Smoke test: el script se ejecuta sin lanzar excepciones y muestra
    el formulario, sin necesidad de navegador ni de un escaneo real."""
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file("../src/topology_scanner/webapp.py")
    at.run()

    assert not at.exception
    assert "Network Topology Scanner" in at.title[0].value
    assert len(at.text_input) == 1
    assert len(at.checkbox) == 3
    assert len(at.button) == 3  # Escanear, Parar escaneo, Detectar mi red


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
