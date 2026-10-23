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
from datetime import datetime
from html import escape
from unittest.mock import MagicMock, patch

import nmap
import pytest

pytest.importorskip("streamlit", reason='pip install "topology-scanner[web]" para probar la interfaz web')

from topology_scanner.classifier import ICONOS_POR_CATEGORIA
from topology_scanner.history import HistoryError
from topology_scanner.scanner import ScannerError
from topology_scanner.snmp import VARIABLE_COMMUNITY, CredencialesV3
from topology_scanner.webapp import (
    ALTURA_ICONO_ISO,
    ELEVACION_PLATAFORMA_ISO,
    _argumentos_nmap_desde_formulario,
    _compactar_html,
    _construir_comando_nmap,
    _detectar_rango_local,
    _ejecutar_proceso_nmap,
    _filas_para_tabla,
    _finalizar_resultados,
    _formatear_tiempo_transcurrido,
    _generar_cambios_html,
    _generar_chips_categorias_html,
    _generar_css,
    _generar_estado_vacio_html,
    _generar_historial_html,
    _generar_kpis_html,
    _generar_progreso_html,
    _generar_tabla_inventario_html,
    _generar_topbar_html,
    _generar_topologia_html,
    _pagina_de_resultados,
    _procesar_salida_nmap,
    _proyectar_isometrico,
    _tiempo_relativo,
    _total_paginas,
    _validar_rangos,
    _validar_snmp,
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


@pytest.fixture
def sin_escaneos_reales():
    """Para los tests de AppTest que pulsan "Escanear": cualquier intento de
    usar nmap falla el test en vez de escanear de verdad. Esos tests confían
    en que una validación corte antes de nmap, pero en la fase "roja" de TDD
    (validación aún sin escribir) o con un bug en ella, el test llegaba a
    lanzar un ping scan real contra los rangos del test. AppTest no reutiliza
    el módulo webapp, pero sí `nmap` (cacheado en sys.modules), así que
    parchear nmap.PortScanner le llega igual que el mock de socket.socket."""
    with patch("nmap.PortScanner", side_effect=AssertionError("el test ha intentado un escaneo real")) as mock:
        yield mock
        mock.assert_not_called()


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

    comando = _construir_comando_nmap("192.168.1.1 192.168.1.2", "22,80", "-sV -T4", "/tmp/salida.xml")

    assert comando == [
        "/usr/bin/nmap", "-v", "-oX", "/tmp/salida.xml",
        "192.168.1.1", "192.168.1.2", "-p", "22,80", "-sV", "-T4",
    ]


@patch("topology_scanner.webapp.nmap.PortScanner")
def test_construir_comando_nmap_reutiliza_la_ruta_resuelta_por_python_nmap(mock_portscanner_cls):
    """No usa shutil.which("nmap") - reutiliza nmap.PortScanner()._nmap_path,
    la misma resolución de ruta que ya usa descubrir_hosts_vivos (fase 1),
    para no divergir si una encuentra el binario y la otra no."""
    mock_portscanner_cls.return_value._nmap_path = "C:\\Program Files (x86)\\Nmap\\nmap.exe"

    comando = _construir_comando_nmap("192.168.1.1", "22", "-T4", "/tmp/salida.xml")

    assert comando[0] == "C:\\Program Files (x86)\\Nmap\\nmap.exe"


@patch("topology_scanner.webapp.nmap.PortScanner")
def test_construir_comando_nmap_error_claro_si_nmap_no_esta_disponible(mock_portscanner_cls):
    mock_portscanner_cls.side_effect = nmap.PortScannerError("nmap program was not found in path")

    with pytest.raises(ScannerError):
        _construir_comando_nmap("192.168.1.1", "22", "-T4", "/tmp/salida.xml")


def _mock_popen_con_lineas(lineas):
    """Simula un subprocess.Popen cuyo stdout, iterado línea a línea (el
    patrón que usa _ejecutar_proceso_nmap para leer el progreso de nmap en
    vivo en vez de esperar con .communicate()), produce `lineas`."""
    mock_proceso = MagicMock()
    mock_proceso.stdout = iter(lineas)
    return mock_proceso


@patch("topology_scanner.webapp.subprocess.Popen")
def test_ejecutar_proceso_nmap_rellena_el_contenedor(mock_popen_cls):
    mock_popen_cls.return_value = _mock_popen_con_lineas([])

    contenedor = {"proceso": None, "log": []}
    _ejecutar_proceso_nmap(["nmap", "-v", "-oX", "/tmp/salida.xml"], contenedor)

    assert contenedor["proceso"] is mock_popen_cls.return_value
    assert contenedor.get("error") is None


@patch("topology_scanner.webapp.subprocess.Popen")
def test_ejecutar_proceso_nmap_guarda_el_error_si_popen_falla(mock_popen_cls):
    """Si no se puede lanzar nmap (ruta inválida, permisos...), el hilo no
    debe morir en silencio."""
    mock_popen_cls.side_effect = OSError("No such file or directory")

    contenedor = {"proceso": None, "log": []}
    _ejecutar_proceso_nmap(["nmap-que-no-existe"], contenedor)

    assert "No such file or directory" in contenedor["error"]


@patch("topology_scanner.webapp.subprocess.Popen")
def test_ejecutar_proceso_nmap_registra_hosts_completados_en_el_log(mock_popen_cls):
    """El log en vivo viene de eventos reales que nmap suelta por su
    salida verbose (-v) mientras escanea, no de datos inventados - "Nmap
    scan report for X" es la línea que nmap imprime cuando termina de
    escanear ese host."""
    mock_popen_cls.return_value = _mock_popen_con_lineas([
        "Scanning 192.168.1.10 [1000 ports]\n",
        "Nmap scan report for 192.168.1.10\n",
        "Host is up (0.0012s latency).\n",
        "Nmap scan report for 192.168.1.20\n",
    ])

    contenedor = {"proceso": None, "log": []}
    _ejecutar_proceso_nmap(["nmap"], contenedor)

    assert contenedor["log"] == ["192.168.1.10", "192.168.1.20"]


@patch("topology_scanner.webapp.subprocess.Popen")
def test_ejecutar_proceso_nmap_ignora_lineas_que_no_son_de_host_completado(mock_popen_cls):
    mock_popen_cls.return_value = _mock_popen_con_lineas([
        "Starting Nmap 7.94\n",
        "Host is up (0.0012s latency).\n",
    ])

    contenedor = {"proceso": None, "log": []}
    _ejecutar_proceso_nmap(["nmap"], contenedor)

    assert contenedor["log"] == []


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


def test_finalizar_resultados_sin_hosts():
    resultado = _finalizar_resultados({}, "192.168.1.0/24", guardar_historial=False)

    assert resultado["resultados"] == {}
    assert resultado["diff"] is None


def test_finalizar_resultados_no_llama_al_historial_si_no_se_pide():
    resultados = {"192.168.1.10": _resultado_fake()}

    with patch("topology_scanner.webapp.registrar_y_comparar") as mock_registrar:
        resultado = _finalizar_resultados(resultados, "192.168.1.0/24", guardar_historial=False)

    mock_registrar.assert_not_called()
    assert resultado["diff"] is None


@patch("topology_scanner.webapp.registrar_y_comparar")
def test_finalizar_resultados_continua_si_falla_el_historial(mock_registrar):
    """Mismo criterio que cli.py: un fallo guardando el historial no debe
    tirar un escaneo que sí ha funcionado."""
    resultados = {"192.168.1.10": _resultado_fake()}
    mock_registrar.side_effect = HistoryError("could not open historial.db")

    resultado = _finalizar_resultados(resultados, "192.168.1.0/24", guardar_historial=True)

    assert resultado["diff"] is None
    assert resultado["resultados"] == resultados


def test_finalizar_resultados_incluye_el_rango():
    """La vista de resultados (KPIs) necesita el rango escaneado para el
    KPI "Hosts detectados" ("en 192.168.1.0/24") - antes no viajaba en el
    dict de resultado, solo se usaba internamente para el historial."""
    resultados = {"192.168.1.10": _resultado_fake()}

    resultado = _finalizar_resultados(resultados, "192.168.1.0/24", guardar_historial=False)

    assert resultado["rango"] == "192.168.1.0/24"


def test_finalizar_resultados_no_genera_el_html_de_pyvis():
    """La web dibuja su propio SVG (_generar_topologia_html); antes además
    generaba en cada escaneo el HTML de pyvis del CLI en un archivo temporal,
    lo leía, lo borraba y lo devolvía en resultado["html"] sin que nadie lo
    usara."""
    resultados = {"192.168.1.10": _resultado_fake()}
    rutas_creadas = []
    ntf_original = tempfile.NamedTemporaryFile

    def _capturar_ruta(*args, **kwargs):
        f = ntf_original(*args, **kwargs)
        rutas_creadas.append(f.name)
        return f

    with patch("topology_scanner.webapp.tempfile.NamedTemporaryFile", side_effect=_capturar_ruta):
        resultado = _finalizar_resultados(resultados, "192.168.1.0/24", guardar_historial=False)

    assert rutas_creadas == []
    assert "html" not in resultado


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
    alertas = [{"puerto": 23, "motivo": "Telnet (unencrypted)"}]
    resultados = {"192.168.1.1": _resultado_fake(alertas=alertas)}
    filas = _filas_para_tabla(resultados)
    assert filas[0]["Alerts"] == 1


def test_generar_css_incluye_el_color_de_acento():
    """El acento se recibe como parámetro (leído de theme.primaryColor en
    tiempo de ejecución) en vez de repetirse a mano en el CSS, para no
    desincronizarse si se cambia .streamlit/config.toml."""
    css = _generar_css("#123456")
    assert "#123456" in css


def test_generar_topbar_html_incluye_version_y_acento():
    html = _generar_topbar_html(version="0.3.0", accent="#00D2D3")
    assert "v0.3.0" in html
    assert "#00D2D3" in html
    assert "Network Topology Scanner" in html


def test_formatear_tiempo_transcurrido_bajo_un_minuto():
    assert _formatear_tiempo_transcurrido(47) == "00:47"


def test_formatear_tiempo_transcurrido_con_minutos():
    assert _formatear_tiempo_transcurrido(125) == "02:05"


def test_generar_progreso_html_incluye_solo_datos_reales():
    """Las cifras de fase 1/rango/tiempo no dependen del log en vivo -
    deben seguir apareciendo aunque el log esté vacío (recién arrancado el
    escaneo, ningún host completado todavía)."""
    html = _generar_progreso_html(
        rango="192.168.1.0/24", hosts_vivos=12, argumentos_nmap="-sV -T4", tiempo="00:47", log=[]
    )
    assert "192.168.1.0/24" in html
    assert "12" in html
    assert "-sV -T4" in html
    assert "00:47" in html


def test_generar_progreso_html_muestra_los_hosts_del_log_en_vivo():
    """El log en vivo viene de _ejecutar_proceso_nmap (eventos reales de
    nmap -v), no se fabrica aquí - esta función solo lo pinta."""
    html = _generar_progreso_html(
        rango="192.168.1.0/24", hosts_vivos=12, argumentos_nmap="-sV -T4", tiempo="00:47",
        log=["192.168.1.10", "192.168.1.20"],
    )
    assert "192.168.1.10</span><span class=\"muted mono\">scanned" in html
    assert "192.168.1.20" in html


def test_generar_progreso_html_log_vacio_no_fabrica_hosts():
    """Sin eventos reales todavía, no debe aparecer ninguna línea de host
    "scanned"."""
    html = _generar_progreso_html(
        rango="10.0.0.0/24", hosts_vivos=12, argumentos_nmap="-sV -T4", tiempo="00:47", log=[]
    )
    assert "scanned" not in html


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

    assert "+2 more categories" in html


def test_generar_kpis_html_incluye_hosts_y_rango():
    resultados = {"192.168.1.10": _resultado_fake()}
    html = _generar_kpis_html(resultados, rango="192.168.1.0/24", diff=None, accent="#00D2D3")
    assert "192.168.1.0/24" in html
    assert "no alerts" in html


def test_generar_kpis_html_puertos_sensibles_cuenta_alertas():
    resultados = {
        "192.168.1.10": _resultado_fake(alertas=[{"puerto": 3389, "motivo": "RDP"}]),
    }
    html = _generar_kpis_html(resultados, rango="192.168.1.0/24", diff=None, accent="#00D2D3")
    assert "need review" in html


def test_generar_kpis_html_primera_vez_no_muestra_cambios_fabricados():
    resultados = {"192.168.1.10": _resultado_fake()}
    diff = {"primera_vez": True, "hosts_nuevos": [], "hosts_caidos": [], "puertos_cambiados": {}}
    html = _generar_kpis_html(resultados, rango="192.168.1.0/24", diff=diff, accent="#00D2D3")
    assert "first scan of this range" in html


def test_compactar_html_elimina_lineas_en_blanco():
    original = '<div>\n  <p>a</p>\n\n  <p>b</p>\n</div>'
    assert "\n" not in _compactar_html(original)
    assert "<p>a</p>" in _compactar_html(original)


def test_total_paginas_redondea_hacia_arriba():
    assert _total_paginas(15, por_pagina=10) == 2


def test_total_paginas_exacto_no_anade_una_de_mas():
    assert _total_paginas(20, por_pagina=10) == 2


def test_total_paginas_minimo_una_pagina_aunque_no_haya_hosts():
    assert _total_paginas(0, por_pagina=10) == 1


def test_pagina_de_resultados_primera_pagina_tiene_por_pagina_hosts():
    resultados = {f"192.168.1.{i}": _resultado_fake() for i in range(1, 16)}
    pagina = _pagina_de_resultados(resultados, pagina=1, por_pagina=10)
    assert len(pagina) == 10


def test_pagina_de_resultados_segunda_pagina_tiene_el_resto():
    resultados = {f"192.168.1.{i}": _resultado_fake() for i in range(1, 16)}
    pagina = _pagina_de_resultados(resultados, pagina=2, por_pagina=10)
    assert len(pagina) == 5


def test_pagina_de_resultados_ordena_igual_que_la_tabla_completa():
    """Mismo orden (lexicográfico, no numérico) que ya usa
    _generar_tabla_inventario_html/exportar_csv - paginar no debe cambiar
    qué host sale en qué posición relativa."""
    resultados = {
        "192.168.1.20": _resultado_fake(hostname="segundo"),
        "192.168.1.10": _resultado_fake(hostname="primero"),
        "192.168.1.5": _resultado_fake(hostname="cero"),
    }
    pagina = _pagina_de_resultados(resultados, pagina=1, por_pagina=2)
    assert list(pagina.keys()) == sorted(resultados)[:2]


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


def test_generar_tabla_inventario_html_con_varias_filas_no_deja_lineas_en_blanco():
    """st.markdown trata el HTML como Markdown antes de dejar pasar las
    etiquetas: una línea en blanco entre filas corta el bloque de HTML "en
    crudo" a medias y el resto se muestra como texto/código en vez de
    renderizarse (bug real, reproducido con el historial del sidebar)."""
    resultados = {f"192.168.1.{i}": _resultado_fake(hostname=f"host{i}") for i in range(4)}
    html = _generar_tabla_inventario_html(resultados)
    assert not any(linea.strip() == "" for linea in html.split("\n"))


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
    assert "did not answer the ping scan" in html


def test_generar_cambios_html_puerto_nuevo_sensible_se_marca_como_warn():
    diff = {
        "primera_vez": False, "hosts_nuevos": [], "hosts_caidos": [],
        "puertos_cambiados": {
            "192.168.1.14": {
                "nuevos": [445], "cerrados": [],
                "nuevos_sensibles": [{"puerto": 445, "motivo": "SMB (common ransomware vector)"}],
            }
        },
    }
    html = _generar_cambios_html(diff, {})
    assert "chg-item warn" in html
    assert "ransomware" in html


def test_generar_cambios_html_sin_cambios_lo_indica():
    diff = {"primera_vez": False, "hosts_nuevos": [], "hosts_caidos": [], "puertos_cambiados": {}}
    assert "No changes" in _generar_cambios_html(diff, {})


def test_generar_cambios_html_con_varios_items_no_deja_lineas_en_blanco():
    diff = {
        "primera_vez": False,
        "hosts_nuevos": ["192.168.1.31", "192.168.1.32"],
        "hosts_caidos": ["192.168.1.40"],
        "puertos_cambiados": {},
    }
    html = _generar_cambios_html(diff, {})
    assert not any(linea.strip() == "" for linea in html.split("\n"))


def test_generar_historial_html_incluye_una_fila_por_escaneo():
    escaneos = [
        {"rango": "192.168.1.0/24", "fecha": "2026-08-21T09:00:00", "total_hosts": 12, "alertas": 2},
        {"rango": "10.0.0.0/24", "fecha": "2026-08-21T08:00:00", "total_hosts": 7, "alertas": 0},
    ]
    html = _generar_historial_html(escaneos)
    assert html.count("history-row") >= 2
    assert "192.168.1.0/24" in html
    assert "10.0.0.0/24" in html


def test_generar_historial_html_muestra_alertas_si_las_hay():
    escaneos = [{"rango": "192.168.1.0/24", "fecha": "2026-08-21T09:00:00", "total_hosts": 12, "alertas": 2}]
    html = _generar_historial_html(escaneos)
    assert "#ff5c5c" in html
    assert "2⚠" in html


def test_generar_historial_html_sin_alertas_usa_verde_y_no_fabrica_el_simbolo():
    escaneos = [{"rango": "192.168.1.0/24", "fecha": "2026-08-21T09:00:00", "total_hosts": 7, "alertas": 0}]
    html = _generar_historial_html(escaneos)
    assert "#2ecc71" in html
    assert "⚠" not in html


def test_generar_historial_html_con_varios_escaneos_no_deja_lineas_en_blanco():
    """Bug real reproducido en el sidebar: con varios escaneos guardados,
    las líneas en blanco entre <div class="history-row"> cortaban el
    bloque de HTML a medias y se veía el código en vez del historial."""
    escaneos = [
        {"rango": "10.1.0.0/24", "fecha": "2026-08-21T09:00:00", "total_hosts": 47, "alertas": 13},
        {"rango": "10.1.0.0/24", "fecha": "2026-08-21T08:59:00", "total_hosts": 47, "alertas": 13},
        {"rango": "10.1.0.0/24", "fecha": "2026-08-21T08:46:00", "total_hosts": 47, "alertas": 13},
        {"rango": "10.1.0.0/24", "fecha": "2026-08-21T08:43:00", "total_hosts": 47, "alertas": 13},
    ]
    html = _generar_historial_html(escaneos)
    assert not any(linea.strip() == "" for linea in html.split("\n"))


def test_generar_topologia_html_un_nodo_por_host():
    resultados = {
        "192.168.1.10": _resultado_fake(hostname="pc1", categoria="pc"),
        "192.168.1.20": _resultado_fake(hostname="pc2", categoria="router"),
    }
    html = _generar_topologia_html(resultados, rango="192.168.1.0/24", accent="#00D2D3")
    # count() sobre la clase CSS incluye también sus propias reglas de
    # estilo (.topo-node-wrap {...}) - se cuenta el atributo class="" real,
    # que solo aparece una vez por nodo del grafo.
    assert html.count('class="topo-node-wrap"') == 2
    assert "pc1" in html
    assert "pc2" in html


def test_generar_topologia_html_marca_alerta_en_hosts_con_puertos_sensibles():
    resultados = {
        "192.168.1.10": _resultado_fake(alertas=[{"puerto": 3389, "motivo": "RDP (brute force)"}]),
    }
    html = _generar_topologia_html(resultados, rango="192.168.1.0/24", accent="#00D2D3")
    assert '<div class="topo-alert-ring">' in html
    assert "3389" in html
    assert "RDP" in html


def test_generar_topologia_html_host_sin_alertas_no_lleva_anillo():
    """La regla CSS .topo-alert-ring siempre está en la hoja de estilos -
    lo que no debe aparecer es el <div> del anillo en sí."""
    resultados = {"192.168.1.10": _resultado_fake(alertas=[])}
    html = _generar_topologia_html(resultados, rango="192.168.1.0/24", accent="#00D2D3")
    assert '<div class="topo-alert-ring">' not in html


def test_generar_topologia_html_incluye_leyenda_de_todas_las_categorias():
    resultados = {"192.168.1.10": _resultado_fake(categoria="nas")}
    html = _generar_topologia_html(resultados, rango="192.168.1.0/24", accent="#00D2D3")
    for categoria in ["router", "firewall", "vm", "nas", "printer", "camera", "iot", "mobile", "apple", "pc"]:
        assert ICONOS_POR_CATEGORIA[categoria]["nombre"] in html


def test_generar_topologia_html_el_hub_muestra_el_sufijo_del_rango():
    resultados = {"192.168.1.10": _resultado_fake()}
    html = _generar_topologia_html(resultados, rango="10.0.0.0/16", accent="#00D2D3")
    assert '<div class="topo-hub-label mono">/16</div>' in html


def test_generar_topologia_html_un_solo_host_no_revienta():
    html = _generar_topologia_html({"192.168.1.10": _resultado_fake()}, rango="192.168.1.0/24", accent="#00D2D3")
    assert '<div class="topo-hub"' in html


def test_generar_topologia_html_es_un_documento_autocontenido_con_pan_zoom():
    """Pensado para st.components.v1.html (no st.markdown): necesita su
    propio <head> (Font Awesome/fuentes no se heredan de la página) y un
    <script> real, que st.markdown ignora - imprescindible para el
    pan/zoom que soluciona el amontonado en redes con muchos hosts."""
    html = _generar_topologia_html({"192.168.1.10": _resultado_fake()}, rango="192.168.1.0/24", accent="#00D2D3")
    assert html.startswith("<!doctype html>")
    assert "<script>" in html
    assert "topo-viewport" in html and "topo-canvas" in html
    assert "font-awesome" in html


def test_generar_estado_vacio_html_incluye_el_acento():
    html = _generar_estado_vacio_html("#123456")
    assert "#123456" in html
    assert "Ready to scan" in html


def test_la_app_carga_sin_excepciones():
    """Smoke test: el script se ejecuta sin lanzar excepciones y muestra
    el formulario (en el sidebar, ver punto 2 del roadmap de UI), sin
    necesidad de navegador ni de un escaneo real."""
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file("../src/topology_scanner/webapp.py")
    at.run()

    assert not at.exception
    assert any("Network Topology Scanner" in md.value for md in at.main.markdown)
    assert len(at.sidebar.text_input) == 1
    assert len(at.sidebar.toggle) == 4  # rápido, SO, historial, SNMP
    assert len(at.sidebar.button) == 3  # Escanear, Parar escaneo, Detectar mi red
    # El estado vacío (sin escaneo ni resultado) vive en el panel principal,
    # no en el sidebar.
    assert "Ready to scan" in at.main.markdown[-1].value


def test_la_app_avisa_si_se_escanea_sin_rango(sin_escaneos_reales):
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file("../src/topology_scanner/webapp.py")
    at.run()
    boton_escanear = next(b for b in at.button if b.label == "▶ Scan")
    boton_escanear.click().run()

    assert not at.exception
    assert any("CIDR" in w.value for w in at.warning)


def test_la_app_parar_escaneo_empieza_deshabilitado():
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file("../src/topology_scanner/webapp.py")
    at.run()

    boton_parar = next(b for b in at.button if b.label == "⏹ Stop scan")
    assert boton_parar.disabled is True


def test_la_app_detecta_mi_red_al_pulsar_el_boton():
    """AppTest ejecuta el script de forma aislada (no reutiliza
    sys.modules["topology_scanner.webapp"], ver el comentario sobre imports
    absolutos en webapp.py), así que mockear
    "topology_scanner.webapp._detectar_rango_local" no llega a afectar lo
    que AppTest ejecuta. socket.socket sí es el mismo objeto cacheado en
    sys.modules independientemente de quién lo importe.

    Solo se falsea el socket UDP (SOCK_DGRAM) del truco de detección: el
    resto se delega en el socket real, porque asyncio (Python 3.13+) crea
    sockets TCP internos durante la pasada de AppTest y con un mock global
    revienta en socketpair()."""
    import socket

    from streamlit.testing.v1 import AppTest

    socket_real = socket.socket
    socket_udp_falso = MagicMock()
    socket_udp_falso.__enter__.return_value.getsockname.return_value = ("192.168.1.42", 0)

    def socket_selectivo(family=socket.AF_INET, type=socket.SOCK_STREAM, *args, **kwargs):
        if type == socket.SOCK_DGRAM:
            return socket_udp_falso
        return socket_real(family, type, *args, **kwargs)

    at = AppTest.from_file("../src/topology_scanner/webapp.py")
    at.run()
    with patch("socket.socket", side_effect=socket_selectivo):
        boton_detectar = next(b for b in at.button if b.label == "Detect my network")
        boton_detectar.click().run()

    assert not at.exception
    assert at.text_input[0].value == "192.168.1.0/24"


# === Topología SNMP en la web ===============================================

def _topologia_fake():
    """Formato de snmp.inferir_topologia (escrito a mano, como en test_graph)."""
    def equipo(nombre, consultado=False, upstream=False):
        return {"nombre": nombre, "plataforma": "MikroTik", "version": "6.49", "mac": None,
                "consultado": consultado, "upstream": upstream}
    return {
        "equipos": {"192.0.2.1": equipo("Router-Casa", consultado=True), "192.0.2.254": equipo("AP-Interior")},
        "enlaces": [{"padre": "192.0.2.1", "hijo": "192.0.2.254", "interfaz_padre": "ether2", "interfaz_hijo": None}],
        "redes": {},
        "ubicaciones": {
            "02:00:00:00:00:10": {"ip": "192.0.2.10", "padre": "192.0.2.254", "interfaz": None},
            "02:00:00:00:00:11": {"ip": "192.0.2.11", "padre": "192.0.2.1", "interfaz": "wlan1"},
            "02:00:00:00:00:12": {"ip": "192.0.2.12", "padre": "192.0.2.1", "interfaz": "wlan1"},
            "02:00:00:00:00:99": {"ip": None, "padre": "192.0.2.1", "interfaz": "ether4"},
        },
    }


def _resultados_fake_arbol():
    return {ip: _resultado_fake(hostname="") for ip in ("192.0.2.10", "192.0.2.11", "192.0.2.12")}


def test_validar_snmp_desactivado_no_hace_nada():
    assert _validar_snmp(False, "", "") == (None, None)


def test_validar_snmp_ips_y_community_correctas(monkeypatch):
    monkeypatch.delenv(VARIABLE_COMMUNITY, raising=False)

    assert _validar_snmp(True, "192.0.2.1, 192.0.2.2", "secreta") == (
        {"ips": ["192.0.2.1", "192.0.2.2"], "credenciales": "secreta"}, None,
    )


def test_validar_snmp_ip_no_valida_es_un_error():
    configuracion, error = _validar_snmp(True, "192.0.2.1,router-casa", "secreta")

    assert configuracion is None
    assert "router-casa" in error


def test_validar_snmp_sin_ips_es_un_error():
    assert _validar_snmp(True, " , ", "secreta")[1] is not None


def test_validar_snmp_sin_community_usa_la_variable_de_entorno(monkeypatch):
    monkeypatch.setenv(VARIABLE_COMMUNITY, "de-entorno")

    configuracion, error = _validar_snmp(True, "192.0.2.1", "")

    assert error is None
    assert configuracion["credenciales"] == "de-entorno"


def test_validar_snmp_sin_community_ni_variable_es_un_error(monkeypatch):
    monkeypatch.delenv(VARIABLE_COMMUNITY, raising=False)

    configuracion, error = _validar_snmp(True, "192.0.2.1", "")

    assert configuracion is None
    assert VARIABLE_COMMUNITY in error


@patch("topology_scanner.webapp.obtener_topologia")
def test_finalizar_resultados_con_snmp_guarda_topologia_y_avisos(
    mock_obtener,
):
    mock_obtener.return_value = (_topologia_fake(), ["192.0.2.2 is not responding over SNMP"])
    resultados = {"192.0.2.10": _resultado_fake()}

    resultado = _finalizar_resultados(resultados, "192.0.2.0/24", guardar_historial=False,
                                      snmp={"ips": ["192.0.2.1", "192.0.2.2"], "credenciales": "secreta"})

    mock_obtener.assert_called_once_with(["192.0.2.1", "192.0.2.2"], "secreta")
    assert resultado["topologia"] == _topologia_fake()
    assert resultado["avisos_snmp"] == ["192.0.2.2 is not responding over SNMP"]
    assert "secreta" not in str(resultado)   # la community no se queda en session_state


@patch("topology_scanner.webapp.obtener_topologia")
def test_finalizar_resultados_sin_snmp_no_consulta_nada(mock_obtener):
    resultado = _finalizar_resultados({"192.0.2.10": _resultado_fake()}, "192.0.2.0/24", guardar_historial=False)

    mock_obtener.assert_not_called()
    assert resultado["topologia"] is None
    assert resultado["avisos_snmp"] == []


def test_generar_topologia_html_con_topologia_dibuja_el_arbol():
    html = _generar_topologia_html(_resultados_fake_arbol(), rango="192.0.2.0/24", accent="#00D2D3",
                                   topologia=_topologia_fake())

    # 2 equipos + 3 hosts de nmap + 1 visto solo por SNMP; sin nodo de red
    assert html.count('class="topo-node-wrap"') == 6
    assert '<div class="topo-hub"' not in html
    assert "Router-Casa" in html and "AP-Interior" in html
    assert html.count("<path ") == 5          # una arista por nodo que no es raíz
    assert html.count(">wlan1</text>") == 1   # una etiqueta por padre+puerto
    assert ">ether2</text>" in html
    assert "seen only over SNMP" in html


def test_generar_topologia_html_con_topologia_los_equipos_se_distinguen():
    html = _generar_topologia_html(_resultados_fake_arbol(), rango="192.0.2.0/24", accent="#00D2D3",
                                   topologia=_topologia_fake())

    assert html.count('class="topo-node equipo"') == 2


def test_generar_topologia_html_escapa_los_nombres():
    """La identidad SNMP la define cada equipo y el hostname sale del DNS
    inverso: no deben poder inyectar HTML en la página."""
    topologia = _topologia_fake()
    topologia["equipos"]["192.0.2.254"]["nombre"] = "<img src=x onerror=alert(1)>"
    resultados = _resultados_fake_arbol()
    resultados["192.0.2.10"]["hostname"] = "<script>x</script>"

    html = _generar_topologia_html(resultados, rango="192.0.2.0/24", accent="#00D2D3", topologia=topologia)

    assert "<img src=x" not in html
    assert "<script>x</script>" not in html
    assert "&lt;img src=x" in html


# --- Vista isométrica (estilo FossFLOW) ---------------------------------------

def test_proyectar_isometrico_gira_el_suelo_45_grados_y_lo_aplasta_a_la_mitad():
    assert _proyectar_isometrico(0, 0) == (0, 0)
    x, y = _proyectar_isometrico(100, 0)
    assert x == pytest.approx(86.6, abs=0.1) and y == pytest.approx(50)
    x, y = _proyectar_isometrico(0, 100)
    assert x == pytest.approx(-86.6, abs=0.1) and y == pytest.approx(50)


def test_generar_topologia_isometrica_una_baldosa_y_un_nodo_por_host():
    resultados = {
        "192.168.1.10": _resultado_fake(hostname="pc1", categoria="pc"),
        "192.168.1.20": _resultado_fake(hostname="pc2", categoria="nas"),
    }
    html = _generar_topologia_html(resultados, rango="192.168.1.0/24", accent="#00D2D3", isometrica=True)

    assert html.count('class="topo-node-wrap"') == 2
    assert html.count('class="topo-tile"') == 3            # 2 hosts + el hub del rango
    assert html.count('class="topo-node iso"') == 2
    assert '<div class="topo-hub iso"' in html


def test_generar_topologia_isometrica_las_baldosas_son_rombos():
    """Cuadrado del suelo proyectado: 4 vértices, dos a la misma altura
    (izquierda/derecha) y los otros dos en la vertical del centro."""
    html = _generar_topologia_html({"192.168.1.10": _resultado_fake()}, rango="192.168.1.0/24",
                                   accent="#00D2D3", isometrica=True)
    puntos = html.split('class="topo-tile" points="')[1].split('"')[0].split()
    arriba, derecha, abajo, izquierda = [tuple(map(float, p.split(","))) for p in puntos]
    assert arriba[0] == pytest.approx(abajo[0])
    assert derecha[1] == pytest.approx(izquierda[1])
    assert arriba[1] < derecha[1] < abajo[1]


def test_generar_topologia_isometrica_dibuja_primero_lo_del_fondo():
    """Orden del pintor: lo que queda más al fondo (x + y del suelo menor)
    va antes en el documento, para que lo de delante lo tape y no al revés."""
    resultados = {f"192.168.1.{i}": _resultado_fake(hostname=f"h{i}") for i in range(1, 7)}
    html = _generar_topologia_html(resultados, rango="192.168.1.0/24", accent="#00D2D3", isometrica=True)

    tops = [float(trozo.split("px")[0]) for trozo in html.split('class="topo-node-wrap" style="')[1:]
            for trozo in [trozo.split("top:")[1]]]
    assert tops == sorted(tops)


def test_generar_topologia_isometrica_marca_las_alertas():
    resultados = {"192.168.1.10": _resultado_fake(alertas=[{"puerto": 3389, "motivo": "RDP (brute force)"}])}
    html = _generar_topologia_html(resultados, rango="192.168.1.0/24", accent="#00D2D3", isometrica=True)

    baldosas = [trozo.split("/>")[0] for trozo in html.split('class="topo-tile"')[1:]]
    assert '<div class="topo-alert-ring">' in html
    assert sum('stroke="#ff5c5c"' in baldosa for baldosa in baldosas) == 1


def test_generar_topologia_isometrica_con_topologia_dibuja_el_arbol():
    html = _generar_topologia_html(_resultados_fake_arbol(), rango="192.0.2.0/24", accent="#00D2D3",
                                   topologia=_topologia_fake(), isometrica=True)

    assert html.count('class="topo-node-wrap"') == 6
    assert html.count('class="topo-node iso equipo"') == 2
    assert html.count('class="topo-iso-edge"') == 5       # una arista por nodo que no es raíz
    assert html.count(">wlan1</text>") == 1
    assert "seen only over SNMP" in html


def test_generar_topologia_isometrica_las_aristas_van_en_angulo_recto_por_el_suelo():
    """Como en FossFLOW: cada cable baja, cruza y vuelve a bajar siguiendo
    los ejes de la cuadrícula (4 puntos), no en diagonal (2 puntos)."""
    html = _generar_topologia_html(_resultados_fake_arbol(), rango="192.0.2.0/24", accent="#00D2D3",
                                   topologia=_topologia_fake(), isometrica=True)

    for trozo in html.split('class="topo-iso-edge" points="')[1:]:
        assert len(trozo.split('"')[0].split()) == 4


def test_generar_topologia_isometrica_una_plataforma_por_rango_sin_snmp():
    resultados = {f"192.168.1.{i}": _resultado_fake() for i in range(1, 4)}
    html = _generar_topologia_html(resultados, rango="192.168.1.0/24", accent="#00D2D3", isometrica=True)

    assert html.count('class="topo-platform"') == 1
    assert '<text class="topo-platform-label"' in html
    assert ">192.168.1.0/24</text>" in html


def test_generar_topologia_isometrica_una_plataforma_por_equipo_con_hosts_colgando():
    """Router-Casa tiene 3 hosts colgando (y el AP, que no va a la
    plataforma porque tiene sus propios hijos); AP-Interior, uno."""
    html = _generar_topologia_html(_resultados_fake_arbol(), rango="192.0.2.0/24", accent="#00D2D3",
                                   topologia=_topologia_fake(), isometrica=True)

    assert html.count('class="topo-platform"') == 2
    assert ">Router-Casa</text>" in html and ">AP-Interior</text>" in html


def test_generar_topologia_isometrica_los_cables_suben_a_la_plataforma():
    """Cada cable hasta un host de una plataforma va por el suelo hasta el
    borde y sigue por encima: la parte de arriba es otro trazo, que se
    pinta después de la plataforma para que no quede tapado."""
    html = _generar_topologia_html(_resultados_fake_arbol(), rango="192.0.2.0/24", accent="#00D2D3",
                                   topologia=_topologia_fake(), isometrica=True)

    assert html.count('class="topo-iso-edge-top"') == 4    # los 4 hosts; el AP no está en plataforma
    assert html.index('class="topo-platform"') < html.index('class="topo-iso-edge-top"')
    assert html.index('class="topo-iso-edge"') < html.index('class="topo-platform"')


def _centro(html, clase):
    """Centro (x, y) del primer polígono con esa clase."""
    puntos = [tuple(map(float, p.split(","))) for p in html.split(f'class="{clase}" points="')[1].split('"')[0].split()]
    return sum(x for x, _ in puntos) / len(puntos), sum(y for _, y in puntos) / len(puntos)


def test_generar_topologia_isometrica_el_host_va_encima_de_su_plataforma():
    """Con un solo host, su baldosa cae en el centro de la cara de arriba
    de la plataforma (no en el suelo, ELEVACION_PLATAFORMA_ISO px más abajo),
    y su icono sigue a la baldosa."""
    html = _generar_topologia_html({"192.168.1.10": _resultado_fake()}, rango="192.168.1.0/24",
                                   accent="#00D2D3", isometrica=True)
    # La baldosa del hub va primero (orden del pintor): la del host es la segunda
    baldosa_host = html.split('class="topo-tile"', 2)[2]
    host_x, host_y = _centro('class="topo-tile"' + baldosa_host, "topo-tile")
    plataforma_x, plataforma_y = _centro(html, "topo-platform")
    host_top = float(html.split('class="topo-node-wrap" style="')[1].split("top:")[1].split("px")[0])

    assert (host_x, host_y) == (pytest.approx(plataforma_x, abs=0.1), pytest.approx(plataforma_y, abs=0.1))
    assert host_top == pytest.approx(host_y - ALTURA_ICONO_ISO, abs=0.1)
    assert ELEVACION_PLATAFORMA_ISO > 0


def test_generar_topologia_isometrica_escapa_los_nombres():
    topologia = _topologia_fake()
    topologia["equipos"]["192.0.2.254"]["nombre"] = "<img src=x onerror=alert(1)>"
    resultados = _resultados_fake_arbol()
    resultados["192.0.2.10"]["hostname"] = "<script>x</script>"

    html = _generar_topologia_html(resultados, rango="192.0.2.0/24", accent="#00D2D3",
                                   topologia=topologia, isometrica=True)

    assert "<img src=x" not in html
    assert "<script>x</script>" not in html


def test_generar_topologia_isometrica_es_un_documento_autocontenido_con_pan_zoom():
    html = _generar_topologia_html({"192.168.1.10": _resultado_fake()}, rango="192.168.1.0/24",
                                   accent="#00D2D3", isometrica=True)
    assert html.startswith("<!doctype html>")
    assert "topo-viewport" in html and "topo-canvas" in html
    assert "font-awesome" in html


def test_la_app_muestra_los_campos_snmp_al_activar_el_interruptor():
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file("../src/topology_scanner/webapp.py")
    at.run()
    interruptor = next(t for t in at.sidebar.toggle if "SNMP" in t.label)
    interruptor.set_value(True).run()

    assert not at.exception
    assert len(at.sidebar.text_input) == 3   # rango + IPs SNMP + community


def test_la_app_avisa_de_una_ip_snmp_no_valida_antes_de_escanear(sin_escaneos_reales):
    """La validación de SNMP va antes que la del rango: si falla, no se
    llega a lanzar nmap (aquí el rango está vacío, así que en ningún caso
    se escanearía nada de verdad)."""
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file("../src/topology_scanner/webapp.py")
    at.run()
    next(t for t in at.sidebar.toggle if "SNMP" in t.label).set_value(True).run()
    next(t for t in at.sidebar.text_input if "Routers" in t.label).set_value("router-casa").run()
    next(b for b in at.button if b.label == "▶ Scan").click().run()

    assert not at.exception
    assert any("router-casa" in w.value for w in at.warning)


# === Escapado de HTML en el panel ===========================================
#
# Todo texto que viene de fuera se escapa antes de meterlo en HTML: el
# hostname sale del DNS inverso (cualquiera con un PTR en la red lo
# controla), el rango lo escribe el usuario y se guarda en el historial, y
# el log en vivo copia lo que nmap imprime tras "Nmap scan report for".

_HTML_MALICIOSO = "<img src=x onerror=alert(1)>"
_HTML_MALICIOSO_SIN_ESPACIOS = "<img/src=x/onerror=alert(1)>"   # lo que cabe en el \S+ del log


def _assert_escapado(html: str, valor: str):
    assert valor not in html
    assert escape(valor) in html


def test_tabla_inventario_escapa_hostname_y_so():
    datos = _resultado_fake(hostname=_HTML_MALICIOSO)
    datos["so"] = "<b>Linux</b>"

    html = _generar_tabla_inventario_html({"192.168.1.10": datos})

    _assert_escapado(html, _HTML_MALICIOSO)
    _assert_escapado(html, "<b>Linux</b>")


def test_cambios_escapa_el_hostname_de_un_host_nuevo():
    diff = {"primera_vez": False, "hosts_nuevos": ["192.168.1.10"], "hosts_caidos": [],
            "puertos_cambiados": {}}
    resultados = {"192.168.1.10": _resultado_fake(hostname=_HTML_MALICIOSO)}

    _assert_escapado(_generar_cambios_html(diff, resultados), _HTML_MALICIOSO)


def test_kpis_escapa_el_rango():
    html = _generar_kpis_html({"192.168.1.10": _resultado_fake()}, _HTML_MALICIOSO, None, "#00D2D3")

    _assert_escapado(html, _HTML_MALICIOSO)


def test_historial_escapa_el_rango_guardado():
    escaneos = [{"rango": _HTML_MALICIOSO, "fecha": datetime.now().isoformat(), "total_hosts": 1, "alertas": 0}]

    _assert_escapado(_generar_historial_html(escaneos), _HTML_MALICIOSO)


def test_progreso_escapa_el_rango_y_las_lineas_del_log():
    html = _generar_progreso_html(rango=_HTML_MALICIOSO, hosts_vivos=1, argumentos_nmap="-T4",
                                  tiempo="00:05", log=[_HTML_MALICIOSO_SIN_ESPACIOS])

    _assert_escapado(html, _HTML_MALICIOSO)
    _assert_escapado(html, _HTML_MALICIOSO_SIN_ESPACIOS)


# === Varios rangos en la web ================================================

@patch("topology_scanner.webapp.registrar_y_comparar")
def test_finalizar_resultados_con_varios_rangos_guarda_el_historial_por_rango(mock_registrar):
    lan_a = {"192.168.50.10": _resultado_fake()}
    lan_b = {"10.0.10.10": _resultado_fake(hostname="proxmox")}
    mock_registrar.side_effect = [
        {"primera_vez": False, "hosts_nuevos": ["192.168.50.10"], "hosts_caidos": [], "puertos_cambiados": {}},
        {"primera_vez": True, "hosts_nuevos": [], "hosts_caidos": [], "puertos_cambiados": {}},
    ]

    resultado = _finalizar_resultados({**lan_a, **lan_b}, ["192.168.50.0/24", "10.0.10.0/24"],
                                      guardar_historial=True)

    assert [c.args[:2] for c in mock_registrar.call_args_list] == [
        (lan_a, "192.168.50.0/24"), (lan_b, "10.0.10.0/24"),
    ]
    assert resultado["diff"]["hosts_nuevos"] == ["192.168.50.10"]   # diffs combinados
    assert resultado["diff"]["primera_vez"] is False
    assert resultado["rangos"] == ["192.168.50.0/24", "10.0.10.0/24"]
    assert resultado["rango"] == "192.168.50.0/24 10.0.10.0/24"


def test_finalizar_resultados_con_un_rango_en_texto_sigue_igual():
    resultado = _finalizar_resultados({"192.168.1.10": _resultado_fake()}, "192.168.1.0/24", guardar_historial=False)

    assert resultado["rango"] == "192.168.1.0/24"
    assert resultado["rangos"] == ["192.168.1.0/24"]


def test_generar_topologia_html_con_varios_rangos_dibuja_un_centro_por_rango():
    """Con dos /24 el sufijo "/24" de cada centro no los distinguiría: en
    este modo el centro lleva el rango completo."""
    resultados = {"192.168.50.10": _resultado_fake(), "10.0.10.10": _resultado_fake()}

    html = _generar_topologia_html(resultados, rango=["192.168.50.0/24", "10.0.10.0/24"], accent="#00D2D3")

    assert html.count('<div class="topo-hub"') == 2
    assert ">192.168.50.0/24</div>" in html
    assert ">10.0.10.0/24</div>" in html
    assert html.count("<path ") == 2


def test_la_app_avisa_de_varios_rangos_no_validos_antes_de_escanear(sin_escaneos_reales):
    """Con varios rangos cada uno tiene que ser IP o CIDR. El aviso sale sin
    llegar a lanzar nmap (el segundo rango no es válido, así que en ningún
    caso se escanearía nada de verdad)."""
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file("../src/topology_scanner/webapp.py")
    at.run()
    at.sidebar.text_input[0].set_value("10.0.10.0/24 192.168.1.1-50").run()
    next(b for b in at.button if b.label == "▶ Scan").click().run()

    assert not at.exception
    assert any("192.168.1.1-50" in w.value for w in at.warning)


# === SNMPv3 en la web =======================================================

@pytest.fixture
def sin_snmp_en_entorno(monkeypatch):
    for variable in ("TOPOLOGY_SNMP_COMMUNITY", "TOPOLOGY_SNMP_USER", "TOPOLOGY_SNMP_AUTH_KEY",
                     "TOPOLOGY_SNMP_PRIV_KEY", "TOPOLOGY_SNMP_AUTH_PROTO", "TOPOLOGY_SNMP_PRIV_PROTO"):
        monkeypatch.delenv(variable, raising=False)


def test_validar_snmp_v3_con_los_campos_del_formulario(sin_snmp_en_entorno):
    configuracion, error = _validar_snmp(True, "192.0.2.1", "", version="v3", usuario="lector",
                                         clave_auth="clave-auth", clave_priv="clave-priv",
                                         protocolo_auth="SHA256", protocolo_priv="AES256")

    assert error is None
    assert configuracion["credenciales"] == CredencialesV3("lector", "clave-auth", "clave-priv", "SHA256", "AES256")


def test_validar_snmp_v3_mal_configurado_es_un_error(sin_snmp_en_entorno):
    configuracion, error = _validar_snmp(True, "192.0.2.1", "", version="v3", usuario="lector", clave_auth="corta")

    assert configuracion is None
    assert "at least 8 characters" in error


def test_validar_snmp_v3_sin_usuario_usa_el_del_entorno(sin_snmp_en_entorno, monkeypatch):
    monkeypatch.setenv("TOPOLOGY_SNMP_USER", "lector")
    monkeypatch.setenv("TOPOLOGY_SNMP_AUTH_KEY", "clave-auth")

    configuracion, error = _validar_snmp(True, "192.0.2.1", "", version="v3")

    assert error is None
    assert configuracion["credenciales"] == CredencialesV3("lector", "clave-auth")


def test_validar_snmp_v3_sin_usuario_ni_en_el_entorno_es_un_error(sin_snmp_en_entorno, monkeypatch):
    """Elegir v3 y tener solo la community en el entorno no debe acabar
    consultando por v2c sin avisar."""
    monkeypatch.setenv("TOPOLOGY_SNMP_COMMUNITY", "de-entorno")

    configuracion, error = _validar_snmp(True, "192.0.2.1", "", version="v3")

    assert configuracion is None
    assert "TOPOLOGY_SNMP_USER" in error


def test_validar_snmp_v2c_no_usa_un_usuario_v3_del_entorno(sin_snmp_en_entorno, monkeypatch):
    """Y al revés: con v2c elegido, el usuario v3 del entorno no cuenta."""
    monkeypatch.setenv("TOPOLOGY_SNMP_USER", "lector")
    monkeypatch.setenv("TOPOLOGY_SNMP_AUTH_KEY", "clave-auth")

    assert _validar_snmp(True, "192.0.2.1", "")[0] is None


def test_la_app_muestra_los_campos_de_v3_al_elegirlo():
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file("../src/topology_scanner/webapp.py")
    at.run()
    next(t for t in at.sidebar.toggle if "SNMP" in t.label).set_value(True).run()
    at.sidebar.radio[0].set_value("v3").run()

    assert not at.exception
    etiquetas = [t.label for t in at.sidebar.text_input]
    assert any("SNMPv3 user" in e for e in etiquetas)
    assert sum("key" in e for e in etiquetas) == 2
    assert not any("Community" in e for e in etiquetas)
    assert [s.value for s in at.sidebar.selectbox] == ["SHA", "AES"]


# === Interfaz en inglés =====================================================

def test_tiempo_relativo_en_ingles():
    ahora = datetime(2026, 8, 21, 12, 0, 0)

    assert _tiempo_relativo("2026-08-21T11:59:30", ahora) == "just now"
    assert _tiempo_relativo("2026-08-21T11:55:00", ahora) == "5 min ago"
    assert _tiempo_relativo("2026-08-21T09:00:00", ahora) == "3 h ago"
    assert _tiempo_relativo("2026-08-20T12:00:00", ahora) == "1 day ago"
    assert _tiempo_relativo("2026-08-18T12:00:00", ahora) == "3 days ago"


def test_topbar_avisa_de_usarla_solo_en_redes_propias():
    assert "Only on networks you own or are authorized to scan" in _generar_topbar_html("1.0.0", "#00D2D3")


# Palabras que solo aparecen si queda texto en español en la interfaz
_MARCAS_ESPAÑOL = ("escaneo", "Escane", "rango", "Rango", "puerto", "Puerto", "hace ", "Fase", "detectad",
                   "caído", "nuevo", "vivos", "Cambios", "Categorí", "Página", "Listo", "Solo ", "sin ", "Sin ")


def _sin_español(texto: str):
    encontradas = [marca for marca in _MARCAS_ESPAÑOL if marca in texto]
    assert not encontradas, f"texto en español: {encontradas}"


def test_los_paneles_html_no_tienen_texto_en_español():
    resultados = {
        "192.168.1.10": _resultado_fake(alertas=[{"puerto": 23, "motivo": "Telnet (unencrypted)"}]),
        "192.168.1.20": _resultado_fake(),
    }
    diff = {
        "primera_vez": False, "hosts_nuevos": ["192.168.1.20"], "hosts_caidos": ["192.168.1.99"],
        "puertos_cambiados": {"192.168.1.10": {
            "nuevos": [23, 8080], "cerrados": [],
            "nuevos_sensibles": [{"puerto": 23, "motivo": "Telnet (unencrypted)"}],
        }},
    }
    topologia = _topologia_fake()
    topologia["equipos"]["192.0.2.254"]["upstream"] = True   # para el texto de la puerta de enlace
    paneles = [
        _generar_kpis_html(resultados, "192.168.1.0/24", diff, "#00D2D3"),
        _generar_kpis_html(resultados, "192.168.1.0/24", None, "#00D2D3"),
        _generar_tabla_inventario_html(resultados),
        _generar_cambios_html(diff, resultados),
        _generar_cambios_html({**diff, "hosts_nuevos": [], "hosts_caidos": [], "puertos_cambiados": {}}, {}),
        _generar_topbar_html("1.0.0", "#00D2D3"),
        _generar_progreso_html("192.168.1.0/24", 2, "-sV -T4", "00:10", ["192.168.1.10"]),
        _generar_estado_vacio_html("#00D2D3"),
        _generar_topologia_html(resultados, "192.168.1.0/24", "#00D2D3"),
        _generar_topologia_html(_resultados_fake_arbol(), "192.0.2.0/24", "#00D2D3", topologia=topologia),
        _generar_topologia_html(resultados, "192.168.1.0/24", "#00D2D3", isometrica=True),
        _generar_topologia_html(_resultados_fake_arbol(), "192.0.2.0/24", "#00D2D3", topologia=topologia,
                                isometrica=True),
    ]
    for html in paneles:
        _sin_español(html)


def test_los_mensajes_de_validacion_estan_en_ingles(sin_snmp_en_entorno):
    mensajes = [
        _validar_rangos("")[1],
        _validar_rangos("10.0.10.0/24 192.168.1.1-50")[1],
        _validar_snmp(True, "", "")[1],
        _validar_snmp(True, "192.0.2.1", "")[1],
        _validar_snmp(True, "192.0.2.1", "", version="v3")[1],
    ]
    assert mensajes[0] == "Enter a network range in CIDR notation (e.g. 192.168.1.0/24)."
    assert mensajes[2] == "SNMP topology: enter the IP of at least one router or switch."
    for mensaje in mensajes:
        _sin_español(mensaje)


def test_los_widgets_del_sidebar_estan_en_ingles():
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file("../src/topology_scanner/webapp.py")
    at.run()
    next(t for t in at.sidebar.toggle if "SNMP" in t.label).set_value(True).run()
    textos = [w.label for w in [*at.sidebar.toggle, *at.sidebar.text_input, *at.sidebar.button, *at.sidebar.radio]]
    textos += [w.help or "" for w in [*at.sidebar.toggle, *at.sidebar.text_input, *at.sidebar.radio]]
    textos += [md.value for md in at.sidebar.markdown] + [c.value for c in at.sidebar.caption]

    assert not at.exception
    assert "Network range (CIDR)" in textos
    for texto in textos:
        _sin_español(texto)
