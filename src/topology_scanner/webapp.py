"""
webapp.py
---------
Interfaz web local (Streamlit): un formulario con botón de escaneo que
envuelve el pipeline scanner -> graph -> export y embebe el grafo
resultante. Igual que cli.py, solo orquesta - scanner/graph/export/history
no saben nada de Streamlit ni de esta interfaz.

El escaneo se lanza a mano como subprocess en un hilo aparte (no con
scanner.escanear_red() directamente) para que el botón "Parar escaneo"
pueda matar el proceso nmap a medias - nmap.PortScanner.scan() es
bloqueante y no expone el subprocess que crea, y la alternativa asíncrona
de python-nmap (PortScannerAsync) usa multiprocessing.Process en vez de
hilos, lo que en Windows complica mucho recuperar el resultado en el
proceso de Streamlit. Parar un escaneo a medias no conserva resultados
parciales (el XML de nmap no queda bien formado si se le mata a mitad).

Se lanza con `streamlit run src/topology_scanner/webapp.py`, o con el
entry point `topology-scanner-web` (ver pyproject.toml) una vez instalado
el extra opcional: pip install "topology-scanner[web]"
"""

import atexit
import contextlib
import os
import shlex
import socket
import subprocess
import tempfile
import threading
import time
from collections import Counter
from datetime import datetime
from typing import Optional

try:
    import streamlit as st
except ImportError as e:
    raise ImportError(
        "Falta streamlit para la interfaz web. Instala con: pip install \"topology-scanner[web]\""
    ) from e

import nmap

from topology_scanner import __version__
from topology_scanner.classifier import ICONOS_POR_CATEGORIA, PUERTOS_SENSIBLES
from topology_scanner.export import exportar_csv, exportar_html
from topology_scanner.graph import construir_grafo
from topology_scanner.history import HistoryError, listar_escaneos_recientes, registrar_y_comparar

# Imports absolutos (no relativos): streamlit run ejecuta este archivo como
# script suelto, sin contexto de paquete, así que "from .scanner import..."
# falla con ImportError. Requiere que topology_scanner esté instalado
# (pip install -e .) o en el PYTHONPATH.
from topology_scanner.scanner import (
    DEFAULT_NMAP_ARGS,
    PUERTOS_POR_DEFECTO,
    ScannerError,
    avisar_si_nmap_reporto_error,
    descubrir_hosts_vivos,
    parsear_host,
)


def _detectar_rango_local() -> Optional[str]:
    """Detecta el rango CIDR (asumiendo /24) de la interfaz de red principal
    del equipo, sin necesidad de admin/sudo. Truco estándar: abrir un socket
    UDP "conectado" a una IP externa no envía ningún paquete, solo hace que
    el SO elija qué interfaz local usaría para llegar ahí - de ahí se lee la
    IP local. Si no hay red disponible, devuelve None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip_local = s.getsockname()[0]
    except OSError:
        return None

    octetos = ip_local.split(".")
    if len(octetos) != 4:
        return None
    return f"{'.'.join(octetos[:3])}.0/24"


def _argumentos_nmap_desde_formulario(rapido: bool, con_so: bool) -> str:
    """Resuelve los argumentos de nmap a partir de los checkboxes del
    formulario. A diferencia de cli.py._resolver_argumentos_nmap, aquí no
    hay un --nmap-args libre con el que pueda entrar en conflicto, así que
    no hace falta cortar con un error: "rápido" simplemente gana si se
    marcan los dos a la vez."""
    if rapido:
        return "-T4"
    argumentos = DEFAULT_NMAP_ARGS
    if con_so:
        argumentos += " -O --osscan-guess"
    return argumentos


def _construir_comando_nmap(hosts: str, ports: str, arguments: str) -> list:
    """Reconstruye la línea de comandos que nmap.PortScanner.scan() lanzaría
    internamente. Hace falta porque ese método es bloqueante y no expone el
    subprocess.Popen que crea - no hay forma de matarlo desde fuera si el
    usuario pulsa "Parar" a medio escaneo, así que lanzamos el proceso
    nosotros mismos para quedarnos con esa referencia.

    La ruta del binario se resuelve con nmap.PortScanner()._nmap_path (la
    misma búsqueda que ya hace python-nmap internamente en
    descubrir_hosts_vivos, fase 1) en vez de shutil.which("nmap"): esa
    alternativa mira solo el PATH y podía no encontrar el binario aunque la
    fase 1 sí lo hubiera hecho, dejando la fase 2 rota de forma inconsistente."""
    try:
        nmap_path = nmap.PortScanner()._nmap_path
    except nmap.PortScannerError as e:
        raise ScannerError(f"Error de nmap (¿ejecutas con sudo?): {e}") from e
    return [nmap_path, "-oX", "-", *shlex.split(hosts), "-p", ports, *shlex.split(arguments)]


def _matar_si_sigue_vivo(proceso: subprocess.Popen):
    """Handler de atexit: si el proceso de Streamlit se cierra (Ctrl+C)
    mientras un escaneo sigue en marcha, intenta matar el nmap huérfano en
    vez de dejarlo corriendo en segundo plano. No cubre un kill -9/taskkill
    /F del propio proceso de Streamlit - ningún código de aplicación puede
    reaccionar a eso."""
    with contextlib.suppress(OSError):
        proceso.terminate()


def _ejecutar_proceso_nmap(comando: list, contenedor: dict):
    """Lanza nmap como subprocess y deja el resultado en `contenedor` (dict
    compartido con el hilo que lo lanzó). Pensado para correr en un
    threading.Thread aparte: mientras nmap corre, el hilo principal de
    Streamlit sigue libre para atender el botón "Parar escaneo".

    Cualquier fallo se guarda en contenedor["error"] en vez de dejar que la
    excepción tire el hilo en silencio: antes, si subprocess.Popen fallaba
    (ruta inválida, permisos...), contenedor["salida"] se quedaba en None y
    _procesar_salida_nmap(None) reventaba más adelante con una excepción
    sin controlar."""
    try:
        proceso = subprocess.Popen(comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        contenedor["proceso"] = proceso
        atexit.register(_matar_si_sigue_vivo, proceso)
        salida, _error = proceso.communicate()
        contenedor["salida"] = salida
        atexit.unregister(_matar_si_sigue_vivo)
    except OSError as e:
        contenedor["error"] = str(e)


def _procesar_salida_nmap(salida_xml: bytes) -> dict:
    """A partir del XML crudo que escupe nmap (-oX -), construye el mismo
    dict {ip: {...}} que produce scanner.escanear_red(), reutilizando
    parsear_host. Puede lanzar nmap.PortScannerError si el XML es inválido
    (p.ej. porque el proceso se mató a medias con "Parar escaneo")."""
    nm = nmap.PortScanner()
    nm.analyse_nmap_xml_scan(nmap_xml_output=salida_xml)
    avisar_si_nmap_reporto_error(nm)
    return {host: parsear_host(nm[host]) for host in nm.all_hosts()}


def _finalizar_resultados(resultados: dict, rango: str, guardar_historial: bool) -> dict:
    """A partir de resultados ya escaneados (formato de scanner.py), hace
    historial + grafo + export HTML. No usa sys.exit ni deja escapar
    excepciones de historial/export - un fallo aquí no debe tirar el
    servidor entero, la UI decide cómo mostrarlo.

    Devuelve: {"resultados": dict, "html": str|None, "diff": dict|None, "rango": str}
    """
    if not resultados:
        return {"resultados": {}, "html": None, "diff": None, "rango": rango}

    diff = None
    if guardar_historial:
        try:
            diff = registrar_y_comparar(resultados, rango)
        except HistoryError:
            diff = None  # perder el historial no es fatal, solo no se muestra el diff

    grafo = construir_grafo(resultados, rango)
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
        archivo_html = f.name
    try:
        exportar_html(grafo, archivo_html)
        with open(archivo_html, encoding="utf-8") as f:
            html = f.read()
    finally:
        # NamedTemporaryFile(delete=False) porque exportar_html necesita una
        # ruta a la que escribir, no un file object - pero eso significa que
        # nadie lo borra solo. Sin este finally, cada escaneo dejaba un
        # .html huérfano en el directorio temporal del sistema para siempre.
        os.remove(archivo_html)

    return {"resultados": resultados, "html": html, "diff": diff, "rango": rango}


def _generar_csv_bytes(resultados: dict) -> bytes:
    """Genera el CSV de inventario en memoria (para el botón de descarga),
    limpiando el archivo temporal que exportar_csv necesita para escribir -
    mismo motivo que el .html de _finalizar_resultados."""
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
        archivo_csv = f.name
    try:
        exportar_csv(resultados, archivo_csv)
        with open(archivo_csv, "rb") as f:
            return f.read()
    finally:
        os.remove(archivo_csv)


def _filas_para_tabla(resultados: dict) -> list:
    """Convierte resultados (formato de scanner.py) en filas planas para
    st.dataframe - una fila por host, sin listas anidadas."""
    return [
        {
            "IP": ip,
            "Hostname": datos.get("hostname") or "",
            "Fabricante": datos.get("vendor") or "",
            "Categoría": datos.get("categoria", "desconocido"),
            "SO": datos.get("so", ""),
            "Puertos": ", ".join(f"{p['puerto']}/{p['servicio']}" for p in datos.get("puertos", [])),
            "Alertas": len(datos.get("alertas", [])),
        }
        for ip, datos in sorted(resultados.items())
    ]


def _generar_chips_categorias_html(resultados: dict, limite: int = 8) -> str:
    """Chips "categoría N" del KPI de categorías, agrupando por categoría y
    ordenando por frecuencia. Reutiliza ICONOS_POR_CATEGORIA para el color -
    única fuente de verdad, la misma que ya usan el grafo y su leyenda
    (export.py) en vez de mantener una paleta duplicada aquí."""
    conteo = Counter(datos.get("categoria", "desconocido") for datos in resultados.values())
    mas_comunes = conteo.most_common()
    visibles, resto = mas_comunes[:limite], mas_comunes[limite:]

    chips = [
        f'<span class="cat-chip mono"><span class="cat-dot" style="width:7px;height:7px;'
        f'border-radius:50%;background:{ICONOS_POR_CATEGORIA.get(cat, ICONOS_POR_CATEGORIA["desconocido"])["color"]};'
        f'display:inline-block;"></span>{cat} {n}</span>'
        for cat, n in visibles
    ]
    if resto:
        chips.append(f'<span class="cat-chip mono">+{sum(n for _, n in resto)} categorías más</span>')
    return "".join(chips)


def _generar_kpis_html(resultados: dict, rango: str, diff: Optional[dict], accent: str) -> str:
    """HTML de la fila de KPIs (hosts, puertos sensibles, cambios,
    categorías) que sustituye a los st.metric() de antes. El KPI de
    "Cambios" no fabrica una comparación si es el primer escaneo de este
    rango (diff["primera_vez"] o diff=None) - mismo criterio que el resto
    de la app de no inventar datos que no existen."""
    total_hosts = len(resultados)
    alertas_totales = sum(len(d.get("alertas", [])) for d in resultados.values())

    if diff and not diff["primera_vez"]:
        n_nuevos, n_caidos = len(diff["hosts_nuevos"]), len(diff["hosts_caidos"])
        cambios_num = (
            f'<span style="color:#2ecc71">+{n_nuevos}</span> '
            f'<span class="muted" style="font-size:15px;">nuevo</span> · '
            f'<span style="color:#8a97a6">-{n_caidos}</span> '
            f'<span class="muted" style="font-size:15px;">caído</span>'
        )
        cambios_sub = "vs. escaneo anterior"
    else:
        cambios_num = '<span class="muted">—</span>'
        cambios_sub = "primer escaneo de este rango"

    color_alertas = "#ff5c5c" if alertas_totales else "#E3E8EE"
    sub_alertas = "requieren revisión" if alertas_totales else "sin alertas"

    return f"""
<div class="kpi-row">
  <div class="kpi-card">
    <div class="kpi-head">
      <div class="kpi-lbl mono">HOSTS DETECTADOS</div>
      <div class="kpi-icon" style="background:{accent}1f; color:{accent}">
        <svg viewBox="0 0 20 20" width="14" height="14" fill="none" stroke="currentColor"
             stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="10" cy="4.5" r="2"/><circle cx="4" cy="15" r="2"/><circle cx="16" cy="15" r="2"/>
          <path d="M10 6.5v3M8.5 10.7L5.3 13.3M11.5 10.7l3.2 2.6"/>
        </svg>
      </div>
    </div>
    <div class="kpi-num display">{total_hosts}</div>
    <div class="kpi-sub mono">en {rango}</div>
  </div>

  <div class="kpi-card">
    <div class="kpi-head">
      <div class="kpi-lbl mono">PUERTOS SENSIBLES</div>
      <div class="kpi-icon" style="background:rgba(255,92,92,0.14); color:#ff5c5c">
        <svg viewBox="0 0 20 20" width="14" height="14" fill="none" stroke="currentColor"
             stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
          <path d="M10 2.8l8 14H2l8-14z"/><path d="M10 8v3.2"/>
        </svg>
      </div>
    </div>
    <div class="kpi-num display" style="color:{color_alertas}">{alertas_totales}</div>
    <div class="kpi-sub mono">{sub_alertas}</div>
  </div>

  <div class="kpi-card">
    <div class="kpi-head">
      <div class="kpi-lbl mono">CAMBIOS</div>
      <div class="kpi-icon" style="background:rgba(46,204,113,0.12); color:#2ecc71">
        <svg viewBox="0 0 20 20" width="14" height="14" fill="none" stroke="currentColor"
             stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
          <path d="M4 12l4-5 3 3 5-6"/><path d="M13 4h3v3"/>
        </svg>
      </div>
    </div>
    <div class="kpi-num display" style="font-size:20px;">{cambios_num}</div>
    <div class="kpi-sub mono">{cambios_sub}</div>
  </div>

  <div class="kpi-card">
    <div class="kpi-head"><div class="kpi-lbl mono">CATEGORÍAS</div></div>
    <div style="line-height:1;">{_generar_chips_categorias_html(resultados)}</div>
  </div>
</div>
"""


def _generar_tabla_inventario_html(resultados: dict) -> str:
    """Tabla de inventario con chips de puertos (los de PUERTOS_SENSIBLES
    resaltados en rojo) y la fila marcada si el host tiene alguna alerta -
    mismo criterio visual que el resto de la app."""
    filas = []
    for ip, datos in sorted(resultados.items()):
        categoria = datos.get("categoria", "desconocido")
        color = ICONOS_POR_CATEGORIA.get(categoria, ICONOS_POR_CATEGORIA["desconocido"])["color"]
        puertos = datos.get("puertos", [])
        tiene_alertas = bool(datos.get("alertas"))

        if puertos:
            chips_puertos = "".join(
                f'<span class="port-chip{" sens" if p["puerto"] in PUERTOS_SENSIBLES else ""} mono">'
                f'{p["puerto"]}</span>'
                for p in puertos
            )
        else:
            chips_puertos = '<span class="muted mono" style="font-size:11px;">—</span>'

        alerta_icono = "" if not tiene_alertas else (
            '<svg viewBox="0 0 20 20" width="14" height="14" fill="none" stroke="#ff5c5c" '
            'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M10 2.8l8 14H2l8-14z"/><path d="M10 8v3.2"/></svg>'
        )

        filas.append(f"""
        <tr{' class="sensitive"' if tiene_alertas else ""}>
          <td><div class="mono" style="font-weight:500;">{ip}</div>
              <div class="muted mono" style="font-size:11px;">{datos.get("hostname") or ""}</div></td>
          <td><div class="row-cat"><span class="cat-dot" style="background:{color}"></span>{categoria}</div></td>
          <td class="mono muted">{datos.get("so") or "desconocido"}</td>
          <td>{chips_puertos}</td>
          <td>{alerta_icono}</td>
        </tr>
        """)

    return f"""
<table class="inv-table">
  <thead><tr><th>Host</th><th>Categoría</th><th>SO</th><th>Puertos</th><th></th></tr></thead>
  <tbody>{"".join(filas)}</tbody>
</table>
"""


def _generar_cambios_html(diff: dict, resultados: dict) -> str:
    """Tarjetas de "Cambios respecto al escaneo anterior", mismo contenido
    que el st.expander de texto plano de antes (hosts nuevos/caídos,
    puertos nuevos y cuáles de esos son sensibles) con el lenguaje visual
    del resto del panel de resultados. Un host caído ya no está en
    `resultados` (por eso ha caído) - no se inventa hostname/categoría
    para él, solo el hecho en sí."""
    items = []

    for ip in diff["hosts_nuevos"]:
        datos = resultados.get(ip, {})
        sub = " · ".join(filter(None, [datos.get("hostname"), datos.get("categoria")]))
        items.append(f"""
        <div class="chg-item">
          <div class="chg-badge" style="background:rgba(46,204,113,0.15); color:#2ecc71;">+</div>
          <div>
            <div class="mono" style="font-weight:500;">{ip}
              <span class="muted" style="font-weight:400;">nuevo</span></div>
            <div class="muted mono" style="font-size:11px;">{sub}</div>
          </div>
        </div>
        """)

    for ip in diff["hosts_caidos"]:
        items.append(f"""
        <div class="chg-item">
          <div class="chg-badge" style="background:rgba(122,138,154,0.15); color:#8a97a6;">-</div>
          <div>
            <div class="mono" style="font-weight:500; color:#8a97a6;">{ip}
              <span class="muted" style="font-weight:400;">caído</span></div>
            <div class="muted mono" style="font-size:11px;">no respondió al ping scan</div>
          </div>
        </div>
        """)

    for ip, cambios in diff["puertos_cambiados"].items():
        if not cambios["nuevos"]:
            continue
        puertos_txt = ", ".join(map(str, cambios["nuevos"]))
        sensibles = cambios.get("nuevos_sensibles", [])
        if sensibles:
            items.append(f"""
            <div class="chg-item warn">
              <div class="chg-badge" style="background:rgba(255,92,92,0.18); color:#ff5c5c;">
                <svg viewBox="0 0 20 20" width="11" height="11" fill="none" stroke="currentColor"
                     stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M10 2.8l8 14H2l8-14z"/><path d="M10 8v3.2"/>
                </svg>
              </div>
              <div>
                <div class="mono" style="font-weight:500; color:#ff8a80;">{ip}
                  <span class="muted" style="font-weight:400; color:#ff8a80;">puerto nuevo</span></div>
                <div class="muted mono" style="font-size:11px;">{puertos_txt} · {sensibles[0]["motivo"]}</div>
              </div>
            </div>
            """)
        else:
            items.append(f"""
            <div class="chg-item">
              <div class="chg-badge" style="background:rgba(227,232,238,0.10); color:#B8C2CC;">•</div>
              <div>
                <div class="mono" style="font-weight:500;">{ip}
                  <span class="muted" style="font-weight:400;">puerto nuevo</span></div>
                <div class="muted mono" style="font-size:11px;">{puertos_txt}</div>
              </div>
            </div>
            """)

    if not items:
        items.append(
            '<div class="muted mono" style="font-size:12px; padding:4px 2px;">'
            "Sin cambios respecto al escaneo anterior.</div>"
        )

    return f'<div class="chg-body">{"".join(items)}</div>'


def _mostrar_resultado(resultado: dict, accent: str):
    resultados = resultado["resultados"]
    if not resultados:
        st.warning("No se detectaron hosts. Revisa el rango y los permisos (prueba con sudo).")
        return

    diff = resultado["diff"]
    st.markdown(_generar_kpis_html(resultados, resultado["rango"], diff, accent), unsafe_allow_html=True)

    st.subheader("Topología")
    st.components.v1.html(resultado["html"], height=650, scrolling=True)

    st.subheader("Inventario")
    st.markdown(_generar_tabla_inventario_html(resultados), unsafe_allow_html=True)
    st.caption(f"Mostrando {len(resultados)} hosts · ordenado por IP")
    st.download_button(
        "Descargar inventario CSV", _generar_csv_bytes(resultados),
        file_name="inventario.csv", mime="text/csv",
    )

    if diff and not diff["primera_vez"]:
        st.subheader("Cambios")
        st.caption(f"{len(diff['hosts_nuevos'])} nuevos · {len(diff['hosts_caidos'])} caídos")
        st.markdown(_generar_cambios_html(diff, resultados), unsafe_allow_html=True)


@st.fragment(run_every="1s")
def _fragmento_progreso():
    """Solo este trozo de la página se refresca cada segundo (no la página
    entera, así no parpadean los botones/campos) mientras el hilo de nmap
    sigue vivo. Cuando termina (solo o porque "Parar escaneo" mató el
    proceso), guarda el resultado en session_state y fuerza un rerun
    completo (st.rerun() por defecto sale del fragmento) para volver a
    dejar los botones activos y mostrar el resultado."""
    if st.session_state.hilo.is_alive():
        parametros = st.session_state.parametros_pendientes
        tiempo = _formatear_tiempo_transcurrido(time.time() - parametros["hora_inicio"])
        st.markdown(
            _generar_progreso_html(
                rango=parametros["rango"],
                hosts_vivos=parametros["hosts_vivos"],
                argumentos_nmap=parametros["argumentos_nmap"],
                tiempo=tiempo,
            ),
            unsafe_allow_html=True,
        )
        return

    contenedor = st.session_state.contenedor
    parametros = st.session_state.parametros_pendientes
    st.session_state.estado = "idle"
    if st.session_state.cancelado:
        st.session_state.mensaje = ("info", "Escaneo cancelado.")
        st.session_state.resultado = None
    elif contenedor.get("error"):
        st.session_state.mensaje = ("error", f"No se pudo lanzar nmap: {contenedor['error']}")
        st.session_state.resultado = None
    else:
        try:
            resultados = _procesar_salida_nmap(contenedor["salida"])
        except nmap.PortScannerError as e:
            st.session_state.mensaje = ("error", f"Error de nmap: {e}")
            st.session_state.resultado = None
        else:
            st.session_state.resultado = _finalizar_resultados(
                resultados, parametros["rango"], parametros["guardar_historial"]
            )
    st.rerun()


def _generar_css(accent: str) -> str:
    """CSS inyectado sobre el tema oscuro de .streamlit/config.toml (colores
    base van ahí). Streamlit no deja fijar fuentes a medida solo con
    [theme], así que eso -y los retoques de botones/inputs/caption de este
    "tema Command Center"- se completa aquí con CSS dirigido a los
    data-testid estables de Streamlit (comprobados a mano en el DOM real,
    no adivinados: `stBaseButton-primary`/`-secondary`,
    `stTextInputRootElement`, `stCaptionContainer`... existen tal cual en
    esta versión) en vez de a sus clases internas (`st-emotion-cache-*`),
    que cambian de una versión a otra sin previo aviso y de hecho no
    distinguen ni siquiera un `st.container(border=True)` de uno sin borde.

    `accent` se recibe como parámetro en vez de repetir el hex a mano: lo
    resuelve _inyectar_estilos() con st.get_option("theme.primaryColor"),
    para que este CSS siga el acento aunque cambie config.toml."""
    return f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@600;700&family=JetBrains+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap');

html, body, [data-testid="stAppViewContainer"] {{
    font-family: 'IBM Plex Sans', sans-serif;
}}
h1, h2, h3 {{
    font-family: 'Space Grotesk', sans-serif !important;
    letter-spacing: -0.01em;
}}
[data-testid="stTextInput"] input,
[data-testid="stDataFrame"],
[data-testid="stMetricValue"] {{
    font-family: 'JetBrains Mono', monospace !important;
}}
[data-testid="stMetricLabel"] {{
    text-transform: uppercase;
    letter-spacing: 0.04em;
    font-size: 0.75rem !important;
}}

[data-testid="stBaseButton-primary"] {{
    border-radius: 10px;
    font-family: 'Space Grotesk', sans-serif;
    font-weight: 600;
    box-shadow: 0 0 0 1px {accent}59, 0 10px 26px -8px {accent}8c;
}}
[data-testid="stBaseButton-secondary"],
[data-testid="stBaseButton-header"] {{
    border-radius: 10px;
    border-color: rgba(227,232,238,0.16);
    font-weight: 500;
}}
[data-testid="stTextInputRootElement"] {{
    border-radius: 9px !important;
}}
[data-testid="stTextInputRootElement"]:focus-within {{
    border-color: {accent} !important;
}}
[data-testid="stCaptionContainer"] {{
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 6px 12px;
    border-radius: 20px;
    border: 1px solid rgba(227,232,238,0.10);
}}

.topbar-meta {{
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: -6px;
}}
.topbar-eyebrow {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 10.5px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: #7C8A9A;
}}
.topbar-version {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: #4A5A6A;
    margin-left: auto;
}}

.section-eyebrow {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 10.5px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: #5A6B7C;
    font-weight: 600;
    margin: 4px 0 2px;
}}
.empty-state {{
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 20px;
    padding: 72px 40px;
    margin-top: 8px;
    border-radius: 18px;
    border: 1px solid rgba(227,232,238,0.08);
    background: rgba(17,25,33,0.5);
    text-align: center;
}}
.empty-state-title {{
    font-family: 'Space Grotesk', sans-serif;
    font-size: 22px;
    font-weight: 600;
}}
.empty-state-body {{
    font-size: 13.5px;
    color: #7C8A9A;
    max-width: 460px;
    line-height: 1.6;
}}
.empty-state-hint {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 11.5px;
    color: #4A5A6A;
    display: flex;
    align-items: center;
    gap: 8px;
}}
.kbd {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 10.5px;
    color: #B8C2CC;
    padding: 3px 7px;
    border-radius: 5px;
    border: 1px solid rgba(227,232,238,0.14);
    background: rgba(227,232,238,0.04);
}}

.history-list {{ display: flex; flex-direction: column; gap: 8px; }}
.history-row {{
    display: flex; align-items: center; justify-content: space-between;
    padding: 10px 12px; border-radius: 9px;
    border: 1px solid rgba(227,232,238,0.07); background: rgba(227,232,238,0.02);
}}
.history-left {{ display: flex; flex-direction: column; gap: 3px; }}
.history-range {{ font-size: 12.5px; font-weight: 500; }}
.history-time {{ display: flex; align-items: center; gap: 5px; font-size: 10.5px; color: #5A6B7C; }}
.history-badge {{
    display: flex; align-items: center; gap: 5px;
    font-size: 11px; color: #B8C2CC;
    padding: 3px 8px; border-radius: 12px; background: rgba(227,232,238,0.06);
}}
.history-dot {{ width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }}

.phase-row {{ display: flex; align-items: center; gap: 0; }}
.phase-chip {{
    display: flex; align-items: center; gap: 9px;
    padding: 10px 16px; border-radius: 10px;
    border: 1px solid rgba(227,232,238,0.10); background: rgba(17,25,33,0.7);
    font-size: 12.5px;
}}
.phase-chip.done {{ color: #B8C2CC; }}
.phase-chip.active {{ border-color: {accent}66; color: #E3E8EE; }}
.phase-line {{ width: 46px; height: 1px; background: rgba(227,232,238,0.15); }}
.check-badge {{
    width: 18px; height: 18px; border-radius: 50%; background: rgba(46,204,113,0.15);
    display: flex; align-items: center; justify-content: center; color: #2ecc71;
}}
.pulse-dot {{
    width: 7px; height: 7px; border-radius: 50%; background: {accent};
    animation: pulse 1.4s ease-in-out infinite;
}}
@keyframes pulse {{ 0%,100% {{ opacity:1; transform:scale(1);}} 50% {{ opacity:.35; transform:scale(1.3);}} }}

.stats-row {{ display: flex; gap: 14px; }}
.stat-chip {{
    flex: 1; display: flex; flex-direction: column; gap: 4px;
    padding: 14px 18px; border-radius: 12px;
    border: 1px solid rgba(227,232,238,0.08); background: rgba(17,25,33,0.7);
}}
.stat-chip .num {{ font-size: 22px; font-weight: 600; font-family: 'Space Grotesk', sans-serif; }}
.stat-chip .lbl {{
    font-size: 10.5px; letter-spacing: 0.06em; text-transform: uppercase; color: #5A6B7C;
}}

.terminal-card {{
    border-radius: 16px; border: 1px solid rgba(227,232,238,0.08);
    background: #060b11; padding: 22px 26px; position: relative; overflow: hidden;
    margin-top: 4px;
}}
.terminal-head {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }}
.terminal-title {{ font-size: 11.5px; letter-spacing: 0.08em; text-transform: uppercase; color: #5A6B7C; }}
.dots {{ display: flex; gap: 6px; }}
.dots span {{ width: 8px; height: 8px; border-radius: 50%; background: rgba(227,232,238,0.15); }}
.log-line {{ display: flex; align-items: center; gap: 10px; font-size: 13px; line-height: 2; }}
.log-line.cmd {{ color: #5A6B7C; }}
.cursor {{
    display: inline-block; width: 8px; height: 15px; background: {accent};
    animation: blink 1s step-start infinite; vertical-align: -2px;
}}
@keyframes blink {{ 50% {{ opacity: 0; }} }}

.radar-mini {{ position: absolute; top: 20px; right: 26px; width: 90px; height: 90px; }}
.sweep {{
    position: absolute; inset: 0; border-radius: 50%;
    background: conic-gradient(from 0deg, {accent}80, transparent 40%);
    animation: spin 2.4s linear infinite;
}}
@keyframes spin {{ to {{ transform: rotate(360deg); }} }}
.radar-ring {{ position: absolute; border-radius: 50%; border: 1px solid {accent}40; }}

.muted {{ color: #7C8A9A; }}

.kpi-row {{ display: flex; gap: 16px; }}
.kpi-card {{
    flex: 1; padding: 18px 20px; border-radius: 14px;
    border: 1px solid rgba(227,232,238,0.08); background: rgba(17,25,33,0.75);
    display: flex; flex-direction: column; gap: 8px;
}}
.kpi-head {{ display: flex; align-items: center; justify-content: space-between; }}
.kpi-icon {{
    width: 26px; height: 26px; border-radius: 7px;
    display: flex; align-items: center; justify-content: center;
}}
.kpi-num {{ font-size: 26px; font-weight: 600; line-height: 1; font-family: 'Space Grotesk', sans-serif; }}
.kpi-lbl {{ font-size: 11px; letter-spacing: 0.04em; color: #5A6B7C; }}
.kpi-sub {{ font-size: 11px; color: #5A6B7C; }}
.cat-chip {{
    display: inline-flex; align-items: center; gap: 5px; font-size: 10.5px; color: #B8C2CC;
    padding: 2px 7px 2px 5px; border-radius: 10px; background: rgba(227,232,238,0.06);
    margin: 2px 4px 0 0;
}}

table.inv-table {{ width: 100%; border-collapse: collapse; }}
table.inv-table th {{
    text-align: left; font-size: 10px; letter-spacing: 0.06em; text-transform: uppercase;
    color: #5A6B7C; font-weight: 500; padding: 10px 12px;
    border-bottom: 1px solid rgba(227,232,238,0.07);
}}
table.inv-table td {{
    padding: 10px 12px; font-size: 12.5px; border-bottom: 1px solid rgba(227,232,238,0.05);
    vertical-align: middle;
}}
table.inv-table tr.sensitive td:first-child {{ box-shadow: inset 3px 0 0 #ff5c5c; }}
.row-cat {{ display: flex; align-items: center; gap: 8px; }}
.cat-dot {{ width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0; display: inline-block; }}
.port-chip {{
    display: inline-block; font-size: 10.5px; padding: 2px 6px; border-radius: 5px;
    background: rgba(227,232,238,0.06); color: #B8C2CC; margin: 1px 3px 1px 0;
}}
.port-chip.sens {{ background: rgba(255,92,92,0.12); color: #ff8a80; }}

.chg-body {{ display: flex; flex-direction: column; gap: 10px; margin-top: 4px; }}
.chg-item {{
    display: flex; align-items: flex-start; gap: 10px; padding: 11px 13px; border-radius: 10px;
    background: rgba(227,232,238,0.03); border: 1px solid rgba(227,232,238,0.06); font-size: 12px;
}}
.chg-item.warn {{ background: rgba(255,92,92,0.07); border-color: rgba(255,92,92,0.25); }}
.chg-badge {{
    width: 20px; height: 20px; border-radius: 6px; display: flex;
    align-items: center; justify-content: center; flex-shrink: 0; font-size: 12px;
}}
</style>
"""


def _generar_encabezado_html(version: str, accent: str) -> str:
    """HTML del bloque de marca (icono + "Command Center" + versión) que se
    muestra encima de st.title(). Aparte en su propia función para poder
    comprobar el contenido sin renderizar Streamlit."""
    return f"""
<div class="topbar-meta">
  <svg viewBox="0 0 24 24" width="22" height="22" fill="none">
    <circle cx="12" cy="12" r="9" stroke="{accent}" stroke-width="1.3" opacity="0.35"/>
    <circle cx="12" cy="12" r="5.5" stroke="{accent}" stroke-width="1.3" opacity="0.65"/>
    <circle cx="12" cy="12" r="2" fill="{accent}"/>
  </svg>
  <span class="topbar-eyebrow">Command Center</span>
  <span class="topbar-version">v{version}</span>
</div>
"""


_SVG_RELOJ = (
    '<svg viewBox="0 0 20 20" width="11" height="11" fill="none" stroke="currentColor" '
    'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">'
    '<circle cx="10" cy="10" r="7.2"/><path d="M10 6v4l3 2"/></svg>'
)


def _tiempo_relativo(fecha_iso: str, ahora: Optional[datetime] = None) -> str:
    """Convierte el ISO datetime que guarda history.py en un texto relativo
    corto ("hace 2 días") para las filas del historial del sidebar. Acepta
    `ahora` para que los tests no dependan del reloj real."""
    momento = datetime.fromisoformat(fecha_iso)
    ahora = ahora or datetime.now()
    segundos = (ahora - momento).total_seconds()
    if segundos < 60:
        return "hace un momento"
    minutos = int(segundos // 60)
    if minutos < 60:
        return f"hace {minutos} min"
    horas = int(minutos // 60)
    if horas < 24:
        return f"hace {horas} h"
    dias = int(horas // 24)
    return f"hace {dias} día" if dias == 1 else f"hace {dias} días"


def _generar_historial_html(escaneos: list) -> str:
    """HTML de la lista de "historial reciente" del sidebar, a partir de
    history.listar_escaneos_recientes(). Aparte en su propia función para
    poder comprobar el contenido sin renderizar Streamlit, igual que
    _generar_encabezado_html."""
    filas = []
    for escaneo in escaneos:
        alertas = escaneo["alertas"]
        color = "#ff5c5c" if alertas else "#2ecc71"
        cifra = f"{escaneo['total_hosts']} · {alertas}⚠" if alertas else str(escaneo["total_hosts"])
        filas.append(f"""
        <div class="history-row">
          <div class="history-left">
            <div class="history-range mono">{escaneo["rango"]}</div>
            <div class="history-time">{_SVG_RELOJ}{_tiempo_relativo(escaneo["fecha"])}</div>
          </div>
          <div class="history-badge mono"><div class="history-dot" style="background:{color}"></div>{cifra}</div>
        </div>
        """)
    return f'<div class="history-list">{"".join(filas)}</div>'


def _formatear_tiempo_transcurrido(segundos: float) -> str:
    """mm:ss para el contador de tiempo transcurrido del panel de progreso."""
    minutos, segs = divmod(int(segundos), 60)
    return f"{minutos:02d}:{segs:02d}"


def _generar_progreso_html(rango: str, hosts_vivos: int, argumentos_nmap: str, tiempo: str) -> str:
    """HTML del panel de progreso (sustituye al st.info() de una sola línea
    de antes). Deliberadamente NO inventa progreso host a host de la fase 2:
    _ejecutar_proceso_nmap lanza un único nmap para todos los hosts vivos a
    la vez y proceso.communicate() no devuelve nada hasta que termina el
    proceso completo (ver docstring del módulo), así que durante la fase 2
    no hay forma de saber cuántos hosts concretos lleva escaneados nmap ni
    qué alertas ha encontrado todavía - mostrar esas cifras "en vivo" sería
    fabricarlas, el mismo error que se corrigió antes con el SO detectado
    en el mockup. Solo se muestran datos que la app conoce de verdad en
    este momento: los hosts vivos de la fase 1 (ya terminada), el rango y
    el tiempo transcurrido."""
    return f"""
<div class="phase-row">
  <div class="phase-chip done mono">
    <div class="check-badge">
      <svg viewBox="0 0 20 20" width="10" height="10" fill="none" stroke="currentColor"
           stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M4 10l4 4 8-9"/></svg>
    </div>
    Fase 1 · Descubrimiento — {hosts_vivos} hosts vivos
  </div>
  <div class="phase-line"></div>
  <div class="phase-chip active mono">
    <div class="pulse-dot"></div>
    Fase 2 · Escaneo de puertos y servicios
  </div>
</div>

<div class="stats-row">
  <div class="stat-chip">
    <div class="num">{hosts_vivos}</div>
    <div class="lbl mono">Hosts vivos</div>
  </div>
  <div class="stat-chip">
    <div class="num mono" style="font-size:16px;">{rango}</div>
    <div class="lbl mono">Rango en curso</div>
  </div>
  <div class="stat-chip">
    <div class="num mono">{tiempo}</div>
    <div class="lbl mono">Tiempo transcurrido</div>
  </div>
</div>

<div class="terminal-card">
  <div class="radar-mini">
    <div class="radar-ring" style="inset:0;"></div>
    <div class="radar-ring" style="inset:20px;"></div>
    <div class="sweep"></div>
  </div>
  <div class="terminal-head">
    <div class="terminal-title mono">Registro de escaneo</div>
    <div class="dots"><span></span><span></span><span></span></div>
  </div>
  <div class="mono" style="display:flex; flex-direction:column;">
    <div class="log-line cmd">&gt; descubrir_hosts_vivos({rango})</div>
    <div class="log-line" style="color:#B8C2CC; padding-left:18px;">ping scan completo — {hosts_vivos} hosts vivos</div>
    <div class="log-line cmd" style="margin-top:6px;">&gt; nmap {argumentos_nmap} -p ...</div>
    <div class="log-line" style="color:#7C8A9A;">
      escaneando puertos y servicios de {hosts_vivos} hosts<span class="cursor"></span>
    </div>
  </div>
</div>
"""


def _generar_estado_vacio_html(accent: str) -> str:
    """HTML del panel principal cuando no hay ni escaneo en curso ni
    resultado que mostrar. Antes de mover el formulario al sidebar
    (_inyectar_estilos), ese hueco lo ocupaba el propio formulario - ahora
    que el sidebar es independiente del panel principal, sin esto el panel
    se queda completamente en blanco al abrir la app."""
    return f"""
<div class="empty-state">
  <svg viewBox="0 0 24 24" width="40" height="40" fill="none">
    <circle cx="12" cy="12" r="9" stroke="{accent}" stroke-width="1.3" opacity="0.3"/>
    <circle cx="12" cy="12" r="5.5" stroke="{accent}" stroke-width="1.3" opacity="0.55"/>
    <circle cx="12" cy="12" r="2" fill="{accent}"/>
  </svg>
  <div class="empty-state-title">Listo para escanear</div>
  <div class="empty-state-body">Configura el rango de red en el panel lateral y pulsa
    <b style="color:#E3E8EE">Escanear</b> para descubrir los dispositivos activos,
    su fabricante y los puertos que exponen.</div>
  <div class="empty-state-hint">Fase 1 <span class="kbd">ping scan</span> ·
    Fase 2 <span class="kbd">-sV puertos</span></div>
</div>
"""


def _inyectar_estilos() -> str:
    """Devuelve el accent color usado (leído de theme.primaryColor) para que
    main() pueda reutilizarlo en el estado vacío sin volver a resolverlo."""
    accent = st.get_option("theme.primaryColor") or "#00D2D3"
    st.markdown(_generar_css(accent), unsafe_allow_html=True)
    st.markdown(_generar_encabezado_html(__version__, accent), unsafe_allow_html=True)
    return accent


def main():
    st.set_page_config(page_title="Network Topology Scanner", page_icon="🌐", layout="wide")
    accent = _inyectar_estilos()
    st.title("Network Topology Scanner")
    st.caption("Usa esta herramienta solo en redes propias o con autorización explícita.")

    st.session_state.setdefault("estado", "idle")
    st.session_state.setdefault("rango_detectado", "")
    st.session_state.setdefault("resultado", None)

    # Mensaje dejado por _fragmento_progreso() justo antes de su propio
    # st.rerun(): si se pintara ahí mismo, ese mismo rerun lo borraría antes
    # de que llegara a verse. Se guarda en session_state y se muestra aquí,
    # en el primer render de la página siguiente - solo una vez (pop).
    mensaje = st.session_state.pop("mensaje", None)
    if mensaje:
        tipo, texto = mensaje
        getattr(st, tipo)(texto)

    escaneando = st.session_state.estado == "escaneando"

    with st.sidebar:
        st.markdown('<div class="section-eyebrow">Configuración de escaneo</div>', unsafe_allow_html=True)
        rango = st.text_input(
            "Rango de red (CIDR)",
            value=st.session_state.rango_detectado,
            placeholder="192.168.1.0/24",
            disabled=escaneando,
        )
        detectar = st.button("📍 Detectar mi red", disabled=escaneando, use_container_width=True)

        st.divider()
        st.markdown('<div class="section-eyebrow">Opciones</div>', unsafe_allow_html=True)
        rapido = st.checkbox(
            "Escaneo rápido", value=True, disabled=escaneando, help="-T4, sin detección de SO"
        )
        con_so = st.checkbox("Detectar SO", disabled=escaneando, help="-O --osscan-guess, más lento")
        guardar_historial = st.checkbox(
            "Guardar en historial",
            value=True,
            disabled=escaneando,
            help="Compara con el escaneo anterior",
        )

        st.divider()
        enviado = st.button("Escanear", disabled=escaneando, type="primary", use_container_width=True)
        parar = st.button("⏹ Parar escaneo", disabled=not escaneando, use_container_width=True)

        st.divider()
        st.markdown('<div class="section-eyebrow">Historial reciente</div>', unsafe_allow_html=True)
        try:
            recientes = listar_escaneos_recientes()
        except HistoryError:
            recientes = []  # mismo criterio que el resto de la app: fallo de historial no bloquea la UI
        if recientes:
            st.markdown(_generar_historial_html(recientes), unsafe_allow_html=True)
        else:
            st.caption("Todavía no hay escaneos guardados.")

    if detectar:
        # "Detectar mi red" está debajo del text_input en el layout (a la
        # derecha de "Escanear"), así que actualizar session_state aquí no
        # llega a tiempo para el value= que ya se evaluó más arriba en esta
        # misma pasada - hace falta un rerun explícito para que se vea.
        detectado = _detectar_rango_local()
        if detectado:
            st.session_state.rango_detectado = detectado
            st.rerun()
        else:
            st.warning("No se pudo detectar la red automáticamente. Indícala a mano.")

    if enviado and not escaneando:
        if not rango:
            st.warning("Indica un rango de red en notación CIDR (ej: 192.168.1.0/24).")
        else:
            try:
                vivos = descubrir_hosts_vivos(rango)
            except ScannerError as e:
                st.error(str(e))
                vivos = None
            if vivos == []:
                st.warning("Ningún host respondió al ping scan.")
            elif vivos:
                argumentos_nmap = _argumentos_nmap_desde_formulario(rapido, con_so)
                try:
                    comando = _construir_comando_nmap(" ".join(vivos), PUERTOS_POR_DEFECTO, argumentos_nmap)
                except ScannerError as e:
                    st.error(str(e))
                else:
                    contenedor = {"proceso": None, "salida": None}
                    hilo = threading.Thread(target=_ejecutar_proceso_nmap, args=(comando, contenedor), daemon=True)
                    hilo.start()
                    st.session_state.estado = "escaneando"
                    st.session_state.hilo = hilo
                    st.session_state.contenedor = contenedor
                    st.session_state.parametros_pendientes = {
                        "rango": rango,
                        "guardar_historial": guardar_historial,
                        "hosts_vivos": len(vivos),
                        "argumentos_nmap": argumentos_nmap,
                        "hora_inicio": time.time(),
                    }
                    st.session_state.cancelado = False
                    st.rerun()

    if parar and escaneando:
        proceso = st.session_state.contenedor.get("proceso")
        if proceso is not None:
            proceso.terminate()
        st.session_state.cancelado = True

    if escaneando:
        _fragmento_progreso()
    elif st.session_state.resultado:
        _mostrar_resultado(st.session_state.resultado, accent)
    else:
        st.markdown(_generar_estado_vacio_html(accent), unsafe_allow_html=True)


def lanzar():
    """Punto de entrada de `topology-scanner-web`: lanza este script con el
    runtime de Streamlit (equivalente a `streamlit run webapp.py`)."""
    import sys

    from streamlit.web import cli as stcli

    sys.argv = ["streamlit", "run", __file__]
    sys.exit(stcli.main())


if __name__ == "__main__":
    main()
