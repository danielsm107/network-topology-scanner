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

La XML de resultado se escribe a un archivo temporal (-oX archivo, no
-oX -) en vez de a stdout: stdout se deja libre para leer en vivo la
salida verbose de nmap (-v) línea a línea y así poder pintar un "Registro
de escaneo" real en el panel de progreso (ver _ejecutar_proceso_nmap),
sin depender de .communicate() (que no devuelve nada hasta que el proceso
entero termina).

Se lanza con `streamlit run src/topology_scanner/webapp.py`, o con el
entry point `topology-scanner-web` (ver pyproject.toml) una vez instalado
el extra opcional: pip install "topology-scanner[web]"
"""

import atexit
import contextlib
import math
import os
import re
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
from topology_scanner.export import CDN_FONTAWESOME, exportar_csv, exportar_html, posiciones_circulares
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


def _construir_comando_nmap(hosts: str, ports: str, arguments: str, archivo_xml: str) -> list:
    """Reconstruye la línea de comandos que nmap.PortScanner.scan() lanzaría
    internamente. Hace falta porque ese método es bloqueante y no expone el
    subprocess.Popen que crea - no hay forma de matarlo desde fuera si el
    usuario pulsa "Parar" a medio escaneo, así que lanzamos el proceso
    nosotros mismos para quedarnos con esa referencia.

    La XML va a un archivo (-oX archivo_xml), no a stdout: stdout se deja
    libre para leer en vivo la salida normal de nmap (-v) línea a línea,
    que es de donde sale el "Registro de escaneo" con los hosts según
    nmap los va terminando (ver _ejecutar_proceso_nmap). No se puede tener
    a la vez XML y progreso verbose sobre el mismo stream.

    La ruta del binario se resuelve con nmap.PortScanner()._nmap_path (la
    misma búsqueda que ya hace python-nmap internamente en
    descubrir_hosts_vivos, fase 1) en vez de shutil.which("nmap"): esa
    alternativa mira solo el PATH y podía no encontrar el binario aunque la
    fase 1 sí lo hubiera hecho, dejando la fase 2 rota de forma inconsistente."""
    try:
        nmap_path = nmap.PortScanner()._nmap_path
    except nmap.PortScannerError as e:
        raise ScannerError(f"Error de nmap (¿ejecutas con sudo?): {e}") from e
    return [
        nmap_path, "-v", "-oX", archivo_xml,
        *shlex.split(hosts), "-p", ports, *shlex.split(arguments),
    ]


def _matar_si_sigue_vivo(proceso: subprocess.Popen):
    """Handler de atexit: si el proceso de Streamlit se cierra (Ctrl+C)
    mientras un escaneo sigue en marcha, intenta matar el nmap huérfano en
    vez de dejarlo corriendo en segundo plano. No cubre un kill -9/taskkill
    /F del propio proceso de Streamlit - ningún código de aplicación puede
    reaccionar a eso."""
    with contextlib.suppress(OSError):
        proceso.terminate()


_RE_HOST_COMPLETADO = re.compile(r"^Nmap scan report for (\S+)")


def _ejecutar_proceso_nmap(comando: list, contenedor: dict):
    """Lanza nmap como subprocess y va rellenando `contenedor` (dict
    compartido con el hilo que lo lanzó) según el propio nmap va soltando
    eventos reales por su salida verbose (-v), en vez de esperar bloqueado
    a que el proceso entero termine (.communicate()) - así _fragmento_progreso
    puede pintar un "Registro de escaneo" en vivo con los hosts que nmap ya
    ha terminado, no un progreso inventado.

    "Nmap scan report for X" es la línea que nmap imprime al terminar de
    escanear ese host - no hay forma más fina de saber en qué anda nmap
    sin parsear su salida línea a línea (la XML, que si tiene el detalle
    completo, solo se escribe cuando el proceso entero acaba).

    stderr se combina con stdout (STDOUT en vez de un PIPE aparte) para no
    arriesgarse a un deadlock: si nadie lee stderr y nmap escribe ahí lo
    bastante como para llenar el buffer del pipe del SO, el proceso se
    queda colgado esperando a que alguien lo vacíe - aquí solo leemos
    stdout en el bucle de abajo.

    Cualquier fallo se guarda en contenedor["error"] en vez de dejar que la
    excepción tire el hilo en silencio: antes, si subprocess.Popen fallaba
    (ruta inválida, permisos...), esto se quedaba sin marcar y reventaba
    más adelante con una excepción sin controlar."""
    contenedor.setdefault("log", [])
    try:
        proceso = subprocess.Popen(
            comando, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
        contenedor["proceso"] = proceso
        atexit.register(_matar_si_sigue_vivo, proceso)
        for linea in proceso.stdout:
            coincidencia = _RE_HOST_COMPLETADO.match(linea)
            if coincidencia:
                contenedor["log"].append(coincidencia.group(1))
        proceso.wait()
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


def _compactar_html(html: str) -> str:
    """st.markdown trata el HTML como Markdown antes de dejar pasar las
    etiquetas: un bloque <div>/<tr>/... termina en la primera línea en
    blanco, y lo que venga después con 4+ espacios de indentación se
    interpreta como un bloque de código en vez de renderizarse. Cualquier
    función que construya HTML uniendo fragmentos multilínea indentados
    (uno por fila/tarjeta, típicamente dentro de un bucle) puede acabar
    con líneas en blanco entre fragmentos sin querer - colapsar todo el
    whitespace a un solo espacio lo evita sin cambiar el HTML resultante."""
    return " ".join(html.split())


FILAS_POR_PAGINA = 10


def _total_paginas(n: int, por_pagina: int = FILAS_POR_PAGINA) -> int:
    """Nº de páginas necesarias para n hosts - mínimo 1 aunque n sea 0, así
    la UI de paginación (Página 1 de 1) no tiene que tratar el caso vacío
    aparte."""
    return max(1, math.ceil(n / por_pagina))


def _pagina_de_resultados(resultados: dict, pagina: int, por_pagina: int = FILAS_POR_PAGINA) -> dict:
    """Subconjunto de `resultados` para la página `pagina` (1-indexada),
    ordenados por IP - mismo orden que ya usaba la tabla completa, para que
    paginar no cambie qué host sale en qué posición relativa."""
    items = sorted(resultados.items())
    inicio = (pagina - 1) * por_pagina
    return dict(items[inicio:inicio + por_pagina])


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
            chips_puertos = '<span class="muted mono" style="font-size:12.5px;">—</span>'

        alerta_icono = "" if not tiene_alertas else (
            '<svg viewBox="0 0 20 20" width="14" height="14" fill="none" stroke="#ff5c5c" '
            'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M10 2.8l8 14H2l8-14z"/><path d="M10 8v3.2"/></svg>'
        )

        filas.append(f"""
        <tr{' class="sensitive"' if tiene_alertas else ""}>
          <td><div class="mono" style="font-weight:500; font-size:14.5px;">{ip}</div>
              <div class="muted mono" style="font-size:12.5px;">{datos.get("hostname") or ""}</div></td>
          <td><div class="row-cat"><span class="cat-dot" style="background:{color}"></span>{categoria}</div></td>
          <td class="mono muted">{datos.get("so") or "desconocido"}</td>
          <td>{chips_puertos}</td>
          <td>{alerta_icono}</td>
        </tr>
        """)

    return _compactar_html(f"""
<table class="inv-table">
  <thead><tr><th>Host</th><th>Categoría</th><th>SO</th><th>Puertos</th><th></th></tr></thead>
  <tbody>{"".join(filas)}</tbody>
</table>
""")


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

    return _compactar_html(f'<div class="chg-body">{"".join(items)}</div>')


_ICONO_HUB = {"code": "", "face": "'Font Awesome 5 Free'", "weight": "900"}
NODE_R, MARGEN_TOPOLOGIA = 24, 90
ALTURA_VIEWPORT_TOPOLOGIA = 540


def _css_topologia(accent: str) -> str:
    """CSS del documento HTML autocontenido del panel de topología (ver
    _generar_topologia_html) - el iframe no hereda el <head> de la página,
    así que estas reglas viven aparte de _generar_css(). #topo-viewport es
    la "ventana" visible (tamaño fijo, overflow oculto); #topo-canvas es el
    lienzo de tamaño real del grafo al que el script de pan/zoom le aplica
    un transform - por eso hub/nodos usan posiciones en px absolutos, no
    en porcentaje como en la primera versión (más simple y es justo lo que
    necesita un transform de canvas)."""
    return f"""
html, body {{ margin: 0; padding: 0; background: #091018; overflow: hidden; }}
* {{ box-sizing: border-box; }}
.mono {{ font-family: 'JetBrains Mono', monospace; }}
.muted {{ color: #7C8A9A; }}

.topo-card {{
    border-radius: 16px; border: 1px solid rgba(227,232,238,0.08);
    background: rgba(17,25,33,0.75); overflow: hidden;
}}
#topo-viewport {{
    position: relative; width: 100%; height: {ALTURA_VIEWPORT_TOPOLOGIA}px;
    overflow: hidden; cursor: grab;
    background-color: #091018;
    background-image: radial-gradient(rgba(227,232,238,0.08) 1px, transparent 1px);
    background-size: 26px 26px;
}}
#topo-canvas {{ position: absolute; top: 0; left: 0; transform-origin: 0 0; }}
.topo-svg {{ position: absolute; inset: 0; width: 100%; height: 100%; }}
.topo-hub {{
    position: absolute; transform: translate(-50%, -50%);
    width: 84px; height: 84px;
    border-radius: 22px; background: {accent}1a; border: 1.5px solid {accent}80;
    display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 4px;
    font-size: 26px; color: {accent};
}}
.topo-hub-label {{ font-size: 11px; font-weight: 600; letter-spacing: 0.02em; color: {accent}; }}
.topo-node-wrap {{ position: absolute; transform: translate(-50%, -50%); text-align: center; }}
.topo-node {{
    width: 44px; height: 44px; border-radius: 50%; background: #0d151d;
    border: 2px solid; display: flex; align-items: center;
    justify-content: center; font-size: 16px; margin: 0 auto; position: relative;
}}
.topo-node-label {{ margin-top: 5px; font-size: 10px; color: #B8C2CC; white-space: nowrap; }}
.topo-alert-ring {{
    position: absolute; top: 50%; left: 50%; width: 54px; height: 54px;
    transform: translate(-50%, -50%); border-radius: 50%; border: 2px solid #ff5c5c;
    animation: alertpulse 1.8s ease-in-out infinite; pointer-events: none;
}}
@keyframes alertpulse {{ 0%,100% {{ opacity:.7; }} 50% {{ opacity:.15; }} }}
.topo-alert-badge {{
    position: absolute; top: -3px; right: -3px; width: 15px; height: 15px;
    border: 1.5px solid #091018;
    border-radius: 50%; background: #ff5c5c; color: #091018;
    display: flex; align-items: center; justify-content: center;
    font-size: 9px; font-weight: 700;
}}
.topo-node-wrap .tooltip-card {{ display: none; }}
.topo-node-wrap:hover .tooltip-card {{ display: block; }}
.tooltip-card {{
    position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%);
    margin-bottom: 10px; padding: 10px 12px; border-radius: 10px; background: #0d151d;
    border: 1px solid rgba(255,92,92,0.4); font-size: 10.5px; width: 190px;
    box-shadow: 0 12px 28px rgba(0,0,0,0.4); z-index: 5; text-align: left;
}}
.tooltip-title {{ font-weight: 600; margin-bottom: 3px; font-family: 'JetBrains Mono', monospace; }}
.tooltip-alert {{ color: #ff8a80; margin-top: 5px; }}
.topo-hint {{ position: absolute; left: 12px; bottom: 8px; font-size: 10px; color: #4A5A6A; }}

.legend-bar {{ display: flex; flex-wrap: wrap; gap: 8px 20px; padding: 14px 18px; }}
.legend-item {{ display: flex; align-items: center; gap: 6px; font-size: 10.5px; color: #B8C2CC; }}
.legend-dot {{ width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; display: inline-block; }}
"""


def _generar_leyenda_topologia_html() -> str:
    """Leyenda horizontal bajo el grafo, reutilizando ICONOS_POR_CATEGORIA -
    misma fuente de verdad que la leyenda del HTML de export.py, pero con
    el estilo de barra horizontal del mockup en vez del panel flotante."""
    items = "".join(
        f'<div class="legend-item mono">'
        f'<span class="legend-dot" style="background:{icono["color"]}"></span>{icono["nombre"]}</div>'
        for icono in ICONOS_POR_CATEGORIA.values()
    )
    return f'<div class="legend-bar">{items}</div>'


def _generar_topologia_html(resultados: dict, rango: str, accent: str) -> str:
    """Documento HTML autocontenido (doctype/head/body/script) con el panel
    de topología dibujado a mano - pensado para st.components.v1.html, no
    para st.markdown.

    Va en un iframe (no inline en la página, como el resto del panel de
    resultados) por dos motivos: (1) st.markdown trata el contenido como
    Markdown antes de dejar pasar el HTML, y con muchos nodos aparecían
    líneas en blanco entre ellos que cortaban el bloque de HTML "en crudo"
    a medias; (2) st.markdown ignora cualquier <script>, y sin JS de
    verdad no hay forma de dar zoom/arrastre - imprescindible en redes con
    muchos hosts vivos, donde un layout estático siempre amontona algo
    (ver commits anteriores intentando arreglarlo solo a base de más
    espaciado). Al vivir en su propio documento, se importan aquí mismo
    las fuentes/Font Awesome que en el resto de la página inyecta
    _inyectar_estilos() - el iframe no hereda el <head> de la página.

    Las posiciones reutilizan export.posiciones_circulares - la misma
    función que ordena el HTML que exportar_html() genera para el CLI, así
    no hay dos algoritmos de layout distintos que mantener sincronizados.

    Compromiso deliberado frente al mockup original: los iconos se dibujan
    con los glyphs de Font Awesome de ICONOS_POR_CATEGORIA (los mismos que
    ya usa export.py) en vez de redibujar a mano 10 iconos SVG nuevos -
    misma fuente de verdad, muchísimo menos código nuevo."""
    hosts = sorted(resultados.items())
    posiciones = posiciones_circulares(len(hosts))

    radio_max = max((math.hypot(x, y) for x, y in posiciones), default=0)
    mitad = radio_max + NODE_R + MARGEN_TOPOLOGIA
    ancho = alto = mitad * 2
    cx = cy = mitad

    radios_anillo = sorted({round(math.hypot(x, y)) for x, y in posiciones})
    anillos_svg = "".join(
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{accent}1c" '
        f'stroke-width="1" stroke-dasharray="3 6"/>'
        for r in radios_anillo
    )

    # Cada conexión son dos trazos superpuestos, no uno solo: uno largo y
    # tenue (todo el trayecto) + uno corto y más marcado junto al hub - da
    # la sensación de profundidad/degradado del mockup sin necesitar un
    # gradiente SVG de verdad.
    lineas_svg = "".join(
        (
            f'<line x1="{cx}" y1="{cy}" x2="{cx + x:.1f}" y2="{cy + y:.1f}" '
            f'stroke="{"rgba(255,92,92,0.35)" if datos.get("alertas") else "rgba(227,232,238,0.14)"}" '
            f'stroke-width="1.3"/>'
            f'<line x1="{cx}" y1="{cy}" x2="{cx + x * 0.42:.1f}" y2="{cy + y * 0.42:.1f}" '
            f'stroke="{"#ff5c5c" if datos.get("alertas") else accent}" stroke-opacity="0.55" '
            f'stroke-width="2.4" stroke-linecap="round"/>'
        )
        for (_, datos), (x, y) in zip(hosts, posiciones)
    )

    nodos_html = []
    for (ip, datos), (x, y) in zip(hosts, posiciones):
        categoria = datos.get("categoria", "desconocido")
        icono = ICONOS_POR_CATEGORIA.get(categoria, ICONOS_POR_CATEGORIA["desconocido"])
        alertas = datos.get("alertas", [])
        color = "#ff5c5c" if alertas else icono["color"]
        sub = " · ".join(filter(None, [datos.get("hostname"), datos.get("vendor"), categoria]))

        # Con muchos hosts vivos, las etiquetas permanentes con hostname +
        # fabricante se amontonaban - ahora solo la IP queda visible bajo
        # el nodo y el resto se mueve al tooltip al pasar el ratón, en
        # todos los nodos (antes solo en los que tenían alerta). El zoom
        # (ver JS más abajo) es lo que de verdad soluciona el amontonado
        # en redes grandes, no el espaciado.
        if alertas:
            primera = alertas[0]
            alerta_extra = '<div class="topo-alert-ring"></div><div class="topo-alert-badge">!</div>'
            alerta_linea = f'<div class="tooltip-alert">⚠ {primera["puerto"]} · {primera["motivo"]}</div>'
            borde_tooltip, color_titulo = "rgba(255,92,92,0.4)", "#ff8a80"
        else:
            alerta_extra = alerta_linea = ""
            borde_tooltip, color_titulo = "rgba(227,232,238,0.14)", "#E3E8EE"

        nodos_html.append(f"""
        <div class="topo-node-wrap" style="left:{cx + x:.1f}px; top:{cy + y:.1f}px;">
          <div class="topo-node" style="border-color:{color};">
            <span style="font-family:{icono["face"]}; font-weight:{icono["weight"]}; color:{color};">
              {icono["code"]}
            </span>
            {alerta_extra}
          </div>
          <div class="topo-node-label mono">{ip}</div>
          <div class="tooltip-card" style="border-color:{borde_tooltip};">
            <div class="tooltip-title" style="color:{color_titulo};">{ip}</div>
            <div class="muted mono">{sub}</div>
            {alerta_linea}
          </div>
        </div>
        """)

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<link rel="stylesheet"
  href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&display=swap">
{CDN_FONTAWESOME}
<style>{_css_topologia(accent)}</style>
</head>
<body>
<div class="topo-card">
  <div id="topo-viewport">
    <div id="topo-canvas" style="width:{ancho}px; height:{alto}px;">
      <svg viewBox="0 0 {ancho} {alto}" class="topo-svg">{anillos_svg}{lineas_svg}</svg>
      <div class="topo-hub" style="left:{cx}px; top:{cy}px;">
        <span style="font-family:{_ICONO_HUB["face"]}; font-weight:{_ICONO_HUB["weight"]};">
          {_ICONO_HUB["code"]}
        </span>
        <div class="topo-hub-label mono">{"/" + rango.rsplit("/", 1)[-1] if "/" in rango else rango}</div>
      </div>
      {"".join(nodos_html)}
    </div>
    <div class="topo-hint mono">rueda = zoom · arrastra = mover · doble clic = restablecer</div>
  </div>
  {_generar_leyenda_topologia_html()}
</div>
<script>
(function() {{
  var viewport = document.getElementById('topo-viewport');
  var canvas = document.getElementById('topo-canvas');
  var ancho = {ancho}, alto = {alto};
  var scale = 1, tx = 0, ty = 0;
  var dragging = false, moved = false, lastX = 0, lastY = 0;

  function aplicar() {{
    canvas.style.transform = 'translate(' + tx + 'px,' + ty + 'px) scale(' + scale + ')';
  }}
  function ajustar() {{
    var vw = viewport.clientWidth, vh = viewport.clientHeight;
    scale = Math.max(0.15, Math.min(vw / ancho, vh / alto, 1.4));
    tx = (vw - ancho * scale) / 2;
    ty = (vh - alto * scale) / 2;
    aplicar();
  }}
  viewport.addEventListener('wheel', function(e) {{
    e.preventDefault();
    scale = Math.min(4, Math.max(0.15, scale * (e.deltaY < 0 ? 1.12 : 0.89)));
    aplicar();
  }}, {{passive: false}});
  viewport.addEventListener('mousedown', function(e) {{
    dragging = true; moved = false; lastX = e.clientX; lastY = e.clientY;
    viewport.style.cursor = 'grabbing';
  }});
  window.addEventListener('mousemove', function(e) {{
    if (!dragging) return;
    tx += e.clientX - lastX; ty += e.clientY - lastY;
    lastX = e.clientX; lastY = e.clientY; moved = true;
    aplicar();
  }});
  window.addEventListener('mouseup', function() {{
    dragging = false; viewport.style.cursor = 'grab';
  }});
  viewport.addEventListener('dblclick', ajustar);
  ajustar();
}})();
</script>
</body>
</html>
"""


def _mostrar_resultado(resultado: dict, accent: str):
    resultados = resultado["resultados"]
    if not resultados:
        st.warning("No se detectaron hosts. Revisa el rango y los permisos (prueba con sudo).")
        return

    diff = resultado["diff"]
    st.markdown(_generar_kpis_html(resultados, resultado["rango"], diff, accent), unsafe_allow_html=True)

    st.subheader("Topología")
    st.components.v1.html(
        _generar_topologia_html(resultados, resultado["rango"], accent),
        height=ALTURA_VIEWPORT_TOPOLOGIA + 90,
        scrolling=False,
    )

    st.subheader("Inventario")
    total_paginas = _total_paginas(len(resultados))
    pagina_actual = min(st.session_state.get("pagina_inventario", 1), total_paginas)
    st.markdown(
        _generar_tabla_inventario_html(_pagina_de_resultados(resultados, pagina_actual)),
        unsafe_allow_html=True,
    )

    if total_paginas > 1:
        col_prev, col_info, col_next = st.columns([1, 2, 1])
        if col_prev.button("< Anterior", disabled=pagina_actual <= 1, use_container_width=True):
            st.session_state.pagina_inventario = pagina_actual - 1
            st.rerun()
        col_info.markdown(
            f'<div class="mono muted" style="text-align:center; padding-top:8px; font-size:12px;">'
            f'Página {pagina_actual} de {total_paginas} · {len(resultados)} hosts</div>',
            unsafe_allow_html=True,
        )
        if col_next.button("Siguiente >", disabled=pagina_actual >= total_paginas, use_container_width=True):
            st.session_state.pagina_inventario = pagina_actual + 1
            st.rerun()
    else:
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
                log=st.session_state.contenedor.get("log", []),
            ),
            unsafe_allow_html=True,
        )
        return

    contenedor = st.session_state.contenedor
    parametros = st.session_state.parametros_pendientes
    st.session_state.estado = "idle"
    try:
        if st.session_state.cancelado:
            st.session_state.mensaje = ("info", "Escaneo cancelado.")
            st.session_state.resultado = None
        elif contenedor.get("error"):
            st.session_state.mensaje = ("error", f"No se pudo lanzar nmap: {contenedor['error']}")
            st.session_state.resultado = None
        else:
            try:
                with open(contenedor["archivo_xml"], "rb") as f:
                    resultados = _procesar_salida_nmap(f.read())
            except (OSError, nmap.PortScannerError) as e:
                st.session_state.mensaje = ("error", f"Error de nmap: {e}")
                st.session_state.resultado = None
            else:
                st.session_state.resultado = _finalizar_resultados(
                    resultados, parametros["rango"], parametros["guardar_historial"]
                )
                # Sin esto, un escaneo nuevo con menos hosts que el anterior
                # podía dejar pagina_inventario apuntando a una página que ya
                # no existe (tabla vacía hasta que el usuario pulsara "Anterior").
                st.session_state.pagina_inventario = 1
    finally:
        # La XML temporal (creada antes de lanzar nmap, ver main()) ya no
        # hace falta pase lo que pase - igual que los .html/.csv temporales
        # de _finalizar_resultados/_generar_csv_bytes, sin este cleanup se
        # queda huérfana en el directorio temporal del sistema para siempre.
        with contextlib.suppress(OSError):
            os.remove(contenedor["archivo_xml"])
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
[data-testid="stHeader"] {{
    display: none;
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
    border-radius: 9px;
    border-color: rgba(227,232,238,0.12);
    font-family: 'JetBrains Mono', monospace;
    font-weight: 500;
    font-size: 12.5px;
    color: #B8C2CC;
}}
[data-testid="stTextInputRootElement"] {{
    border-radius: 9px !important;
}}
.st-key-detectar_red button {{
    justify-content: flex-start !important;
    text-align: left !important;
    white-space: normal !important;
    line-height: 1.4;
    height: auto !important;
    min-height: 48px;
    padding: 12px 14px !important;
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

.topbar {{
    width: 100%; box-sizing: border-box;
    min-height: 64px; display: flex; align-items: center; justify-content: space-between;
    flex-wrap: wrap; gap: 10px;
    padding: 14px 24px; background: #111921;
    border: 1px solid rgba(227,232,238,0.08); border-radius: 14px;
    margin-bottom: 22px;
}}
.topbar-brand {{ display: flex; align-items: center; gap: 12px; }}
.topbar-brand-text {{ display: flex; flex-direction: column; gap: 2px; }}
.topbar-title {{
    font-size: 15px !important; font-weight: 700 !important; letter-spacing: 0.01em; margin: 0 !important;
    font-family: 'Space Grotesk', sans-serif !important; color: #E3E8EE !important;
    text-transform: uppercase; line-height: 1.3 !important;
}}
.topbar-subtitle {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 10.5px; letter-spacing: 0.08em; text-transform: uppercase; color: #7C8A9A;
}}
.topbar-right {{ display: flex; align-items: center; gap: 12px; }}
.legal-pill {{
    display: flex; align-items: center; gap: 7px;
    padding: 6px 12px; border-radius: 20px;
    border: 1px solid rgba(227,232,238,0.10);
    color: #7C8A9A; font-size: 11.5px; font-family: 'JetBrains Mono', monospace;
}}
.topbar-version {{ font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #4A5A6A; }}

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

.phase-row {{ display: flex; align-items: center; gap: 0; margin-top: 14px; }}
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

.stats-row {{ display: flex; gap: 14px; margin-top: 18px; }}
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
    margin-top: 18px;
}}
.terminal-head {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }}
.terminal-title {{ font-size: 11.5px; letter-spacing: 0.08em; text-transform: uppercase; color: #5A6B7C; }}
.dots {{ display: flex; gap: 6px; }}
.dots span {{ width: 8px; height: 8px; border-radius: 50%; background: rgba(227,232,238,0.15); }}
.log-lines {{ max-height: 220px; overflow-y: auto; }}
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

.kpi-row {{ display: flex; gap: 16px; margin-top: 14px; }}
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
    text-align: left; font-size: 11.5px; letter-spacing: 0.06em; text-transform: uppercase;
    color: #5A6B7C; font-weight: 600; padding: 12px 14px;
    border-bottom: 1px solid rgba(227,232,238,0.07);
}}
table.inv-table td {{
    padding: 13px 14px; font-size: 14.5px; border-bottom: 1px solid rgba(227,232,238,0.05);
    vertical-align: middle;
}}
table.inv-table tr.sensitive td:first-child {{ box-shadow: inset 3px 0 0 #ff5c5c; }}
.row-cat {{ display: flex; align-items: center; gap: 8px; }}
.cat-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; display: inline-block; }}
.port-chip {{
    display: inline-block; font-size: 12px; padding: 3px 8px; border-radius: 5px;
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


def _generar_topbar_html(version: str, accent: str) -> str:
    """Barra superior completa (marca a la izquierda, aviso legal + versión
    a la derecha) que sustituye a st.title()/st.caption() - se estira a
    ancho completo de la ventana con el truco left:50%/-50vw (funciona sin
    importar el padding real del bloque de contenido de Streamlit, que
    puede variar). Aparte en su propia función para poder comprobar el
    contenido sin renderizar Streamlit."""
    return f"""
<div class="topbar">
  <div class="topbar-brand">
    <svg viewBox="0 0 24 24" width="30" height="30" fill="none">
      <circle cx="12" cy="12" r="9" stroke="{accent}" stroke-width="1.3" opacity="0.35"/>
      <circle cx="12" cy="12" r="5.5" stroke="{accent}" stroke-width="1.3" opacity="0.65"/>
      <circle cx="12" cy="12" r="2" fill="{accent}"/>
      <circle cx="19" cy="8" r="1.5" fill="{accent}"/>
    </svg>
    <div class="topbar-brand-text">
      <div class="topbar-title">Network Topology Scanner</div>
      <div class="topbar-subtitle">Command Center</div>
    </div>
  </div>
  <div class="topbar-right">
    <div class="legal-pill">
      <svg viewBox="0 0 20 20" width="13" height="13" fill="none" stroke="currentColor"
           stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
        <path d="M10 2.5l6 2.2v4.6c0 4-2.6 6.9-6 8.2-3.4-1.3-6-4.2-6-8.2V4.7l6-2.2z"/>
      </svg>
      Solo redes propias o autorizadas
    </div>
    <div class="topbar-version">v{version}</div>
  </div>
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
    _generar_topbar_html."""
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
    return _compactar_html(f'<div class="history-list">{"".join(filas)}</div>')


def _formatear_tiempo_transcurrido(segundos: float) -> str:
    """mm:ss para el contador de tiempo transcurrido del panel de progreso."""
    minutos, segs = divmod(int(segundos), 60)
    return f"{minutos:02d}:{segs:02d}"


def _generar_progreso_html(rango: str, hosts_vivos: int, argumentos_nmap: str, tiempo: str, log: list) -> str:
    """HTML del panel de progreso (sustituye al st.info() de una sola línea
    de antes). `log` es la lista de IPs que _ejecutar_proceso_nmap ya ha
    visto terminar (eventos reales de la salida verbose de nmap, "Nmap
    scan report for X") - no se fabrica nada aquí: si `log` está vacío
    (nmap todavía no ha terminado ningún host) solo se muestra el cursor
    parpadeando, sin listar hosts que no se han visto de verdad. Fabricante/
    categoría/alertas por host no se pueden sacar de forma fiable de la
    salida verbose de nmap (solo de la XML final, cuando el proceso entero
    termina), así que no aparecen aquí - eso ya se ve en el resultado."""
    lineas_log = "".join(
        f'<div class="log-line"><span class="mono">{ip}</span>'
        f'<span class="muted mono">detectado</span></div>'
        for ip in log[-30:]
    )
    html = f"""
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
  <div class="mono log-lines" style="display:flex; flex-direction:column;">
    <div class="log-line cmd">&gt; descubrir_hosts_vivos({rango})</div>
    <div class="log-line" style="color:#B8C2CC; padding-left:18px;">ping scan completo — {hosts_vivos} hosts vivos</div>
    <div class="log-line cmd" style="margin-top:6px;">&gt; nmap {argumentos_nmap} -p ...</div>
    {lineas_log}
    <div class="log-line" style="color:#7C8A9A;">
      escaneando puertos y servicios<span class="cursor"></span>
    </div>
  </div>
</div>
"""
    # Mismo problema que _generar_topologia_html/_generar_historial_html:
    # st.markdown trata esto como Markdown antes de dejar pasar el HTML, y
    # cuando `log` está vacío la línea "{lineas_log}" queda en blanco -
    # corta el bloque de HTML "en crudo" a medias justo antes del cursor
    # parpadeante, que se mostraba como texto/código en vez de renderizarse.
    return _compactar_html(html)


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
    main() pueda reutilizarlo en el estado vacío sin volver a resolverlo.

    Font Awesome (CDN_FONTAWESOME) NO se inyecta aquí: solo lo necesita el
    panel de topología, que vive en su propio documento HTML autocontenido
    (ver _generar_topologia_html/_css_topologia) - nada más en esta página
    usa esos glyphs."""
    accent = st.get_option("theme.primaryColor") or "#00D2D3"
    st.markdown(_generar_css(accent), unsafe_allow_html=True)
    st.markdown(_generar_topbar_html(__version__, accent), unsafe_allow_html=True)
    return accent


def main():
    st.set_page_config(page_title="Network Topology Scanner", page_icon="🌐", layout="wide")
    accent = _inyectar_estilos()

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
        detectar = st.button(
            "Detectar mi red automáticamente",
            key="detectar_red",
            icon=":material/gps_fixed:",
            disabled=escaneando,
            use_container_width=True,
        )

        st.divider()
        st.markdown('<div class="section-eyebrow">Opciones</div>', unsafe_allow_html=True)
        rapido = st.toggle(
            "Escaneo rápido", value=True, disabled=escaneando, help="-T4, sin detección de SO"
        )
        con_so = st.toggle("Detectar SO", disabled=escaneando, help="-O --osscan-guess, más lento")
        guardar_historial = st.toggle(
            "Guardar en historial",
            value=True,
            disabled=escaneando,
            help="Compara con el escaneo anterior",
        )

        st.divider()
        enviado = st.button("▶ Escanear", disabled=escaneando, type="primary", use_container_width=True)
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
                with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
                    archivo_xml = f.name
                try:
                    comando = _construir_comando_nmap(
                        " ".join(vivos), PUERTOS_POR_DEFECTO, argumentos_nmap, archivo_xml
                    )
                except ScannerError as e:
                    st.error(str(e))
                    os.remove(archivo_xml)
                else:
                    contenedor = {"proceso": None, "log": [], "archivo_xml": archivo_xml}
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
