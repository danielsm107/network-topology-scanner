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
import os
import shlex
import socket
import subprocess
import tempfile
import threading
from typing import Optional

try:
    import streamlit as st
except ImportError as e:
    raise ImportError(
        "Falta streamlit para la interfaz web. Instala con: pip install \"topology-scanner[web]\""
    ) from e

import nmap

# Imports absolutos (no relativos): streamlit run ejecuta este archivo como
# script suelto, sin contexto de paquete, así que "from .scanner import..."
# falla con ImportError. Requiere que topology_scanner esté instalado
# (pip install -e .) o en el PYTHONPATH.
from topology_scanner.scanner import (
    descubrir_hosts_vivos, parsear_host, ScannerError, DEFAULT_NMAP_ARGS, PUERTOS_POR_DEFECTO,
)
from topology_scanner.graph import construir_grafo
from topology_scanner.export import exportar_html, exportar_csv
from topology_scanner.history import registrar_y_comparar, HistoryError, hay_cambios


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
    return [nmap_path, "-oX", "-"] + shlex.split(hosts) + ["-p", ports] + shlex.split(arguments)


def _matar_si_sigue_vivo(proceso: subprocess.Popen):
    """Handler de atexit: si el proceso de Streamlit se cierra (Ctrl+C)
    mientras un escaneo sigue en marcha, intenta matar el nmap huérfano en
    vez de dejarlo corriendo en segundo plano. No cubre un kill -9/taskkill
    /F del propio proceso de Streamlit - ningún código de aplicación puede
    reaccionar a eso."""
    try:
        proceso.terminate()
    except OSError:
        pass


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
    finally:
        contenedor["terminado"] = True


def _procesar_salida_nmap(salida_xml: bytes) -> dict:
    """A partir del XML crudo que escupe nmap (-oX -), construye el mismo
    dict {ip: {...}} que produce scanner.escanear_red(), reutilizando
    parsear_host. Puede lanzar nmap.PortScannerError si el XML es inválido
    (p.ej. porque el proceso se mató a medias con "Parar escaneo")."""
    nm = nmap.PortScanner()
    nm.analyse_nmap_xml_scan(nmap_xml_output=salida_xml)
    return {host: parsear_host(nm[host]) for host in nm.all_hosts()}


def _finalizar_resultados(resultados: dict, rango: str, guardar_historial: bool) -> dict:
    """A partir de resultados ya escaneados (formato de scanner.py), hace
    historial + grafo + export HTML. No usa sys.exit ni deja escapar
    excepciones de historial/export - un fallo aquí no debe tirar el
    servidor entero, la UI decide cómo mostrarlo.

    Devuelve: {"resultados": dict, "html": str|None, "diff": dict|None}
    """
    if not resultados:
        return {"resultados": {}, "html": None, "diff": None}

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

    return {"resultados": resultados, "html": html, "diff": diff}


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


def _mostrar_resultado(resultado: dict):
    resultados = resultado["resultados"]
    if not resultados:
        st.warning("No se detectaron hosts. Revisa el rango y los permisos (prueba con sudo).")
        return

    alertas_totales = sum(len(d.get("alertas", [])) for d in resultados.values())
    col1, col2 = st.columns(2)
    col1.metric("Hosts detectados", len(resultados))
    col2.metric("Con puertos sensibles abiertos", alertas_totales)

    diff = resultado["diff"]
    if diff and not diff["primera_vez"]:
        hay_cambios_reales = hay_cambios(diff)
        with st.expander("Cambios respecto al escaneo anterior", expanded=hay_cambios_reales):
            if diff["hosts_nuevos"]:
                st.write("**Hosts nuevos:**", ", ".join(diff["hosts_nuevos"]))
            if diff["hosts_caidos"]:
                st.write("**Hosts caídos:**", ", ".join(diff["hosts_caidos"]))
            for ip, cambios in diff["puertos_cambiados"].items():
                if cambios["nuevos"]:
                    st.write(f"**[{ip}]** puertos nuevos:", ", ".join(map(str, cambios["nuevos"])))
                for sensible in cambios.get("nuevos_sensibles", []):
                    st.warning(f"[{ip}] puerto nuevo y sensible: {sensible['puerto']} ({sensible['motivo']})")
            if not hay_cambios_reales:
                st.write("Sin cambios respecto al escaneo anterior.")

    st.dataframe(_filas_para_tabla(resultados), use_container_width=True)

    st.download_button(
        "Descargar inventario CSV", _generar_csv_bytes(resultados),
        file_name="inventario.csv", mime="text/csv",
    )

    st.components.v1.html(resultado["html"], height=650, scrolling=True)


@st.fragment(run_every="1s")
def _fragmento_progreso():
    """Solo este trozo de la página se refresca cada segundo (no la página
    entera, así no parpadean los botones/campos) mientras el hilo de nmap
    sigue vivo. Cuando termina (solo o porque "Parar escaneo" mató el
    proceso), guarda el resultado en session_state y fuerza un rerun
    completo (st.rerun() por defecto sale del fragmento) para volver a
    dejar los botones activos y mostrar el resultado."""
    if st.session_state.hilo.is_alive():
        rango_en_curso = st.session_state.parametros_pendientes["rango"]
        st.info(f'Escaneando {rango_en_curso}... (pulsa "Parar escaneo" para cancelar)')
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


def main():
    st.set_page_config(page_title="Network Topology Scanner", layout="wide")
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

    rango = st.text_input(
        "Rango de red (CIDR)",
        value=st.session_state.rango_detectado,
        placeholder="192.168.1.0/24",
        disabled=escaneando,
    )
    col1, col2, col3 = st.columns(3)
    rapido = col1.checkbox("Escaneo rápido", value=True, disabled=escaneando)
    con_so = col2.checkbox("Detectar SO", disabled=escaneando)
    guardar_historial = col3.checkbox("Guardar en historial", value=True, disabled=escaneando)

    col_a, col_b, col_c = st.columns(3)
    enviado = col_a.button("Escanear", disabled=escaneando)
    parar = col_b.button("⏹ Parar escaneo", disabled=not escaneando)
    detectar = col_c.button("📍 Detectar mi red", disabled=escaneando)

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
                    contenedor = {"proceso": None, "salida": None, "terminado": False}
                    hilo = threading.Thread(target=_ejecutar_proceso_nmap, args=(comando, contenedor), daemon=True)
                    hilo.start()
                    st.session_state.estado = "escaneando"
                    st.session_state.hilo = hilo
                    st.session_state.contenedor = contenedor
                    st.session_state.parametros_pendientes = {"rango": rango, "guardar_historial": guardar_historial}
                    st.session_state.cancelado = False
                    st.rerun()

    if parar and escaneando:
        proceso = st.session_state.contenedor.get("proceso")
        if proceso is not None:
            proceso.terminate()
        st.session_state.cancelado = True

    if escaneando:
        _fragmento_progreso()

    if st.session_state.resultado:
        _mostrar_resultado(st.session_state.resultado)


def lanzar():
    """Punto de entrada de `topology-scanner-web`: lanza este script con el
    runtime de Streamlit (equivalente a `streamlit run webapp.py`)."""
    import sys

    from streamlit.web import cli as stcli

    sys.argv = ["streamlit", "run", __file__]
    sys.exit(stcli.main())


if __name__ == "__main__":
    main()
