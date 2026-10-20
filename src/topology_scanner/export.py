"""
export.py
---------
Convierte el grafo/resultados en salidas visibles: HTML interactivo (pyvis)
o informe de texto plano por consola.
"""

import csv
import logging
import math
from datetime import datetime

import networkx as nx

from .classifier import ICONOS_POR_CATEGORIA, icono_para_categoria
from .history import hay_cambios


class ExportError(RuntimeError):
    """Error al generar la salida: dependencia faltante, fallo de escritura,
    etc. Quien llame decide qué hacer (cli.py la captura y termina el
    programa con un mensaje claro)."""


try:
    from pyvis.network import Network
except ImportError as e:
    raise ExportError("Falta pyvis. Instala con: pip install pyvis") from e

log = logging.getLogger("topology_scanner")

CDN_FONTAWESOME = (
    '<link rel="stylesheet" '
    'href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">'
)

# pyvis fija #mynetwork a una altura en píxeles (800px) que no se adapta a
# la ventana del navegador. Se pisa a mano con !important para que el grafo
# ocupe siempre el 100% de la ventana, y se neutralizan los márgenes/bordes
# de Bootstrap que pyvis mete alrededor (.card, .card-body) para que no
# empujen el grafo fuera de la vista.
CSS_PANTALLA_COMPLETA = """<style>
    html, body { margin: 0; padding: 0; height: 100%; overflow: hidden; background-color: #1e1e1e; }
    center { display: none !important; }
    .card, .card-body { margin: 0 !important; padding: 0 !important; border: none !important; }
    #mynetwork { width: 100% !important; height: 100vh !important; border: none !important; }
</style>"""

# Color de aviso para hosts con puertos sensibles abiertos (ver
# classifier.PUERTOS_SENSIBLES). Pisa el color normal del icono de
# categoría para que destaque independientemente del tipo de dispositivo.
COLOR_ALERTA = "#ff0000"

# Layout circular fijo alrededor del hub (en vez de la simulación
# barnes_hut anterior, que dejaba el grafo con una disposición cambiante e
# irregular). NODOS_POR_ANILLO limita cuántos hosts caben en cada anillo
# antes de abrir uno nuevo más ancho, para que no se amontonen si hay
# muchos hosts vivos (p.ej. un /24 muy poblado).
RADIO_BASE_HOST = 320
RADIO_INCREMENTO_ANILLO = 220
NODOS_POR_ANILLO = 8


def posiciones_circulares(n: int) -> list:
    """Reparte n puntos en anillos concéntricos alrededor del origen
    (donde va el hub), llenando cada anillo antes de abrir el siguiente."""
    posiciones = []
    restantes = n
    anillo = 0
    while restantes > 0:
        en_este_anillo = min(NODOS_POR_ANILLO, restantes)
        radio = RADIO_BASE_HOST + anillo * RADIO_INCREMENTO_ANILLO
        for i in range(en_este_anillo):
            angulo = 2 * math.pi * i / en_este_anillo
            posiciones.append((radio * math.cos(angulo), radio * math.sin(angulo)))
        restantes -= en_este_anillo
        anillo += 1
    return posiciones


# Layout jerárquico (grafo con topología SNMP): un nivel por profundidad del
# árbol, y las hojas de un mismo padre en un bloque de COLUMNAS_HOJAS
# columnas para que 20 hosts colgando de un router no den un árbol de 20 de
# ancho. vis-network usa y creciente hacia abajo, así que la raíz va arriba.
SEPARACION_X = 170
SEPARACION_NIVEL_Y = 240
SEPARACION_FILA_HOJAS_Y = 130
COLUMNAS_HOJAS = 4

# Etiqueta de interfaz en las aristas: con fondo del color del lienzo para
# que se lea encima de la línea (sin él, vis pinta un contorno blanco).
FUENTE_ETIQUETA_ARISTA = {"color": "#bbbbbb", "size": 13, "strokeWidth": 0, "background": "#1e1e1e"}

# En el árbol, aristas curvas que salen y llegan en vertical: con rectas, las
# que van del padre a la 2ª/3ª fila de un bloque de hojas atraviesan a las de
# la 1ª fila.
# Encuadra todo el grafo tras el primer dibujado. Antes el encuadre venía de
# rebote al terminar la simulación física (las aristas 'dynamic' por defecto
# tienen nodos de apoyo que simular); en el árbol no hay nada que simular y
# la vista se quedaba centrada en la raíz. `network` es la variable global
# que crea la plantilla de pyvis.
SCRIPT_AJUSTAR_VISTA = '<script>network.once("afterDrawing", function () { network.fit(); });</script>'

ARISTA_CURVA_VERTICAL = {"enabled": True, "type": "cubicBezier", "forceDirection": "vertical", "roundness": 0.6}


def posiciones_jerarquicas(grafo: nx.Graph) -> dict:
    """{nodo: (x, y)} para un grafo cuyos nodos llevan `padre` (None o
    ausente en las raíces), como el que genera graph.py con topología.

    Cada nodo ocupa un hueco horizontal tan ancho como su subárbol y queda
    centrado sobre sus hijos. Los hijos con descendientes van primero, uno
    al lado del otro; las hojas, después, en un bloque de pocas columnas.
    Dentro de cada grupo se ordena por interfaz (los hosts del mismo puerto
    quedan juntos) y luego por id, para que el resultado sea determinista."""
    hijos: dict = {nodo: [] for nodo in grafo.nodes}
    raices = []
    for nodo, atributos in grafo.nodes(data=True):
        padre = atributos.get("padre")
        if padre is not None and padre in hijos and padre != nodo:
            hijos[padre].append(nodo)
        else:
            raices.append(nodo)

    def orden(padre, hijo):
        interfaz = (grafo.get_edge_data(padre, hijo) or {}).get("interfaz") or ""
        return (interfaz, str(hijo))

    for padre, lista in hijos.items():
        lista.sort(key=lambda hijo, padre=padre: orden(padre, hijo))

    anchos: dict = {}

    def ancho(nodo) -> float:
        if nodo not in anchos:
            anchos[nodo] = SEPARACION_X   # provisional: corta un ciclo si lo hubiera
            subarboles = [h for h in hijos[nodo] if hijos[h]]
            hojas = [h for h in hijos[nodo] if not hijos[h]]
            contenido = sum(ancho(s) for s in subarboles) + min(len(hojas), COLUMNAS_HOJAS) * SEPARACION_X
            anchos[nodo] = max(SEPARACION_X, contenido)
        return anchos[nodo]

    posiciones: dict = {}

    def colocar(nodo, izquierda: float, y: float):
        if nodo in posiciones:
            return
        posiciones[nodo] = (izquierda + ancho(nodo) / 2, y)   # provisional, por si hay ciclo
        subarboles = [h for h in hijos[nodo] if hijos[h]]
        hojas = [h for h in hijos[nodo] if not hijos[h]]
        columnas = min(len(hojas), COLUMNAS_HOJAS)
        contenido = sum(ancho(s) for s in subarboles) + columnas * SEPARACION_X
        x = izquierda + (ancho(nodo) - contenido) / 2
        y_hijos = y + SEPARACION_NIVEL_Y

        centros = []
        for subarbol in subarboles:
            colocar(subarbol, x, y_hijos)
            centros.append(posiciones[subarbol][0])
            x += ancho(subarbol)
        for i, hoja in enumerate(hojas):
            fila, columna = divmod(i, columnas)
            posiciones[hoja] = (x + SEPARACION_X * (columna + 0.5), y_hijos + fila * SEPARACION_FILA_HOJAS_Y)
        if hojas:
            centros.append(x + columnas * SEPARACION_X / 2)

        if centros:
            posiciones[nodo] = ((centros[0] + centros[-1]) / 2, y)

    # El nodo "Red <rango>" (hosts sin ubicar) va después del árbol principal
    raices.sort(key=lambda nodo: (grafo.nodes[nodo].get("tipo") == "red", str(nodo)))
    total = sum(ancho(raiz) for raiz in raices) + SEPARACION_X * max(len(raices) - 1, 0)
    izquierda = -total / 2
    for raiz in raices:
        colocar(raiz, izquierda, 0)
        izquierda += ancho(raiz) + SEPARACION_X
    # Red de seguridad: un ciclo de `padre` (graph.py no los genera) dejaría
    # nodos inalcanzables desde las raíces; se colocan aparte en vez de
    # quedarse sin posición.
    for nodo in grafo.nodes:
        if nodo not in posiciones:
            colocar(nodo, izquierda, 0)
            izquierda += ancho(nodo) + SEPARACION_X
    return posiciones


def _generar_leyenda_html() -> str:
    """Panel fijo (esquina superior izquierda: en el árbol siempre queda
    vacía; abajo tapaba la primera columna de hosts) con el icono/color/nombre de
    cada categoría conocida, reutilizando ICONOS_POR_CATEGORIA de
    classifier.py como única fuente de verdad - no una lista aparte que
    se pueda desincronizar si se añade una categoría nueva."""
    filas = "".join(
        f'<div style="margin:3px 0;">'
        f'<span style="font-family:{icono["face"]}; font-weight:{icono["weight"]}; '
        f'color:{icono["color"]}; display:inline-block; width:20px;">{icono["code"]}</span> '
        f'{icono["nombre"]}</div>'
        for icono in ICONOS_POR_CATEGORIA.values()
    )
    fila_alerta = (
        f'<div style="margin:3px 0; border-top:1px solid #555; padding-top:5px;">'
        f'<span style="color:{COLOR_ALERTA}; display:inline-block; width:20px;">⚠</span> '
        f'Puerto sensible abierto</div>'
    )
    return (
        '<div id="leyenda" style="position:fixed; top:16px; left:16px; '
        'background:rgba(30,30,30,0.9); color:white; padding:10px 14px; '
        'border-radius:6px; font-family:sans-serif; font-size:13px; z-index:1000;">'
        '<div style="font-weight:bold; margin-bottom:6px;">Leyenda</div>'
        f'{filas}{fila_alerta}'
        '</div>'
    )


def exportar_html(grafo: nx.Graph, archivo_salida: str):
    """Genera un HTML interactivo (pyvis) a partir del grafo, usando un icono
    distinto por categoría de dispositivo (deducida de la MAC/vendor).

    Las posiciones son fijas (posiciones_circulares + physics=False por
    nodo) en vez de dejar que la simulación barnes_hut las calcule: así el
    grafo sale siempre ordenado en estrella/círculo alrededor del hub, sin
    depender de dónde se "asiente" la física. physics=False no quita el
    arrastre manual ni el zoom (los sigue dando vis-network por debajo),
    solo impide que el nodo se mueva solo.

    Si el grafo trae equipos de red (topología SNMP, ver graph.py) se usa
    posiciones_jerarquicas en vez del círculo, y cada arista lleva como
    etiqueta la interfaz por la que cuelga el nodo (ether2, wlan1...).

    cdn_resources="remote": con el "local" por defecto, pyvis enlaza
    lib/bindings/utils.js por ruta relativa y solo copia esa carpeta en
    write_html (aquí se usa generate_html), así que el HTML dependía de que
    existiera un lib/ junto a él. En "remote" ese JS va en línea."""
    red_visual = Network(height="800px", width="100%", bgcolor="#1e1e1e", font_color="white",
                         cdn_resources="remote")

    es_arbol = any(at.get("tipo") == "equipo" for _, at in grafo.nodes(data=True))
    if es_arbol:
        posiciones = posiciones_jerarquicas(grafo)
    else:
        nodos_host = [(nodo, at) for nodo, at in grafo.nodes(data=True) if at.get("tipo") != "red"]
        posiciones = dict(zip(
            (nodo for nodo, _ in nodos_host),
            posiciones_circulares(len(nodos_host)),
            strict=True,
        ))

    for nodo, atributos in grafo.nodes(data=True):
        if atributos.get("tipo") == "red":
            red_visual.add_node(
                nodo,
                label=nodo,
                shape="icon",
                icon={"face": "'Font Awesome 5 Free'", "code": "\uf6ff", "size": 60,
                      "color": "#e74c3c", "weight": "900"},
                title=atributos.get("titulo", ""),
                # En la estrella el hub va en el centro; en el árbol, donde diga el layout
                x=posiciones.get(nodo, (0, 0))[0], y=posiciones.get(nodo, (0, 0))[1], physics=False,
            )
        else:
            categoria = atributos.get("categoria", "desconocido")
            icono = icono_para_categoria(categoria)
            # Sin hostname, la IP una sola vez (antes salía "IP (IP)")
            hostname = atributos.get("hostname")
            etiqueta = f"{hostname}\n({nodo})" if hostname else str(nodo)
            tiene_alerta = bool(atributos.get("alertas"))
            color_icono = COLOR_ALERTA if tiene_alerta else icono["color"]
            if tiene_alerta:
                etiqueta = f"⚠ {etiqueta}"
            x, y = posiciones[nodo]
            red_visual.add_node(
                nodo,
                label=etiqueta,
                shape="icon",
                icon={"face": icono["face"], "code": icono["code"], "size": 40,
                      "color": color_icono, "weight": icono["weight"]},
                title=atributos.get("titulo", ""),
                x=x, y=y, physics=False,
            )

    # Una sola etiqueta por padre+interfaz: con 8 móviles por wlan1, ocho
    # etiquetas "wlan1" iguales solo ensucian (cada host la lleva en su tooltip).
    puertos_etiquetados = set()
    for origen, destino, datos in grafo.edges(data=True):
        opciones = {"smooth": ARISTA_CURVA_VERTICAL} if es_arbol else {}
        interfaz = datos.get("interfaz")
        padre = grafo.nodes[destino].get("padre", origen)
        if interfaz and (padre, interfaz) not in puertos_etiquetados:
            puertos_etiquetados.add((padre, interfaz))
            opciones.update(label=interfaz, font=FUENTE_ETIQUETA_ARISTA)
        red_visual.add_edge(origen, destino, **opciones)

    html = red_visual.generate_html(archivo_salida, notebook=False)
    html = html.replace("</head>", f"{CDN_FONTAWESOME}{CSS_PANTALLA_COMPLETA}</head>")
    html = html.replace("</body>", f"{_generar_leyenda_html()}{SCRIPT_AJUSTAR_VISTA}</body>")

    with open(archivo_salida, "w", encoding="utf-8") as f:
        f.write(html)

    log.info(f"Topología exportada a: {archivo_salida}")


def exportar_texto(resultados: dict):
    """Resumen en texto plano por si no se quiere abrir el HTML."""
    print("\n" + "=" * 60)
    print(f"INFORME DE RED - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 60)
    for ip, datos in sorted(resultados.items()):
        print(f"\n[{ip}] {datos['hostname'] or ''}")
        print(f"  SO estimado : {datos['so']}")
        print(f"  MAC         : {datos.get('mac') or 'N/D'}")
        print(f"  Fabricante  : {datos.get('vendor') or 'N/D'} ({datos.get('categoria', 'desconocido')})")
        if datos["puertos"]:
            for p in datos["puertos"]:
                extra = f" ({p['producto']})" if p["producto"] else ""
                print(f"  - {p['puerto']}/tcp  {p['servicio']}{extra}")
        else:
            print("  - Sin puertos abiertos detectados")
    print("\n" + "=" * 60 + "\n")


CABECERA_CSV = ["ip", "hostname", "mac", "vendor", "categoria", "so", "puertos", "alertas"]


def exportar_csv(resultados: dict, archivo_salida: str):
    """Exporta el inventario a CSV (IP, hostname, MAC, vendor, categoría,
    SO, puertos, alertas de puertos sensibles) para auditoría/inventario.
    Una fila por host; puertos y alertas se listan separados por comas
    dentro de su celda (el módulo csv se encarga del quoting)."""
    with open(archivo_salida, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(CABECERA_CSV)
        for ip, datos in sorted(resultados.items()):
            puertos = ", ".join(f"{p['puerto']}/{p['servicio']}" for p in datos.get("puertos", []))
            alertas = ", ".join(f"{a['puerto']} ({a['motivo']})" for a in datos.get("alertas", []))
            writer.writerow([
                ip,
                datos.get("hostname", ""),
                datos.get("mac", ""),
                datos.get("vendor", ""),
                datos.get("categoria", "desconocido"),
                datos.get("so", ""),
                puertos,
                alertas,
            ])

    log.info(f"Inventario exportado a: {archivo_salida}")


def exportar_diff_texto(diff: dict):
    """Resumen en texto plano de los cambios respecto al escaneo anterior
    del mismo rango (ver history.registrar_y_comparar)."""
    print("-" * 60)
    print("HISTORIAL")
    print("-" * 60)

    if diff["primera_vez"]:
        print("Primer escaneo de este rango, nada con qué comparar todavía.")
        print("-" * 60 + "\n")
        return

    if not hay_cambios(diff):
        print("Sin cambios respecto al escaneo anterior.")
        print("-" * 60 + "\n")
        return

    if diff["hosts_nuevos"]:
        print(f"  + Hosts nuevos: {', '.join(diff['hosts_nuevos'])}")
    if diff["hosts_caidos"]:
        print(f"  - Hosts caídos: {', '.join(diff['hosts_caidos'])}")
    for ip, cambios in diff["puertos_cambiados"].items():
        if cambios["nuevos"]:
            print(f"  [{ip}] puertos nuevos: {', '.join(map(str, cambios['nuevos']))}")
        for sensible in cambios.get("nuevos_sensibles", []):
            # Marcador ASCII, no el emoji ⚠: en Windows con la consola en
            # cp1252 (el caso por defecto, no UTF-8) print() lo revienta con
            # UnicodeEncodeError. El HTML sí puede llevar el emoji porque se
            # escribe a archivo con encoding="utf-8" explícito.
            print(f"  [{ip}] [!] puerto nuevo Y sensible: {sensible['puerto']} ({sensible['motivo']})")
        if cambios["cerrados"]:
            print(f"  [{ip}] puertos cerrados: {', '.join(map(str, cambios['cerrados']))}")
    print("-" * 60 + "\n")
