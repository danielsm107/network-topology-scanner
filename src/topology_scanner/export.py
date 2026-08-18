"""
export.py
---------
Convierte el grafo/resultados en salidas visibles: HTML interactivo (pyvis)
o informe de texto plano por consola.
"""

import logging
from datetime import datetime

import networkx as nx


class ExportError(RuntimeError):
    """Error al generar la salida: dependencia faltante, fallo de escritura,
    etc. Quien llame decide qué hacer (cli.py la captura y termina el
    programa con un mensaje claro)."""


try:
    from pyvis.network import Network
except ImportError as e:
    raise ExportError("Falta pyvis. Instala con: pip install pyvis") from e

from .classifier import icono_para_categoria

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


def exportar_html(grafo: nx.Graph, archivo_salida: str):
    """Genera un HTML interactivo (pyvis) a partir del grafo, usando un icono
    distinto por categoría de dispositivo (deducida de la MAC/vendor)."""
    red_visual = Network(height="800px", width="100%", bgcolor="#1e1e1e", font_color="white")
    red_visual.barnes_hut()

    for nodo, atributos in grafo.nodes(data=True):
        if atributos.get("tipo") == "red":
            red_visual.add_node(
                nodo,
                label=nodo,
                shape="icon",
                icon={"face": "'Font Awesome 5 Free'", "code": "\uf6ff", "size": 60,
                      "color": "#e74c3c", "weight": "900"},
                title=atributos.get("titulo", ""),
            )
        else:
            categoria = atributos.get("categoria", "desconocido")
            icono = icono_para_categoria(categoria)
            etiqueta = atributos.get("hostname") or nodo
            tiene_alerta = bool(atributos.get("alertas"))
            color_icono = COLOR_ALERTA if tiene_alerta else icono["color"]
            if tiene_alerta:
                etiqueta = f"⚠ {etiqueta}"
            red_visual.add_node(
                nodo,
                label=f"{etiqueta}\n({nodo})",
                shape="icon",
                icon={"face": "'Font Awesome 5 Free'", "code": icono["code"], "size": 40,
                      "color": color_icono, "weight": "900"},
                title=atributos.get("titulo", ""),
            )

    for origen, destino in grafo.edges():
        red_visual.add_edge(origen, destino)

    html = red_visual.generate_html(archivo_salida, notebook=False)
    html = html.replace("</head>", f"{CDN_FONTAWESOME}{CSS_PANTALLA_COMPLETA}</head>")

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

    hay_cambios = diff["hosts_nuevos"] or diff["hosts_caidos"] or diff["puertos_cambiados"]
    if not hay_cambios:
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
