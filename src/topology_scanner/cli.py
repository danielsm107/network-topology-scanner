"""
cli.py
------
Punto de entrada de línea de comandos. Solo orquesta: parsea argumentos,
llama a scanner (+ snmp) -> graph -> export. La lógica real vive en esos módulos.
"""

import argparse
import logging
import os
import sys

try:
    from .export import (
        ExportError,
        exportar_csv,
        exportar_diff_texto,
        exportar_html,
        exportar_texto,
    )
    from .graph import construir_grafo
    from .history import DB_POR_DEFECTO, HistoryError, registrar_y_comparar
    from .rangos import parsear_rangos, repartir_por_rango
    from .scanner import (
        DEFAULT_NMAP_ARGS,
        PUERTOS_POR_DEFECTO,
        ScannerError,
        escanear_red,
    )
    from .snmp import (
        VARIABLE_CLAVE_AUTH_V3,
        VARIABLE_CLAVE_PRIV_V3,
        VARIABLE_COMMUNITY,
        VARIABLE_USUARIO_V3,
        Credenciales,
        credenciales_desde_entorno,
        obtener_topologia,
        parsear_lista_ips,
    )
except RuntimeError as e:
    sys.exit(str(e))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("topology_scanner")


def _lista_de_ips(valor: str) -> list:
    """Tipo de argparse para --snmp: "192.168.1.1, 192.168.1.2" -> lista."""
    try:
        return parsear_lista_ips(valor)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from e


def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="topology-scanner",
        description="Escanea una red y genera un grafo de topología interactivo."
    )
    parser.add_argument(
        "rango", nargs="+",
        help="Rango(s) de red, ej: 192.168.1.0/24. Varios separados por espacios (cada uno IP o CIDR) "
             "se escanean juntos y el historial se guarda por rango"
    )
    parser.add_argument(
        "--ports", default=PUERTOS_POR_DEFECTO,
        help="Puertos a escanear (formato nmap, ej: '22,80,443' o '1-1000')"
    )
    parser.add_argument(
        "--nmap-args", default=None,
        help=f"Argumentos extra para nmap (por defecto: '{DEFAULT_NMAP_ARGS}', sin detección de "
             "SO por velocidad). Incompatible con --rapido"
    )
    parser.add_argument(
        "--output", default="topologia_red.html",
        help="Nombre del archivo HTML de salida (por defecto: topologia_red.html)"
    )
    parser.add_argument(
        "--con-so", action="store_true",
        help="Activa detección de SO (-O --osscan-guess). Es la opción más lenta de nmap. "
             "Incompatible con --rapido"
    )
    parser.add_argument(
        "--sin-2-fases", action="store_true",
        help="Desactiva el descubrimiento previo (ping scan) y escanea el rango completo directamente"
    )
    parser.add_argument(
        "--rapido", action="store_true",
        help="Preset rápido: sin detección de SO, sin versión de servicio, solo puertos comunes. "
             "Incompatible con --con-so y --nmap-args"
    )
    parser.add_argument(
        "--csv", default=None, metavar="ARCHIVO",
        help="Exporta también un inventario CSV (IP, hostname, MAC, vendor, categoría, SO, "
             "puertos, alertas) a la ruta indicada. Desactivado por defecto"
    )
    parser.add_argument(
        "--history-db", default=DB_POR_DEFECTO,
        help=f"Archivo SQLite donde guardar el historial de escaneos (por defecto: {DB_POR_DEFECTO})"
    )
    parser.add_argument(
        "--sin-historial", action="store_true",
        help="No guarda este escaneo en el historial ni compara con el anterior"
    )
    parser.add_argument(
        "--snmp", type=_lista_de_ips, default=None, metavar="IP[,IP...]",
        help="Routers/switches a consultar por SNMP para dibujar la topología real (árbol) en vez de "
             f"la estrella. Credenciales por variables de entorno: {VARIABLE_COMMUNITY} (v2c), o "
             f"{VARIABLE_USUARIO_V3} + {VARIABLE_CLAVE_AUTH_V3} [+ {VARIABLE_CLAVE_PRIV_V3}] (v3). "
             "Requiere el extra [snmp]"
    )
    return parser


def _resolver_argumentos_nmap(args: argparse.Namespace, parser: argparse.ArgumentParser) -> str:
    """Decide qué argumentos de nmap usar según los flags combinados.
    --rapido es un preset cerrado: combinarlo con --con-so o --nmap-args
    antes se ignoraba en silencio (el último `if` pisaba a los anteriores),
    así que aquí se corta con un error claro en vez de sorprender al usuario."""
    if args.rapido:
        if args.con_so or args.nmap_args is not None:
            parser.error("--rapido no se puede combinar con --con-so ni --nmap-args.")
        return "-T4"

    argumentos_nmap = args.nmap_args if args.nmap_args is not None else DEFAULT_NMAP_ARGS
    if args.con_so:
        argumentos_nmap += " -O --osscan-guess"
    return argumentos_nmap


def main():
    parser = construir_parser()
    args = parser.parse_args()

    argumentos_nmap = _resolver_argumentos_nmap(args, parser)

    # Separados por espacios, no por comas: "192.168.1.1,5" es sintaxis de
    # nmap (las IPs .1 y .5) y partirlo la rompería.
    try:
        rangos = parsear_rangos(args.rango)
    except ValueError as e:
        parser.error(str(e))

    # Antes de escanear: sin credenciales no hay SNMP, y no tiene sentido
    # descubrirlo después de un escaneo de nmap que puede tardar minutos.
    credenciales = None
    if args.snmp:
        try:
            credenciales = credenciales_desde_entorno(os.environ)
        except ValueError as e:
            parser.error(str(e))
        if credenciales is None:
            parser.error(f"--snmp necesita credenciales: la community en {VARIABLE_COMMUNITY} (v2c), "
                         f"o {VARIABLE_USUARIO_V3} y {VARIABLE_CLAVE_AUTH_V3} (v3).")

    try:
        # nmap acepta varios objetivos separados por espacios en una sola pasada
        resultados = escanear_red(" ".join(rangos), args.ports, argumentos_nmap, dos_fases=not args.sin_2_fases)
    except ScannerError as e:
        sys.exit(str(e))

    if not resultados:
        log.warning("No se detectaron hosts. Revisa el rango y los permisos (prueba con sudo).")
        return

    exportar_texto(resultados)

    if args.csv:
        exportar_csv(resultados, args.csv)

    if not args.sin_historial:
        # Un registro por rango: cada uno se compara con su propio escaneo
        # anterior (rangos distintos no se mezclan), así que un rango que
        # antes se escaneaba solo sigue comparándose bien.
        for rango, resultados_rango in repartir_por_rango(resultados, rangos).items():
            try:
                diff = registrar_y_comparar(resultados_rango, rango, db_path=args.history_db)
                exportar_diff_texto(diff, rango=rango if len(rangos) > 1 else None)
            except HistoryError as e:
                # Perder el historial no es motivo para tirar un escaneo que sí
                # ha funcionado: se avisa y se sigue con el grafo/export normal.
                log.warning(str(e))

    topologia = _obtener_topologia(args.snmp, credenciales) if args.snmp else None
    grafo = construir_grafo(resultados, rangos, topologia=topologia)
    try:
        exportar_html(grafo, args.output)
    except ExportError as e:
        sys.exit(str(e))


def _obtener_topologia(ips: list, credenciales: Credenciales) -> dict | None:
    """snmp.obtener_topologia, con los avisos al log (en la web se pintan)."""
    topologia, avisos = obtener_topologia(ips, credenciales)
    for aviso in avisos:
        log.warning(aviso)
    return topologia


if __name__ == "__main__":
    main()
