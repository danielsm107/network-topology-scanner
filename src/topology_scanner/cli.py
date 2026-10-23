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


# Flags de la v1.0 (en español), ya publicados en PyPI: siguen funcionando
# para no romper scripts ni crons, pero no salen en --help.
ALIAS_EN_ESPAÑOL = {
    "--rapido": "fast",
    "--con-so": "os_detection",
    "--sin-2-fases": "no_discovery",
    "--sin-historial": "no_history",
}


def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="topology-scanner",
        description="Scans a network and generates an interactive topology graph."
    )
    parser.add_argument(
        "rango", nargs="+", metavar="range",
        help="Network range(s), e.g. 192.168.1.0/24. Several, separated by spaces (each one an IP or CIDR), "
             "are scanned together and history is kept per range"
    )
    parser.add_argument(
        "--ports", default=PUERTOS_POR_DEFECTO,
        help="Ports to scan (nmap format, e.g. '22,80,443' or '1-1000')"
    )
    parser.add_argument(
        "--nmap-args", default=None,
        help=f"Extra arguments for nmap (default: '{DEFAULT_NMAP_ARGS}', no OS detection "
             "for speed). Incompatible with --fast"
    )
    parser.add_argument(
        "--output", default="network_topology.html",
        help="Output HTML file name (default: network_topology.html)"
    )
    parser.add_argument(
        "--os-detection", action="store_true",
        help="Enables OS detection (-O --osscan-guess), the slowest nmap option. "
             "Incompatible with --fast"
    )
    parser.add_argument(
        "--no-discovery", action="store_true",
        help="Skips the preliminary ping scan and scans the whole range directly"
    )
    parser.add_argument(
        "--fast", action="store_true",
        help="Quick preset: no OS or service version detection, common ports only. "
             "Incompatible with --os-detection and --nmap-args"
    )
    parser.add_argument(
        "--csv", default=None, metavar="FILE",
        help="Also export a CSV inventory (IP, hostname, MAC, vendor, category, OS, "
             "ports, alerts) to the given path. Off by default"
    )
    parser.add_argument(
        "--history-db", default=DB_POR_DEFECTO,
        help=f"SQLite file where scan history is stored (default: {DB_POR_DEFECTO})"
    )
    parser.add_argument(
        "--no-history", action="store_true",
        help="Don't save this scan to history or compare it with the previous one"
    )
    parser.add_argument(
        "--snmp", type=_lista_de_ips, default=None, metavar="IP[,IP...]",
        help="Routers/switches to query over SNMP to draw the real topology (a tree) instead of "
             f"the star. Credentials via environment variables: {VARIABLE_COMMUNITY} (v2c), or "
             f"{VARIABLE_USUARIO_V3} + {VARIABLE_CLAVE_AUTH_V3} [+ {VARIABLE_CLAVE_PRIV_V3}] (v3). "
             "Requires the [snmp] extra"
    )
    for alias, destino in ALIAS_EN_ESPAÑOL.items():
        parser.add_argument(alias, dest=destino, action="store_true", help=argparse.SUPPRESS)
    return parser


def _resolver_argumentos_nmap(args: argparse.Namespace, parser: argparse.ArgumentParser) -> str:
    """Decide qué argumentos de nmap usar según los flags combinados.
    --fast es un preset cerrado: combinarlo con --os-detection o --nmap-args
    antes se ignoraba en silencio (el último `if` pisaba a los anteriores),
    así que aquí se corta con un error claro en vez de sorprender al usuario."""
    if args.fast:
        if args.os_detection or args.nmap_args is not None:
            parser.error("--fast cannot be combined with --os-detection or --nmap-args.")
        return "-T4"

    argumentos_nmap = args.nmap_args if args.nmap_args is not None else DEFAULT_NMAP_ARGS
    if args.os_detection:
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
            parser.error(f"--snmp needs credentials: the community in {VARIABLE_COMMUNITY} (v2c), "
                         f"or {VARIABLE_USUARIO_V3} and {VARIABLE_CLAVE_AUTH_V3} (v3).")

    try:
        # nmap acepta varios objetivos separados por espacios en una sola pasada
        resultados = escanear_red(" ".join(rangos), args.ports, argumentos_nmap, dos_fases=not args.no_discovery)
    except ScannerError as e:
        sys.exit(str(e))

    if not resultados:
        log.warning("No hosts found. Check the range and your permissions (try with sudo).")
        return

    exportar_texto(resultados)

    if args.csv:
        try:
            exportar_csv(resultados, args.csv)
        except ExportError as e:
            sys.exit(str(e))

    if not args.no_history:
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
