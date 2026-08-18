"""
cli.py
------
Punto de entrada de línea de comandos. Solo orquesta: parsea argumentos,
llama a scanner -> graph -> export. La lógica real vive en esos módulos.
"""

import argparse
import logging
import sys

try:
    from .scanner import escanear_red, ScannerError
    from .graph import construir_grafo
    from .export import exportar_html, exportar_texto, ExportError
except RuntimeError as e:
    sys.exit(str(e))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("topology_scanner")

DEFAULT_NMAP_ARGS = "-sV -T4"


def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="topology-scanner",
        description="Escanea una red y genera un grafo de topología interactivo."
    )
    parser.add_argument("rango", help="Rango de red en notación CIDR, ej: 192.168.1.0/24")
    parser.add_argument(
        "--ports", default="21-23,25,53,80,110,135,139,143,443,445,3389,8080",
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

    try:
        resultados = escanear_red(args.rango, args.ports, argumentos_nmap, dos_fases=not args.sin_2_fases)
    except ScannerError as e:
        sys.exit(str(e))

    if not resultados:
        log.warning("No se detectaron hosts. Revisa el rango y los permisos (prueba con sudo).")
        return

    exportar_texto(resultados)

    grafo = construir_grafo(resultados, args.rango)
    try:
        exportar_html(grafo, args.output)
    except ExportError as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
