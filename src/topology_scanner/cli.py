"""
cli.py
------
Punto de entrada de línea de comandos. Solo orquesta: parsea argumentos,
llama a scanner (+ snmp) -> graph -> export. La lógica real vive en esos módulos.
"""

import argparse
import ipaddress
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
    from .scanner import (
        DEFAULT_NMAP_ARGS,
        PUERTOS_POR_DEFECTO,
        ScannerError,
        escanear_red,
    )
    from .snmp import SnmpError, consultar_equipo, inferir_topologia
except RuntimeError as e:
    sys.exit(str(e))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("topology_scanner")

# La community SNMP va por variable de entorno, nunca como argumento: los
# argumentos se ven en `ps` y quedan en el historial de la shell.
VARIABLE_COMMUNITY = "TOPOLOGY_SNMP_COMMUNITY"


def _lista_de_ips(valor: str) -> list:
    """Tipo de argparse para --snmp: "192.168.1.1, 192.168.1.2" -> lista."""
    ips = [parte.strip() for parte in valor.split(",") if parte.strip()]
    for ip in ips:
        try:
            ipaddress.IPv4Address(ip)
        except ValueError as e:
            raise argparse.ArgumentTypeError(f"'{ip}' no es una IPv4 válida") from e
    return ips


def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="topology-scanner",
        description="Escanea una red y genera un grafo de topología interactivo."
    )
    parser.add_argument("rango", help="Rango de red en notación CIDR, ej: 192.168.1.0/24")
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
        help="Routers/switches a consultar por SNMP v2c para dibujar la topología real (árbol) "
             f"en vez de la estrella. La community se lee de la variable de entorno "
             f"{VARIABLE_COMMUNITY}. Requiere el extra [snmp]"
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

    # Antes de escanear: sin community no hay SNMP, y no tiene sentido
    # descubrirlo después de un escaneo de nmap que puede tardar minutos.
    community = os.environ.get(VARIABLE_COMMUNITY, "")
    if args.snmp and not community:
        parser.error(f"--snmp necesita la community en la variable de entorno {VARIABLE_COMMUNITY}.")

    try:
        resultados = escanear_red(args.rango, args.ports, argumentos_nmap, dos_fases=not args.sin_2_fases)
    except ScannerError as e:
        sys.exit(str(e))

    if not resultados:
        log.warning("No se detectaron hosts. Revisa el rango y los permisos (prueba con sudo).")
        return

    exportar_texto(resultados)

    if args.csv:
        exportar_csv(resultados, args.csv)

    if not args.sin_historial:
        try:
            diff = registrar_y_comparar(resultados, args.rango, db_path=args.history_db)
            exportar_diff_texto(diff)
        except HistoryError as e:
            # Perder el historial no es motivo para tirar un escaneo que sí
            # ha funcionado: se avisa y se sigue con el grafo/export normal.
            log.warning(str(e))

    topologia = _obtener_topologia(args.snmp, community) if args.snmp else None
    grafo = construir_grafo(resultados, args.rango, topologia=topologia)
    try:
        exportar_html(grafo, args.output)
    except ExportError as e:
        sys.exit(str(e))


def _obtener_topologia(ips: list, community: str) -> dict | None:
    """Consulta cada equipo por SNMP e infiere la topología. Un equipo que
    no responde se salta con un aviso; si no responde ninguno, se devuelve
    None y se dibuja la estrella: el escaneo de nmap ya ha funcionado y
    perder la topología no es motivo para no generar nada (mismo criterio
    que con el historial)."""
    equipos = []
    for ip in ips:
        log.info(f"Consultando {ip} por SNMP...")
        try:
            equipos.append(consultar_equipo(ip, community))
        except SnmpError as e:
            log.warning(str(e))
    if not equipos:
        log.warning("Ningún equipo ha respondido por SNMP: se dibuja la topología en estrella.")
        return None
    topologia = inferir_topologia(equipos)
    log.info(f"Topología SNMP: {len(topologia['equipos'])} equipos de red, "
             f"{len(topologia['ubicaciones'])} hosts ubicados")
    return topologia


if __name__ == "__main__":
    main()
