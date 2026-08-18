"""
scanner.py
----------
Todo lo relacionado con lanzar escaneos nmap: descubrimiento de hosts vivos
(fase 1) y escaneo completo de puertos/servicios (fase 2).

No conoce nada de grafos ni de HTML — solo devuelve datos en diccionarios.
Esto permite testear la lógica de descubrimiento sin tocar networkx/pyvis.
"""

import logging
import sys

try:
    import nmap
except ImportError:
    sys.exit("Falta la librería python-nmap. Instala con: pip install python-nmap")

from .classifier import clasificar_dispositivo

log = logging.getLogger("topology_scanner")


def descubrir_hosts_vivos(rango: str) -> list:
    """
    FASE 1: ping scan rápido (-sn), sin puertos ni detección de servicio/SO.
    Tarda segundos en vez de minutos, y evita perder tiempo en IPs que no responden.
    Devuelve la lista de IPs que están activas.
    """
    log.info(f"Fase 1/2: descubriendo hosts activos en {rango} (ping scan)...")
    scanner = nmap.PortScanner()

    try:
        scanner.scan(hosts=rango, arguments="-sn -T4")
    except nmap.PortScannerError as e:
        sys.exit(f"Error de nmap (¿ejecutas con sudo?): {e}")

    vivos = [h for h in scanner.all_hosts() if scanner[h].state() == "up"]
    log.info(f"  {len(vivos)} hosts activos de todo el rango")
    return vivos


def _parsear_host(info_host) -> dict:
    """Convierte el resultado de nmap para un host en nuestro formato interno."""
    estado = info_host.state()

    hostname = ""
    if info_host.hostname():
        hostname = info_host.hostname()

    so_detectado = "desconocido"
    if "osmatch" in info_host and info_host["osmatch"]:
        so_detectado = info_host["osmatch"][0].get("name", "desconocido")

    mac = ""
    vendor = ""
    direcciones = info_host.get("addresses", {})
    if "mac" in direcciones:
        mac = direcciones["mac"]
        vendor = info_host.get("vendor", {}).get(mac, "")

    puertos_abiertos = []
    if "tcp" in info_host:
        for puerto, datos_puerto in info_host["tcp"].items():
            if datos_puerto.get("state") == "open":
                puertos_abiertos.append({
                    "puerto": puerto,
                    "servicio": datos_puerto.get("name", "?"),
                    "producto": datos_puerto.get("product", ""),
                })

    return {
        "estado": estado,
        "hostname": hostname,
        "so": so_detectado,
        "mac": mac,
        "vendor": vendor,
        "categoria": clasificar_dispositivo(vendor),
        "puertos": puertos_abiertos,
    }


def escanear_red(rango: str, puertos: str, argumentos_nmap: str, dos_fases: bool = True) -> dict:
    """
    Lanza un escaneo nmap sobre el rango indicado.
    Si dos_fases=True (por defecto), primero descubre qué IPs están vivas
    con un ping scan rápido, y solo hace el escaneo completo (puertos/SO)
    sobre esas IPs — esto reduce muchísimo el tiempo total en rangos grandes.
    Devuelve un diccionario {ip: {estado, hostname, so, mac, vendor, categoria, puertos: [...]}}
    """
    objetivo = rango

    if dos_fases:
        vivos = descubrir_hosts_vivos(rango)
        if not vivos:
            log.warning("Ningún host respondió al ping scan.")
            return {}
        objetivo = " ".join(vivos)
        log.info(f"Fase 2/2: escaneo completo de {len(vivos)} hosts (puertos: {puertos})...")
    else:
        log.info(f"Escaneando rango {rango} (puertos: {puertos})...")

    scanner = nmap.PortScanner()

    try:
        scanner.scan(hosts=objetivo, ports=puertos, arguments=argumentos_nmap)
    except nmap.PortScannerError as e:
        sys.exit(f"Error de nmap (¿ejecutas con sudo?): {e}")

    resultados = {}
    for host in scanner.all_hosts():
        datos = _parsear_host(scanner[host])
        resultados[host] = datos
        log.info(f"  Host {host} ({datos['hostname'] or 'sin hostname'}) - "
                  f"{datos['vendor'] or 'vendor desconocido'} - {len(datos['puertos'])} puertos abiertos")

    log.info(f"Escaneo completado: {len(resultados)} hosts detectados")
    return resultados
