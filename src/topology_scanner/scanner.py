"""
scanner.py
----------
Todo lo relacionado con lanzar escaneos nmap: descubrimiento de hosts vivos
(fase 1) y escaneo completo de puertos/servicios (fase 2).

No conoce nada de grafos ni de HTML — solo devuelve datos en diccionarios.
Esto permite testear la lógica de descubrimiento sin tocar networkx/pyvis.
"""

import logging

from .classifier import clasificar_dispositivo, puertos_sensibles_abiertos


class ScannerError(RuntimeError):
    """Error al lanzar nmap: dependencia faltante, binario no encontrado,
    fallo del propio escaneo, etc. Quien llame decide qué hacer (cli.py
    la captura y termina el programa con un mensaje claro)."""


try:
    import nmap
except ImportError as e:
    raise ScannerError(
        "The python-nmap library is missing. Install it with: pip install python-nmap"
    ) from e

log = logging.getLogger("topology_scanner")

# Única fuente de verdad para los valores por defecto de nmap: cli.py y
# webapp.py los reutilizan en vez de tener cada uno su propia copia
# literal, que podía desincronizarse si se cambiaba uno y no el otro.
DEFAULT_NMAP_ARGS = "-sV -T4"
PUERTOS_POR_DEFECTO = "21-23,25,53,80,110,135,139,143,443,445,3389,8080"


def avisar_si_nmap_reporto_error(scanner):
    """nmap puede "tener éxito" (sin lanzar PortScannerError) y aun así no
    haber podido escanear nada - el error queda en scanner.scaninfo()
    ["error"], invisible si nadie lo revisa explícitamente. No es fatal
    (no se convierte en ScannerError): solo se avisa por log."""
    errores = scanner.scaninfo().get("error")
    if errores:
        log.warning(f"nmap reported errors during the scan: {'; '.join(errores)}")


def descubrir_hosts_vivos(rango: str) -> list:
    """
    FASE 1: ping scan rápido (-sn), sin puertos ni detección de servicio/SO.
    Tarda segundos en vez de minutos, y evita perder tiempo en IPs que no responden.
    Devuelve la lista de IPs que están activas.
    """
    log.info(f"Phase 1/2: discovering live hosts in {rango} (ping scan)...")

    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=rango, arguments="-sn -T4")
    except nmap.PortScannerError as e:
        raise ScannerError(f"nmap error (are you running with sudo?): {e}") from e

    avisar_si_nmap_reporto_error(scanner)
    vivos = [h for h in scanner.all_hosts() if scanner[h].state() == "up"]
    log.info(f"  {len(vivos)} live hosts in the whole range")
    return vivos


def _reparar_codificacion(texto: str) -> str:
    """nmap escribe en la XML cada byte UTF-8 de un carácter no ASCII como
    una referencia aparte (&#xef;&#xbc;&#x8c; en vez de &#xff0c;), y el
    parser lo lee como caracteres Latin-1 sueltos: "Electronicï¼LTD".
    Si el texto se puede volver a esos bytes y forman UTF-8 válido, era ese
    caso y se recompone. Un texto ASCII no cambia, y uno con acentos bien
    decodificados ("Société") no forma UTF-8 válido y se deja tal cual."""
    try:
        return texto.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return texto


def parsear_host(info_host) -> dict:
    """Convierte el resultado de nmap para un host en nuestro formato interno.
    Pública (no _parsear_host): webapp.py la reutiliza para el escaneo
    cancelable, que no pasa por escanear_red() (lanza nmap a mano en un
    hilo para poder matar el proceso si el usuario pulsa "Parar")."""
    estado = info_host.state()

    hostname = ""
    if info_host.hostname():
        hostname = info_host.hostname()

    so_detectado = "desconocido"
    if info_host.get("osmatch"):
        so_detectado = info_host["osmatch"][0].get("name", "desconocido")

    mac = ""
    vendor = ""
    direcciones = info_host.get("addresses", {})
    if "mac" in direcciones:
        mac = direcciones["mac"]
        vendor = _reparar_codificacion(info_host.get("vendor", {}).get(mac, ""))

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
        "alertas": puertos_sensibles_abiertos(puertos_abiertos),
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
            log.warning("No host answered the ping scan.")
            return {}
        objetivo = " ".join(vivos)
        log.info(f"Phase 2/2: full scan of {len(vivos)} hosts (ports: {puertos})...")
    else:
        log.info(f"Scanning range {rango} (ports: {puertos})...")

    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=objetivo, ports=puertos, arguments=argumentos_nmap)
    except nmap.PortScannerError as e:
        raise ScannerError(f"nmap error (are you running with sudo?): {e}") from e

    avisar_si_nmap_reporto_error(scanner)
    resultados = {}
    for host in scanner.all_hosts():
        datos = parsear_host(scanner[host])
        resultados[host] = datos
        log.info(f"  Host {host} ({datos['hostname'] or 'no hostname'}) - "
                  f"{datos['vendor'] or 'unknown vendor'} - {len(datos['puertos'])} open ports")

    log.info(f"Scan finished: {len(resultados)} hosts found")
    return resultados
