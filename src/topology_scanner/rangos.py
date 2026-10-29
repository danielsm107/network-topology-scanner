"""
rangos.py
---------
Escanear varios rangos a la vez (p. ej. una LAN y la subred del homelab
detrás de otro router). No sabe nada de nmap, grafos ni historial: solo
valida los objetivos y dice a qué rango pertenece cada IP.

nmap ya acepta varios objetivos separados por espacios; lo que hace falta
aparte es repartir los resultados, porque el historial compara cada rango
con su propio escaneo anterior (rangos distintos no se mezclan) y el grafo
en estrella dibuja un centro por rango.
"""

import ipaddress


def parsear_rangos(objetivos: list[str]) -> list[str]:
    """Valida la lista de objetivos y quita duplicados (manteniendo el orden).

    Con uno solo se devuelve tal cual, admitiendo cualquier sintaxis de nmap
    (192.168.1.1-50, 192.168.1.1,5, un hostname...), como hasta ahora. Con
    varios, cada uno tiene que ser una IP o un CIDR: hay que poder decir a
    qué rango pertenece cada host. Lanza ValueError si no."""
    unicos = list(dict.fromkeys(objetivo.strip() for objetivo in objetivos if objetivo.strip()))
    if not unicos:
        raise ValueError("give at least one range to scan")
    if len(unicos) > 1:
        for objetivo in unicos:
            try:
                ipaddress.ip_network(objetivo, strict=False)
            except ValueError as e:
                raise ValueError(
                    f"'{objetivo}' is not an IP or CIDR: with several ranges, each one must be "
                    "(to know which range each host belongs to)"
                ) from e
    return unicos


def rango_de(ip: str, rangos: list[str]) -> str:
    """Rango de `rangos` al que pertenece `ip`: el más específico si se
    solapan. Si no encaja en ninguno (o los rangos no son CIDR, cosa que
    solo pasa con un único objetivo), el primero: un host nunca se queda
    sin rango."""
    try:
        direccion = ipaddress.ip_address(ip)
    except ValueError:
        return rangos[0]
    candidatos = []
    for rango in rangos:
        try:
            red = ipaddress.ip_network(rango, strict=False)
        except ValueError:
            continue
        if direccion in red:
            candidatos.append((red.prefixlen, rango))
    return max(candidatos)[1] if candidatos else rangos[0]


def repartir_por_rango(resultados: dict, rangos: list[str]) -> dict[str, dict]:
    """{rango: {ip: datos}} con todos los rangos, también los que no tienen
    hosts: en el historial, un rango vacío hace que sus hosts del escaneo
    anterior salgan como caídos."""
    reparto: dict[str, dict] = {rango: {} for rango in rangos}
    for ip, datos in resultados.items():
        reparto[rango_de(ip, rangos)][ip] = datos
    return reparto


# Rangos permitidos: la web del clúster no tiene login y escanea lo que le
# pidan, así que con esta variable solo acepta rangos dentro de estas redes.
# Sin ella no hay límite (uso local en el PC, como siempre).
VARIABLE_RANGOS_PERMITIDOS = "TOPOLOGY_ALLOWED_RANGES"


def parsear_permitidos(texto: str | None) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None:
    """Lista de redes permitidas a partir del valor de la variable (CIDRs o
    IPs separados por espacios). None si no hay variable o está vacía (sin
    límite). Lanza ValueError si algún elemento no es una red válida: mejor
    no escanear nada que escanear sin límites por una errata."""
    if texto is None or not texto.strip():
        return None
    try:
        return [ipaddress.ip_network(red, strict=False) for red in texto.split()]
    except ValueError as e:
        raise ValueError(f"'{texto.strip()}' is not a list of IPs or CIDRs ({e})") from e


def validar_permitidos(objetivos: list[str], permitidos: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> None:
    """Lanza ValueError si algún objetivo no es una IP o un CIDR contenido
    entero en alguna red permitida. La sintaxis de nmap (192.0.2.1-5) se
    rechaza: no se puede comprobar de forma fiable qué cubre."""
    texto_permitidos = ", ".join(str(red) for red in permitidos)
    for objetivo in objetivos:
        try:
            red = ipaddress.ip_network(objetivo, strict=False)
        except ValueError:
            red = None
        # subnet_of lanza TypeError si se mezclan IPv4 e IPv6: se compara la versión antes
        if red is None or not any(red.version == p.version and red.subnet_of(p) for p in permitidos):
            raise ValueError(f"'{objetivo}' is outside the allowed ranges ({texto_permitidos})")
