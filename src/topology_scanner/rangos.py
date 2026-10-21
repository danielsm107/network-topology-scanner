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
        raise ValueError("indica al menos un rango a escanear")
    if len(unicos) > 1:
        for objetivo in unicos:
            try:
                ipaddress.ip_network(objetivo, strict=False)
            except ValueError as e:
                raise ValueError(
                    f"'{objetivo}' no es una IP ni un CIDR: con varios rangos, cada uno tiene que "
                    "serlo (para saber a cuál pertenece cada host)"
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
