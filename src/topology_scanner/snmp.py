"""
snmp.py
-------
Topología real a partir de las tablas SNMP de routers/switches (ARP, tabla
MAC del bridge, rutas, vecinos). No sabe nada de nmap ni de grafos.

Por ahora solo contiene los parsers: funciones puras que reciben las filas
de un walk SNMP y devuelven listas/dicts normales. Cada fila es
(oid_completo, valor) con el valor ya convertido a tipo nativo de Python:
`bytes` para cadenas/MACs/IPs, `int` para enteros. La conversión desde los
tipos de la librería SNMP la hace la capa de consulta, así que los parsers
no dependen de ella y se testean sin red.

Cada parser sabe qué tipo tiene cada columna (MAC, IP o texto) por el OID,
nunca lo adivina por la longitud del valor: "ether1" también tiene 6 bytes.
Muchos datos van en el índice del OID, no en el valor (la IP en la ARP, la
MAC en la tabla del bridge, destino/máscara en las rutas).

Las filas mal formadas se descartan con un aviso en el log de depuración:
un equipo real puede devolver entradas incompletas y eso no debe tirar el
resto de la tabla.
"""

import ipaddress
import logging
from collections.abc import Iterable

log = logging.getLogger("topology_scanner")

Fila = tuple[str, bytes | int]

# SNMPv2-MIB / IF-MIB
OID_SYS_NAME = "1.3.6.1.2.1.1.5"
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
# IP-MIB: ipNetToMediaPhysAddress, índice = ifIndex.IP
OID_ARP = "1.3.6.1.2.1.4.22.1.2"
# IP-FORWARD-MIB: ipCidrRouteNextHop, índice = destino.máscara.tos.siguiente_salto
OID_RUTAS = "1.3.6.1.2.1.4.24.4.1.4"
# BRIDGE-MIB: dot1dTpFdbPort (índice = MAC en decimal) y dot1dBasePortIfIndex
OID_FDB_PUERTO = "1.3.6.1.2.1.17.4.3.1.2"
OID_PUERTO_A_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
# MIKROTIK-MIB: mtxrNeighborTableEntry, índice = columna.fila
OID_VECINOS_MIKROTIK = "1.3.6.1.4.1.14988.1.1.11.1.1"

_COLUMNAS_VECINOS_MIKROTIK = {2: "ip", 3: "mac", 4: "version", 5: "plataforma", 6: "identidad", 8: "if_index"}


def _indice(oid: str, base: str) -> list[int] | None:
    """Lo que va detrás de `base` en el OID, como lista de enteros. None si
    el OID no pertenece a esa tabla."""
    if not oid.startswith(base + "."):
        return None
    try:
        return [int(parte) for parte in oid[len(base) + 1:].split(".")]
    except ValueError:
        return None


def _filas_de(filas: Iterable[Fila], base: str):
    """Recorre solo las filas de la tabla `base`, devolviendo (índice, valor)."""
    for oid, valor in filas:
        indice = _indice(oid, base)
        if indice is not None:
            yield indice, valor


def _mac(octetos) -> str | None:
    if not isinstance(octetos, bytes) or len(octetos) != 6:
        return None
    return ":".join(f"{b:02x}" for b in octetos)


def _ip(octetos) -> str | None:
    if not isinstance(octetos, bytes) or len(octetos) != 4:
        return None
    return str(ipaddress.IPv4Address(octetos))


def _texto(octetos) -> str:
    if isinstance(octetos, bytes):
        return octetos.decode("utf-8", errors="replace")
    return str(octetos)


def parsear_nombre(filas: Iterable[Fila]) -> str:
    """sysName del equipo ("" si no lo devuelve)."""
    for _, valor in _filas_de(filas, OID_SYS_NAME):
        return _texto(valor)
    return ""


def parsear_interfaces(filas: Iterable[Fila]) -> dict[int, str]:
    """ifIndex -> nombre de interfaz (ifName), p. ej. {3: "ether1"}."""
    return {indice[0]: _texto(valor) for indice, valor in _filas_de(filas, OID_IF_NAME) if len(indice) == 1}


def parsear_arp(filas: Iterable[Fila]) -> list[dict]:
    """Tabla ARP: [{"ip", "mac", "if_index"}]."""
    entradas = []
    for indice, valor in _filas_de(filas, OID_ARP):
        mac = _mac(valor)
        if len(indice) != 5 or mac is None:
            log.debug(f"SNMP: fila ARP descartada ({indice}, {valor!r})")
            continue
        entradas.append({"ip": ".".join(map(str, indice[1:])), "mac": mac, "if_index": indice[0]})
    return entradas


def parsear_rutas(filas: Iterable[Fila]) -> list[dict]:
    """Tabla de rutas: [{"red": "10.0.10.0/24", "siguiente_salto": "192.0.2.44"}].
    Se usa ipCidrRouteTable porque su índice ya incluye destino y máscara;
    con la tabla antigua (ipRouteTable) la máscara va en otra columna."""
    rutas = []
    for indice, _ in _filas_de(filas, OID_RUTAS):
        if len(indice) != 13:
            log.debug(f"SNMP: fila de rutas descartada ({indice})")
            continue
        destino = ".".join(map(str, indice[0:4]))
        mascara = ".".join(map(str, indice[4:8]))
        try:
            red = ipaddress.IPv4Network(f"{destino}/{mascara}")
        except ValueError:
            log.debug(f"SNMP: ruta con máscara no válida descartada ({destino}/{mascara})")
            continue
        rutas.append({"red": str(red), "siguiente_salto": ".".join(map(str, indice[9:13]))})
    return rutas


def parsear_fdb(filas_fdb: Iterable[Fila], filas_puerto_a_ifindex: Iterable[Fila]) -> list[dict]:
    """Tabla MAC del bridge: [{"mac", "if_index"}] (en qué interfaz se ve
    cada MAC). BRIDGE-MIB da el puerto del bridge, no la interfaz, así que
    se traduce con dot1dBasePortIfIndex. Se descartan el puerto 0 (el propio
    bridge), la MAC nula y los puertos que no se pueden traducir."""
    puerto_a_ifindex = {
        indice[0]: valor
        for indice, valor in _filas_de(filas_puerto_a_ifindex, OID_PUERTO_A_IFINDEX)
        if len(indice) == 1 and isinstance(valor, int)
    }

    entradas = []
    for indice, puerto in _filas_de(filas_fdb, OID_FDB_PUERTO):
        if len(indice) != 6 or not any(indice) or not all(0 <= b <= 255 for b in indice):
            continue
        if_index = puerto_a_ifindex.get(puerto)
        if if_index is None:
            continue
        entradas.append({"mac": _mac(bytes(indice)), "if_index": if_index})
    return entradas


def parsear_vecinos_mikrotik(filas: Iterable[Fila]) -> list[dict]:
    """Vecinos descubiertos por un MikroTik (MNDP/LLDP/CDP):
    [{"ip", "mac", "identidad", "plataforma", "version", "if_index"}].
    `ip` es None si el vecino no la anuncia (llega como 0.0.0.0). Se
    conservan todos, también los que no son equipos de red."""
    por_fila: dict[int, dict] = {}
    for indice, valor in _filas_de(filas, OID_VECINOS_MIKROTIK):
        if len(indice) != 2 or indice[0] not in _COLUMNAS_VECINOS_MIKROTIK:
            continue
        columna, fila = indice
        por_fila.setdefault(fila, {})[_COLUMNAS_VECINOS_MIKROTIK[columna]] = valor

    vecinos = []
    for fila in sorted(por_fila):
        datos = por_fila[fila]
        ip = _ip(datos.get("ip"))
        if_index = datos.get("if_index")
        vecinos.append({
            "ip": None if ip in (None, "0.0.0.0") else ip,
            "mac": _mac(datos.get("mac")),
            "identidad": _texto(datos.get("identidad", b"")),
            "plataforma": _texto(datos.get("plataforma", b"")),
            "version": _texto(datos.get("version", b"")),
            "if_index": if_index if isinstance(if_index, int) else None,
        })
    return vecinos
