"""
snmp.py
-------
Topología real a partir de las tablas SNMP de routers/switches (ARP, tabla
MAC del bridge, rutas, vecinos). No sabe nada de nmap ni de grafos.

Dos capas:
- Consulta (`consultar_equipo`, `_recorrer`): la única que habla con la
  red, vía pysnmp (extra opcional `[snmp]`, importado solo al consultar
  para que el resto del módulo funcione sin él).
- Parsers (`parsear_*`): funciones puras que reciben las filas de un walk
  SNMP y devuelven listas/dicts normales.

Cada fila es
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

import asyncio
import ipaddress
import logging
from collections.abc import Iterable, Sequence

log = logging.getLogger("topology_scanner")

Fila = tuple[str, bytes | int]


class SnmpError(Exception):
    """El equipo no responde por SNMP, o falta la librería."""

# SNMPv2-MIB / IF-MIB
OID_SYS_NAME = "1.3.6.1.2.1.1.5"
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
# IP-MIB: ipNetToMediaPhysAddress, índice = ifIndex.IP
OID_ARP = "1.3.6.1.2.1.4.22.1.2"
# IP-FORWARD-MIB: ipCidrRouteNextHop, índice = destino.máscara.tos.siguiente_salto
OID_RUTAS = "1.3.6.1.2.1.4.24.4.1.4"
# BRIDGE-MIB: dot1dTpFdbPort y dot1dTpFdbStatus (índice = MAC en decimal) y
# dot1dBasePortIfIndex
OID_FDB_PUERTO = "1.3.6.1.2.1.17.4.3.1.2"
OID_FDB_ESTADO = "1.3.6.1.2.1.17.4.3.1.3"
OID_PUERTO_A_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
# dot1dTpFdbStatus: invalid(2) es basura y self(4) la MAC de un puerto del
# propio equipo (el hAP mete la de cada uno de sus puertos); no son hosts.
_ESTADOS_FDB_DESCARTADOS = {2, 4}
# MIKROTIK-MIB: mtxrNeighborTableEntry, índice = columna.fila
OID_VECINOS_MIKROTIK = "1.3.6.1.4.1.14988.1.1.11.1.1"

_COLUMNAS_VECINOS_MIKROTIK = {2: "ip", 3: "mac", 4: "version", 5: "plataforma", 6: "identidad", 8: "if_index"}

# sysName va primero a propósito: si no responde, el equipo no responde.
TABLAS_A_CONSULTAR = (
    OID_SYS_NAME, OID_IF_NAME, OID_ARP, OID_RUTAS,
    OID_FDB_PUERTO, OID_FDB_ESTADO, OID_PUERTO_A_IFINDEX, OID_VECINOS_MIKROTIK,
)


# --- Consulta (red) ----------------------------------------------------------

def consultar_equipo(ip: str, community: str, timeout: float = 2.0, reintentos: int = 1) -> dict:
    """Lee por SNMP v2c las tablas de un router/switch y las devuelve ya
    parseadas: {"ip", "nombre", "interfaces", "arp", "rutas", "fdb", "vecinos"}.
    Lanza SnmpError si el equipo no responde. Una tabla que el equipo no
    implementa sale vacía, no es un error."""
    tablas = _recorrer(ip, community, TABLAS_A_CONSULTAR, timeout, reintentos)

    def filas(oid: str) -> list[Fila]:
        return tablas.get(oid, [])

    return {
        "ip": ip,
        "nombre": parsear_nombre(filas(OID_SYS_NAME)),
        "interfaces": parsear_interfaces(filas(OID_IF_NAME)),
        "arp": parsear_arp(filas(OID_ARP)),
        "rutas": parsear_rutas(filas(OID_RUTAS)),
        "fdb": parsear_fdb(filas(OID_FDB_PUERTO), filas(OID_PUERTO_A_IFINDEX), filas(OID_FDB_ESTADO)),
        "vecinos": parsear_vecinos_mikrotik(filas(OID_VECINOS_MIKROTIK)),
    }


def _recorrer(ip: str, community: str, oids: Sequence[str], timeout: float, reintentos: int) -> dict[str, list[Fila]]:
    """Hace un walk de cada tabla y devuelve {oid_base: [filas]}.
    pysnmp 7 solo tiene API asyncio; se envuelve aquí con asyncio.run para
    que el resto del programa (síncrono) no tenga que saberlo."""
    try:
        from pysnmp.hlapi.v3arch.asyncio import (  # noqa: F401 (se comprueba que está instalado)
            SnmpEngine,
        )
    except ImportError as e:
        raise SnmpError(
            "Falta la librería SNMP. Instálala con: pip install -e \".[snmp]\""
        ) from e
    return asyncio.run(_recorrer_async(ip, community, oids, timeout, reintentos))


async def _recorrer_async(ip, community, oids, timeout, reintentos) -> dict[str, list[Fila]]:
    from pysnmp.error import PySnmpError
    from pysnmp.hlapi.v3arch.asyncio import CommunityData, SnmpEngine, UdpTransportTarget

    motor = SnmpEngine()
    try:
        try:
            destino = await UdpTransportTarget.create((ip, 161), timeout=timeout, retries=reintentos)
        except PySnmpError as e:
            raise SnmpError(f"No se puede usar {ip} como destino SNMP: {e}") from e
        # mpModel=1 = SNMP v2c. La community nunca va en mensajes de error ni logs.
        credenciales = CommunityData(community, mpModel=1)

        tablas: dict[str, list[Fila]] = {}
        for oid in oids:
            try:
                tablas[oid] = await _recorrer_tabla(motor, credenciales, destino, oid)
            except SnmpError as e:
                if not tablas:
                    raise SnmpError(
                        f"{ip} no responde por SNMP ({e}). Revisa que SNMP esté activado, la "
                        "community y que el equipo acepte consultas desde esta IP."
                    ) from e
                log.warning(f"SNMP {ip}: no se pudo leer la tabla {oid} ({e}); se sigue sin ella")
                tablas[oid] = []
        return tablas
    finally:
        motor.close_dispatcher()


async def _recorrer_tabla(motor, credenciales, destino, oid: str) -> list[Fila]:
    from pysnmp.hlapi.v3arch.asyncio import ContextData, ObjectIdentity, ObjectType, walk_cmd

    filas: list[Fila] = []
    # lexicographicMode=False: parar al salir de la tabla pedida
    async for error, estado, _indice_error, varbinds in walk_cmd(
        motor, credenciales, destino, ContextData(),
        ObjectType(ObjectIdentity(oid)), lexicographicMode=False,
    ):
        if error:
            raise SnmpError(str(error))
        if estado:
            raise SnmpError(estado.prettyPrint())
        for nombre, valor in varbinds:
            convertido = _convertir_valor(valor)
            if convertido is not None:
                filas.append((str(nombre), convertido))
    return filas


def _convertir_valor(valor) -> bytes | int | None:
    """Tipo de pysnmp -> bytes (cadenas, MACs, IPs) o int (enteros,
    contadores). None para lo que no interesa a los parsers (OIDs) y para
    los marcadores de "no existe": NoSuchObject/NoSuchInstance/EndOfMibView
    también tienen asOctets() (devuelven b""), así que van primero."""
    from pysnmp.proto.rfc1905 import EndOfMibView, NoSuchInstance, NoSuchObject

    if isinstance(valor, (NoSuchObject, NoSuchInstance, EndOfMibView)):
        return None
    if hasattr(valor, "asOctets"):
        return valor.asOctets()
    try:
        return int(valor)
    except (TypeError, ValueError):
        return None


# --- Parsers (puros) ---------------------------------------------------------


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


def parsear_fdb(filas_fdb: Iterable[Fila], filas_puerto_a_ifindex: Iterable[Fila],
                filas_estado: Iterable[Fila] = ()) -> list[dict]:
    """Tabla MAC del bridge: [{"mac", "if_index"}] (en qué interfaz se ve
    cada MAC). BRIDGE-MIB da el puerto del bridge, no la interfaz, así que
    se traduce con dot1dBasePortIfIndex. Se descartan el puerto 0 (el propio
    bridge), la MAC nula, los puertos que no se pueden traducir y, si el
    equipo da dot1dTpFdbStatus, las entradas invalid/self (las MACs de sus
    propios puertos no son hosts). Sin tabla de estado no se filtra por eso."""
    puerto_a_ifindex = {
        indice[0]: valor
        for indice, valor in _filas_de(filas_puerto_a_ifindex, OID_PUERTO_A_IFINDEX)
        if len(indice) == 1 and isinstance(valor, int)
    }
    estado_por_mac = {tuple(indice): valor for indice, valor in _filas_de(filas_estado, OID_FDB_ESTADO)}

    entradas = []
    for indice, puerto in _filas_de(filas_fdb, OID_FDB_PUERTO):
        if len(indice) != 6 or not any(indice) or not all(0 <= b <= 255 for b in indice):
            continue
        if estado_por_mac.get(tuple(indice)) in _ESTADOS_FDB_DESCARTADOS:
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


# --- Inferencia de topología (pura) ------------------------------------------

def inferir_topologia(equipos_consultados: list[dict]) -> dict:
    """Deduce quién cuelga de quién a partir de lo que devuelve
    consultar_equipo (uno o varios routers/switches). Devuelve un dict
    neutral, sin nada de SNMP, indexado por IP como los nodos del grafo:

        {"equipos":     {ip: {"nombre", "plataforma", "version", "mac", "consultado", "upstream"}},
         "enlaces":     [{"padre", "hijo", "interfaz_padre", "interfaz_hijo"}],
         "redes":       {"10.0.10.0/24": ip_del_router_que_la_sirve},
         "ubicaciones": {mac: {"ip", "padre", "interfaz"}}}

    Reglas:
    - Equipos de red: los consultados, sus vecinos con identidad (MNDP/LLDP)
      y los siguientes saltos de sus rutas (un router que no anuncia LLDP
      solo se conoce por la tabla de rutas).
    - La puerta de enlace (ruta por defecto) es el padre del router; el
      resto de equipos, sus hijos. Si la puerta de enlace no se ha
      consultado, se marca como `upstream`.
    - Una ruta cuyo siguiente salto está dentro de la propia red es una red
      conectada (el salto es el propio router): no apunta a otro router.
      Tampoco una con salto 0.0.0.0 (por interfaz: túnel VPN, PPPoE...).
    - Un host visto en un puerto donde hay otro equipo de red cuelga de ese
      equipo (sin puerto: no se sabe cuál de los suyos); si no, cuelga del
      router en esa interfaz. Si varios routers lo ven, gana la ubicación
      con interfaz (la más precisa).
    """
    consultados = {equipo["ip"] for equipo in equipos_consultados}
    equipos: dict[str, dict] = {}
    enlaces: dict[tuple[str, str], dict] = {}
    redes: dict[str, str] = {}
    pasarelas: set[str] = set()
    # Por router consultado: ifIndex -> IP del equipo de red que hay detrás
    interfaz_a_equipo: dict[str, dict[int, str]] = {}

    def registrar(ip: str, **datos):
        actual = equipos.setdefault(ip, {
            "nombre": "", "plataforma": "", "version": "", "mac": None,
            "consultado": ip in consultados, "upstream": False,
        })
        for clave, valor in datos.items():
            if valor and not actual[clave]:
                actual[clave] = valor

    def enlazar(padre: str, hijo: str, interfaz_padre: str | None, interfaz_hijo: str | None):
        if padre == hijo or (hijo, padre) in enlaces:
            return
        enlace = enlaces.setdefault((padre, hijo), {
            "padre": padre, "hijo": hijo, "interfaz_padre": None, "interfaz_hijo": None,
        })
        enlace["interfaz_padre"] = enlace["interfaz_padre"] or interfaz_padre
        enlace["interfaz_hijo"] = enlace["interfaz_hijo"] or interfaz_hijo

    # Pasada 1: equipos de red, enlaces y redes remotas
    for router in equipos_consultados:
        ip_router = router["ip"]
        registrar(ip_router, nombre=router["nombre"])
        arp_por_ip = {entrada["ip"]: entrada for entrada in router["arp"]}
        fdb_por_mac = {entrada["mac"]: entrada["if_index"] for entrada in router["fdb"]}
        mapa = interfaz_a_equipo.setdefault(ip_router, {})

        # (ip, mac, ifIndex del vecino si se conoce)
        vecinos_de_red: list[tuple[str, str | None, int | None]] = []
        for vecino in router["vecinos"]:
            if vecino["ip"] and vecino["identidad"]:
                registrar(vecino["ip"], nombre=vecino["identidad"], plataforma=vecino["plataforma"],
                          version=vecino["version"], mac=vecino["mac"])
                vecinos_de_red.append((vecino["ip"], vecino["mac"], vecino["if_index"]))

        pasarela = None
        for ruta in router["rutas"]:
            red = ipaddress.IPv4Network(ruta["red"])
            salto = ruta["siguiente_salto"]
            # Ruta por interfaz (túnel VPN, PPPoE...): no apunta a ningún router
            if ipaddress.IPv4Address(salto).is_unspecified:
                continue
            if red.prefixlen == 0:
                pasarela = salto
            elif ipaddress.IPv4Address(salto) in red:
                continue
            else:
                redes.setdefault(str(red), salto)
            mac_salto = arp_por_ip.get(salto, {}).get("mac")
            registrar(salto, mac=mac_salto)
            vecinos_de_red.append((salto, mac_salto, None))

        for ip_equipo, mac, if_vecino in vecinos_de_red:
            if ip_equipo == ip_router:
                continue
            # Dónde está: vecino > tabla MAC > ARP. La ARP solo sirve para
            # etiquetar el enlace: en un bridge diría "Bridge LAN" para todos.
            if_index = if_vecino if if_vecino is not None else fdb_por_mac.get(mac)
            if if_index is not None:
                mapa.setdefault(if_index, ip_equipo)
            else:
                if_index = arp_por_ip.get(ip_equipo, {}).get("if_index")
            interfaz = router["interfaces"].get(if_index)
            if ip_equipo == pasarela:
                enlazar(ip_equipo, ip_router, None, interfaz)
            else:
                enlazar(ip_router, ip_equipo, interfaz, None)

        if pasarela:
            pasarelas.add(pasarela)

    for pasarela in pasarelas - consultados:
        equipos[pasarela]["upstream"] = True

    # Pasada 2: hosts (necesita conocer ya todos los equipos de red)
    macs_de_equipos = {equipo["mac"] for equipo in equipos.values() if equipo["mac"]}
    ubicaciones: dict[str, dict] = {}

    def ubicar(mac: str, ip: str | None, padre: str, interfaz: str | None):
        actual = ubicaciones.get(mac)
        if actual is None or (actual["interfaz"] is None and interfaz is not None):
            ubicaciones[mac] = {"ip": ip or (actual or {}).get("ip"), "padre": padre, "interfaz": interfaz}
        elif ip and not actual["ip"]:
            actual["ip"] = ip

    for router in equipos_consultados:
        ip_router = router["ip"]
        ip_por_mac = {entrada["mac"]: entrada["ip"] for entrada in router["arp"]}
        mapa = interfaz_a_equipo[ip_router]
        macs_en_fdb = set()

        for entrada in router["fdb"]:
            mac = entrada["mac"]
            macs_en_fdb.add(mac)
            ip = ip_por_mac.get(mac)
            if mac in macs_de_equipos or ip in equipos:
                continue
            equipo_detras = mapa.get(entrada["if_index"])
            if equipo_detras:
                ubicar(mac, ip, equipo_detras, None)
            else:
                ubicar(mac, ip, ip_router, router["interfaces"].get(entrada["if_index"]))

        for entrada in router["arp"]:
            mac, ip = entrada["mac"], entrada["ip"]
            if mac in macs_en_fdb or mac in macs_de_equipos or ip in equipos:
                continue
            ubicar(mac, ip, ip_router, None)

    return {"equipos": equipos, "enlaces": list(enlaces.values()), "redes": redes, "ubicaciones": ubicaciones}


# --- Orquestación (compartida por cli.py y webapp.py) ------------------------

# La community va por variable de entorno, nunca como argumento del CLI: los
# argumentos se ven en `ps` y quedan en el historial de la shell. La web la
# usa también como valor por defecto si el campo se deja vacío.
VARIABLE_COMMUNITY = "TOPOLOGY_SNMP_COMMUNITY"


def parsear_lista_ips(texto: str) -> list[str]:
    """"192.0.2.1, 192.0.2.2" -> ["192.0.2.1", "192.0.2.2"]. Lanza
    ValueError si alguna no es una IPv4 (cada interfaz lo muestra a su
    manera: argparse como error de argumento, la web como aviso)."""
    ips = [parte.strip() for parte in texto.split(",") if parte.strip()]
    for ip in ips:
        try:
            ipaddress.IPv4Address(ip)
        except ValueError as e:
            raise ValueError(f"'{ip}' no es una IPv4 válida") from e
    return ips


def obtener_topologia(ips: list[str], community: str) -> tuple[dict | None, list[str]]:
    """Consulta cada equipo e infiere la topología. Devuelve (topologia,
    avisos): un equipo que no responde se salta y se añade a los avisos; si
    no responde ninguno, topologia es None y quien llame dibuja la estrella
    (el escaneo de nmap ya ha funcionado: perder la topología no es motivo
    para no mostrar nada). Los avisos se devuelven en vez de loguearse para
    que el CLI los mande al log y la web los pinte en pantalla."""
    equipos = []
    avisos = []
    for ip in ips:
        log.info(f"Consultando {ip} por SNMP...")
        try:
            equipos.append(consultar_equipo(ip, community))
        except SnmpError as e:
            avisos.append(str(e))
    if not equipos:
        avisos.append("Ningún equipo ha respondido por SNMP: se dibuja la topología en estrella.")
        return None, avisos
    topologia = inferir_topologia(equipos)
    log.info(f"Topología SNMP: {len(topologia['equipos'])} equipos de red, "
             f"{len(topologia['ubicaciones'])} hosts ubicados")
    return topologia, avisos
