"""
Tests de los parsers de snmp.py. No tocan la red: las filas (oid, valor)
reproducen la estructura real que devolvió un MikroTik hAP ac2 (RouterOS v6)
en el reconocimiento, pero anonimizadas: IPs en rangos de documentación
(192.0.2.0/24 = LAN, 198.51.100.0/24 = enlace al router de arriba) y MACs
"locales" 02:00:00:xx:xx:xx.
"""

from topology_scanner.snmp import (
    OID_ARP,
    OID_FDB_PUERTO,
    OID_IF_NAME,
    OID_PUERTO_A_IFINDEX,
    OID_RUTAS,
    OID_SYS_NAME,
    OID_VECINOS_MIKROTIK,
    parsear_arp,
    parsear_fdb,
    parsear_interfaces,
    parsear_nombre,
    parsear_rutas,
    parsear_vecinos_mikrotik,
)

MAC_UPSTREAM = "02:00:00:00:00:01"
MAC_PC = "02:00:00:00:00:20"
MAC_UDM = "02:00:00:00:00:44"
MAC_MOVIL = "02:00:00:00:00:66"
MAC_AP = "02:00:00:00:00:fe"


def _mac(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def _ip(ip: str) -> bytes:
    return bytes(int(octeto) for octeto in ip.split("."))


def _mac_en_oid(mac: str) -> str:
    """BRIDGE-MIB indexa la tabla MAC con la MAC en decimal: 2.0.0.0.0.32"""
    return ".".join(str(b) for b in _mac(mac))


# --- sysName -----------------------------------------------------------------

def test_parsear_nombre_devuelve_el_sysname():
    filas = [(f"{OID_SYS_NAME}.0", b"Router-Casa")]

    assert parsear_nombre(filas) == "Router-Casa"


def test_parsear_nombre_sin_filas_devuelve_cadena_vacia():
    assert parsear_nombre([]) == ""


# --- ifName ------------------------------------------------------------------

def test_parsear_interfaces_mapea_ifindex_a_nombre():
    filas = [
        (f"{OID_IF_NAME}.1", b"wlan1"),
        (f"{OID_IF_NAME}.3", b"ether1"),
        (f"{OID_IF_NAME}.8", b"Bridge LAN"),
    ]

    assert parsear_interfaces(filas) == {1: "wlan1", 3: "ether1", 8: "Bridge LAN"}


def test_parsear_interfaces_no_confunde_un_nombre_de_6_letras_con_una_mac():
    """El script de reconocimiento mostraba 'ether1' como 65:74:68:65:72:31
    por tener 6 bytes. El parser sabe que ifName es texto."""
    filas = [(f"{OID_IF_NAME}.3", b"ether1")]

    assert parsear_interfaces(filas) == {3: "ether1"}


# --- ARP (ipNetToMediaPhysAddress) -------------------------------------------

def test_parsear_arp_saca_interfaz_e_ip_del_indice_y_mac_del_valor():
    filas = [
        (f"{OID_ARP}.3.198.51.100.2", _mac(MAC_UPSTREAM)),
        (f"{OID_ARP}.8.192.0.2.20", _mac(MAC_PC)),
        (f"{OID_ARP}.8.192.0.2.44", _mac(MAC_UDM)),
    ]

    assert parsear_arp(filas) == [
        {"ip": "198.51.100.2", "mac": MAC_UPSTREAM, "if_index": 3},
        {"ip": "192.0.2.20", "mac": MAC_PC, "if_index": 8},
        {"ip": "192.0.2.44", "mac": MAC_UDM, "if_index": 8},
    ]


def test_parsear_arp_descarta_filas_con_mac_mal_formada():
    filas = [
        (f"{OID_ARP}.8.192.0.2.20", _mac(MAC_PC)),
        (f"{OID_ARP}.8.192.0.2.21", b""),          # entrada incompleta
        (f"{OID_ARP}.8.192.0.2", _mac(MAC_UDM)),   # índice sin IP completa
    ]

    assert parsear_arp(filas) == [{"ip": "192.0.2.20", "mac": MAC_PC, "if_index": 8}]


# --- Rutas (ipCidrRouteNextHop) ----------------------------------------------

def test_parsear_rutas_convierte_destino_y_mascara_a_cidr():
    filas = [
        (f"{OID_RUTAS}.0.0.0.0.0.0.0.0.0.198.51.100.2", _ip("198.51.100.2")),
        (f"{OID_RUTAS}.10.0.10.0.255.255.255.0.0.192.0.2.44", _ip("192.0.2.44")),
        (f"{OID_RUTAS}.192.0.2.0.255.255.255.0.0.192.0.2.1", _ip("192.0.2.1")),
    ]

    assert parsear_rutas(filas) == [
        {"red": "0.0.0.0/0", "siguiente_salto": "198.51.100.2"},
        {"red": "10.0.10.0/24", "siguiente_salto": "192.0.2.44"},
        {"red": "192.0.2.0/24", "siguiente_salto": "192.0.2.1"},
    ]


def test_parsear_rutas_descarta_mascaras_no_validas():
    filas = [(f"{OID_RUTAS}.10.0.10.0.255.0.255.0.0.192.0.2.44", _ip("192.0.2.44"))]

    assert parsear_rutas(filas) == []


# --- Tabla MAC del bridge (dot1dTpFdbPort + dot1dBasePortIfIndex) ------------

def _filas_puerto_a_ifindex():
    return [
        (f"{OID_PUERTO_A_IFINDEX}.1", 4),   # puerto 1 del bridge = ether2
        (f"{OID_PUERTO_A_IFINDEX}.3", 5),   # puerto 3 = ether3
        (f"{OID_PUERTO_A_IFINDEX}.6", 1),   # puerto 6 = wlan1
    ]


def test_parsear_fdb_traduce_puerto_del_bridge_a_ifindex():
    filas_fdb = [
        (f"{OID_FDB_PUERTO}.{_mac_en_oid(MAC_PC)}", 1),
        (f"{OID_FDB_PUERTO}.{_mac_en_oid(MAC_UDM)}", 3),
        (f"{OID_FDB_PUERTO}.{_mac_en_oid(MAC_MOVIL)}", 6),
    ]

    assert parsear_fdb(filas_fdb, _filas_puerto_a_ifindex()) == [
        {"mac": MAC_PC, "if_index": 4},
        {"mac": MAC_UDM, "if_index": 5},
        {"mac": MAC_MOVIL, "if_index": 1},
    ]


def test_parsear_fdb_descarta_puerto_0_mac_nula_y_puertos_sin_interfaz():
    """El hAP devuelve una entrada 00:00:00:00:00:00 en el puerto 0 (el propio
    bridge). Un puerto que no aparece en dot1dBasePortIfIndex no se puede
    traducir a interfaz, así que tampoco sirve."""
    filas_fdb = [
        (f"{OID_FDB_PUERTO}.0.0.0.0.0.0", 0),
        (f"{OID_FDB_PUERTO}.{_mac_en_oid(MAC_AP)}", 0),
        (f"{OID_FDB_PUERTO}.{_mac_en_oid(MAC_MOVIL)}", 9),
        (f"{OID_FDB_PUERTO}.{_mac_en_oid(MAC_PC)}", 1),
    ]

    assert parsear_fdb(filas_fdb, _filas_puerto_a_ifindex()) == [{"mac": MAC_PC, "if_index": 4}]


# --- Vecinos MikroTik (mtxrNeighborTable) ------------------------------------

def _filas_vecinos():
    """Tabla con columnas: 2 IP, 3 MAC, 4 versión, 5 plataforma, 6 identidad,
    7 software-id, 8 interfaz. Índice = columna.fila."""
    filas = []
    vecinos = {
        1: (_ip("198.51.100.2"), _mac(MAC_UPSTREAM), b"6.48.5 (long-term)", b"MikroTik", b"Upstream", 3),
        2: (_ip("192.0.2.254"), _mac(MAC_AP), b"6.49.19 (stable)", b"MikroTik", b"AP-Interior", 4),
        # Un PC que manda LLDP: sin IP (0.0.0.0) ni identidad/plataforma
        17: (_ip("0.0.0.0"), _mac(MAC_PC), b"", b"", b"", 4),
    }
    for fila, (ip, mac, version, plataforma, identidad, if_index) in vecinos.items():
        filas += [
            (f"{OID_VECINOS_MIKROTIK}.2.{fila}", ip),
            (f"{OID_VECINOS_MIKROTIK}.3.{fila}", mac),
            (f"{OID_VECINOS_MIKROTIK}.4.{fila}", version),
            (f"{OID_VECINOS_MIKROTIK}.5.{fila}", plataforma),
            (f"{OID_VECINOS_MIKROTIK}.6.{fila}", identidad),
            (f"{OID_VECINOS_MIKROTIK}.7.{fila}", b"XXXX-XXXX"),
            (f"{OID_VECINOS_MIKROTIK}.8.{fila}", if_index),
        ]
    return filas


def test_parsear_vecinos_mikrotik_agrupa_las_columnas_por_fila():
    vecinos = parsear_vecinos_mikrotik(_filas_vecinos())

    assert vecinos[:2] == [
        {"ip": "198.51.100.2", "mac": MAC_UPSTREAM, "identidad": "Upstream",
         "plataforma": "MikroTik", "version": "6.48.5 (long-term)", "if_index": 3},
        {"ip": "192.0.2.254", "mac": MAC_AP, "identidad": "AP-Interior",
         "plataforma": "MikroTik", "version": "6.49.19 (stable)", "if_index": 4},
    ]


def test_parsear_vecinos_mikrotik_ip_0000_es_none():
    """Los vecinos que solo mandan LLDP (p. ej. un PC) llegan con IP 0.0.0.0
    y sin identidad: el parser los conserva, decidir si son equipos de red
    es cosa de la inferencia de topología."""
    vecinos = parsear_vecinos_mikrotik(_filas_vecinos())

    assert vecinos[2] == {"ip": None, "mac": MAC_PC, "identidad": "", "plataforma": "",
                          "version": "", "if_index": 4}


# --- Robustez común ----------------------------------------------------------

def test_los_parsers_ignoran_filas_de_otra_tabla():
    """Un walk con lexicographicMode=False no debería devolverlas, pero si
    llegan no deben colarse como datos."""
    filas = [
        (f"{OID_IF_NAME}.1", b"wlan1"),
        ("1.3.6.1.2.1.2.2.1.2.1", b"wlan1"),   # ifDescr, no ifName
    ]

    assert parsear_interfaces(filas) == {1: "wlan1"}
