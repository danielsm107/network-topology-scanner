"""
Tests de los parsers de snmp.py. No tocan la red: las filas (oid, valor)
reproducen la estructura real que devolvió un MikroTik hAP ac2 (RouterOS v6)
en el reconocimiento, pero anonimizadas: IPs en rangos de documentación
(192.0.2.0/24 = LAN, 198.51.100.0/24 = enlace al router de arriba) y MACs
"locales" 02:00:00:xx:xx:xx.

La capa de consulta (la que habla con la red vía pysnmp) se prueba al
final mockeando `_recorrer` o, para la propia consulta, `walk_cmd`/
`UdpTransportTarget`/`SnmpEngine`. Los tests que necesitan tipos reales de
pysnmp se saltan si no está instalado (extra opcional [snmp]).
"""

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from topology_scanner.snmp import (
    OID_ARP,
    OID_FDB_PUERTO,
    OID_IF_NAME,
    OID_PUERTO_A_IFINDEX,
    OID_RUTAS,
    OID_SYS_NAME,
    OID_VECINOS_MIKROTIK,
    TABLAS_A_CONSULTAR,
    SnmpError,
    _recorrer,
    consultar_equipo,
    inferir_topologia,
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


# === Capa de consulta =======================================================

MODULO_PYSNMP = "pysnmp.hlapi.v3arch.asyncio"


# --- consultar_equipo (con _recorrer mockeado) -------------------------------

def _tablas_fake():
    return {
        OID_SYS_NAME: [(f"{OID_SYS_NAME}.0", b"Router-Casa")],
        OID_IF_NAME: [(f"{OID_IF_NAME}.3", b"ether1")],
        OID_ARP: [(f"{OID_ARP}.3.198.51.100.2", bytes.fromhex("020000000001"))],
    }


@patch("topology_scanner.snmp._recorrer")
def test_consultar_equipo_devuelve_las_tablas_ya_parseadas(mock_recorrer):
    mock_recorrer.return_value = _tablas_fake()

    equipo = consultar_equipo("192.0.2.1", "community")

    assert equipo == {
        "ip": "192.0.2.1",
        "nombre": "Router-Casa",
        "interfaces": {3: "ether1"},
        "arp": [{"ip": "198.51.100.2", "mac": "02:00:00:00:00:01", "if_index": 3}],
        "rutas": [],
        "fdb": [],
        "vecinos": [],
    }


@patch("topology_scanner.snmp._recorrer")
def test_consultar_equipo_pide_todas_las_tablas_con_timeout_y_reintentos(mock_recorrer):
    mock_recorrer.return_value = {}

    consultar_equipo("192.0.2.1", "community", timeout=5, reintentos=3)

    mock_recorrer.assert_called_once_with("192.0.2.1", "community", TABLAS_A_CONSULTAR, 5, 3)


@patch("topology_scanner.snmp._recorrer", side_effect=SnmpError("192.0.2.1 no responde por SNMP"))
def test_consultar_equipo_propaga_snmperror(_mock_recorrer):
    with pytest.raises(SnmpError, match="no responde"):
        consultar_equipo("192.0.2.1", "community")


def test_sin_pysnmp_instalado_da_un_error_claro():
    """None en sys.modules hace que el import falle con ImportError, igual
    que si el extra [snmp] no estuviera instalado."""
    with patch.dict(sys.modules, {MODULO_PYSNMP: None}), pytest.raises(SnmpError, match=r"\[snmp\]"):
        _recorrer("192.0.2.1", "community", (OID_SYS_NAME,), 1, 0)


# --- _recorrer (con pysnmp mockeado) -----------------------------------------

def _walk_falso(respuestas):
    """Sustituye a walk_cmd. Cada llamada (una por tabla, en orden) consume
    una respuesta: una lista de (error, estado, varbinds) por paso del walk."""
    pendientes = iter(respuestas)

    def walk_cmd(*_args, **_kwargs):
        pasos = next(pendientes)

        async def generador():
            for error, estado, varbinds in pasos:
                yield error, estado, 0, varbinds

        return generador()

    return walk_cmd


@pytest.fixture
def pysnmp_falso():
    """Mockea lo que toca la red (transporte y motor) y deja que cada test
    defina las respuestas de walk_cmd."""
    pytest.importorskip(MODULO_PYSNMP)
    with patch(f"{MODULO_PYSNMP}.UdpTransportTarget.create", new=AsyncMock()), \
            patch(f"{MODULO_PYSNMP}.SnmpEngine", MagicMock()):
        yield lambda respuestas: patch(f"{MODULO_PYSNMP}.walk_cmd", _walk_falso(respuestas))


def test_recorrer_convierte_los_tipos_de_pysnmp_a_bytes_e_int(pysnmp_falso):
    from pysnmp.proto.rfc1902 import Integer32, IpAddress, ObjectName, OctetString

    respuestas = [
        [(None, 0, [(ObjectName(f"{OID_SYS_NAME}.0"), OctetString(b"Router-Casa"))])],
        [(None, 0, [(ObjectName(f"{OID_IF_NAME}.3"), OctetString(b"ether1"))]),
         (None, 0, [(ObjectName(f"{OID_IF_NAME}.4"), IpAddress("192.0.2.1"))]),
         (None, 0, [(ObjectName(f"{OID_IF_NAME}.5"), Integer32(7))])],
    ]

    with pysnmp_falso(respuestas):
        tablas = _recorrer("192.0.2.1", "community", (OID_SYS_NAME, OID_IF_NAME), 1, 0)

    assert tablas == {
        OID_SYS_NAME: [(f"{OID_SYS_NAME}.0", b"Router-Casa")],
        OID_IF_NAME: [(f"{OID_IF_NAME}.3", b"ether1"),
                      (f"{OID_IF_NAME}.4", bytes([192, 0, 2, 1])),
                      (f"{OID_IF_NAME}.5", 7)],
    }


def test_recorrer_descarta_valores_de_no_existe(pysnmp_falso):
    """NoSuchObject/EndOfMibView también tienen asOctets() (devuelven b""):
    sin descartarlos antes se colarían como filas vacías."""
    from pysnmp.proto.rfc1902 import ObjectName
    from pysnmp.proto.rfc1905 import EndOfMibView, NoSuchObject

    respuestas = [[(None, 0, [(ObjectName(f"{OID_SYS_NAME}.0"), NoSuchObject("")),
                              (ObjectName(f"{OID_SYS_NAME}.1"), EndOfMibView(""))])]]

    with pysnmp_falso(respuestas):
        tablas = _recorrer("192.0.2.1", "community", (OID_SYS_NAME,), 1, 0)

    assert tablas == {OID_SYS_NAME: []}


def test_recorrer_si_la_primera_tabla_falla_el_equipo_no_responde(pysnmp_falso):
    respuestas = [[("No SNMP response received before timeout", 0, [])]]

    with pysnmp_falso(respuestas), pytest.raises(SnmpError, match=r"192\.0\.2\.1 no responde"):
        _recorrer("192.0.2.1", "community", (OID_SYS_NAME, OID_IF_NAME), 1, 0)


def test_recorrer_si_falla_una_tabla_posterior_sigue_con_las_demas(pysnmp_falso, caplog):
    """Si el equipo ya ha respondido, perder una tabla no es motivo para
    tirar las demás: se avisa y se sigue con esa tabla vacía."""
    from pysnmp.proto.rfc1902 import ObjectName, OctetString

    respuestas = [
        [(None, 0, [(ObjectName(f"{OID_SYS_NAME}.0"), OctetString(b"Router-Casa"))])],
        [("No SNMP response received before timeout", 0, [])],
        [(None, 0, [(ObjectName(f"{OID_ARP}.3.198.51.100.2"), OctetString(bytes(6)))])],
    ]

    with pysnmp_falso(respuestas):
        tablas = _recorrer("192.0.2.1", "community", (OID_SYS_NAME, OID_IF_NAME, OID_ARP), 1, 0)

    assert tablas[OID_IF_NAME] == []
    assert len(tablas[OID_ARP]) == 1
    assert "no se pudo leer" in caplog.text


def test_recorrer_un_error_de_estado_snmp_cuenta_como_fallo(pysnmp_falso):
    """errorStatus distinto de 0 (p. ej. authorizationError) llega con
    errorIndication vacío: también tiene que tratarse como fallo."""
    estado = MagicMock()
    estado.__bool__.return_value = True
    estado.prettyPrint.return_value = "authorizationError"

    with pysnmp_falso([[(None, estado, [])]]), pytest.raises(SnmpError, match="authorizationError"):
        _recorrer("192.0.2.1", "community", (OID_SYS_NAME,), 1, 0)


def test_los_errores_no_incluyen_la_community(pysnmp_falso):
    with pysnmp_falso([[("No SNMP response received before timeout", 0, [])]]), \
            pytest.raises(SnmpError) as error:
        _recorrer("192.0.2.1", "community-secreta", (OID_SYS_NAME,), 1, 0)

    assert "community-secreta" not in str(error.value)


# === Inferencia de topología ================================================
#
# Entrada: lo que devuelve consultar_equipo (ya parseado). Este router
# reproduce la red real anonimizada:
#
#   Upstream 198.51.100.2 ── ether1 ── Router-Casa 192.0.2.1
#                                         ├─ ether2 ── AP-Interior 192.0.2.254 ── PC
#                                         ├─ ether3 ── UDM 192.0.2.44 (sin LLDP) ── LAN B 10.0.10.0/24
#                                         ├─ ether4 ── cámara
#                                         └─ wlan1  ── móvil

MAC_UDM_OTRA = "02:00:00:00:00:45"
MAC_CAMARA = "02:00:00:00:00:40"
MAC_SOLO_ARP = "02:00:00:00:00:50"


def _router_casa():
    return {
        "ip": "192.0.2.1",
        "nombre": "Router-Casa",
        "interfaces": {1: "wlan1", 3: "ether1", 4: "ether2", 5: "ether3", 6: "ether4", 8: "Bridge LAN"},
        "arp": [
            {"ip": "198.51.100.2", "mac": MAC_UPSTREAM, "if_index": 3},
            {"ip": "192.0.2.20", "mac": MAC_PC, "if_index": 8},
            {"ip": "192.0.2.44", "mac": MAC_UDM, "if_index": 8},
            {"ip": "192.0.2.30", "mac": MAC_MOVIL, "if_index": 8},
            {"ip": "192.0.2.40", "mac": MAC_CAMARA, "if_index": 8},
            {"ip": "192.0.2.50", "mac": MAC_SOLO_ARP, "if_index": 8},
        ],
        "rutas": [
            {"red": "0.0.0.0/0", "siguiente_salto": "198.51.100.2"},
            {"red": "10.0.10.0/24", "siguiente_salto": "192.0.2.44"},
            {"red": "192.0.2.0/24", "siguiente_salto": "192.0.2.1"},
            {"red": "198.51.100.0/30", "siguiente_salto": "198.51.100.1"},
        ],
        "fdb": [
            {"mac": MAC_PC, "if_index": 4},
            {"mac": MAC_AP, "if_index": 4},
            {"mac": MAC_UDM, "if_index": 5},
            {"mac": MAC_UDM_OTRA, "if_index": 5},
            {"mac": MAC_CAMARA, "if_index": 6},
            {"mac": MAC_MOVIL, "if_index": 1},
        ],
        "vecinos": [
            {"ip": "198.51.100.2", "mac": MAC_UPSTREAM, "identidad": "Upstream",
             "plataforma": "MikroTik", "version": "6.48.5", "if_index": 3},
            {"ip": "192.0.2.254", "mac": MAC_AP, "identidad": "AP-Interior",
             "plataforma": "MikroTik", "version": "6.49.19", "if_index": 4},
            {"ip": None, "mac": MAC_PC, "identidad": "", "plataforma": "", "version": "", "if_index": 4},
        ],
    }


def test_inferir_topologia_sin_equipos_devuelve_estructura_vacia():
    assert inferir_topologia([]) == {"equipos": {}, "enlaces": [], "redes": {}, "ubicaciones": {}}


def test_inferir_topologia_identifica_los_equipos_de_red():
    """Equipos de red = el consultado + vecinos con identidad + siguientes
    saltos de rutas (el UDM no anuncia LLDP: solo se sabe de él por la
    tabla de rutas). El PC que manda LLDP sin identidad no es un equipo."""
    equipos = inferir_topologia([_router_casa()])["equipos"]

    assert set(equipos) == {"192.0.2.1", "198.51.100.2", "192.0.2.254", "192.0.2.44"}
    assert equipos["192.0.2.1"] == {"nombre": "Router-Casa", "plataforma": "", "version": "",
                                    "mac": None, "consultado": True, "upstream": False}
    assert equipos["192.0.2.254"]["nombre"] == "AP-Interior"
    assert equipos["192.0.2.44"]["mac"] == MAC_UDM
    assert equipos["192.0.2.44"]["consultado"] is False


def test_inferir_topologia_marca_como_upstream_la_puerta_de_enlace_no_consultada():
    equipos = inferir_topologia([_router_casa()])["equipos"]

    assert equipos["198.51.100.2"]["upstream"] is True
    assert not any(e["upstream"] for ip, e in equipos.items() if ip != "198.51.100.2")


def test_inferir_topologia_enlaces_padre_hijo_con_interfaces():
    """La puerta de enlace es el padre del router consultado (el enlace se
    ve desde el lado del hijo: ether1); el resto de equipos son hijos."""
    enlaces = inferir_topologia([_router_casa()])["enlaces"]

    assert sorted(enlaces, key=lambda e: e["hijo"]) == [
        {"padre": "198.51.100.2", "hijo": "192.0.2.1", "interfaz_padre": None, "interfaz_hijo": "ether1"},
        {"padre": "192.0.2.1", "hijo": "192.0.2.254", "interfaz_padre": "ether2", "interfaz_hijo": None},
        {"padre": "192.0.2.1", "hijo": "192.0.2.44", "interfaz_padre": "ether3", "interfaz_hijo": None},
    ]


def test_inferir_topologia_redes_remotas_sin_las_conectadas_ni_la_ruta_por_defecto():
    """Una ruta cuyo siguiente salto está dentro de la propia red es una red
    conectada (el salto es el propio router), no otro router."""
    assert inferir_topologia([_router_casa()])["redes"] == {"10.0.10.0/24": "192.0.2.44"}


def test_inferir_topologia_ubica_cada_host():
    ubicaciones = inferir_topologia([_router_casa()])["ubicaciones"]

    assert ubicaciones == {
        # Puertos de acceso: cuelga del router, en esa interfaz
        MAC_MOVIL: {"ip": "192.0.2.30", "padre": "192.0.2.1", "interfaz": "wlan1"},
        MAC_CAMARA: {"ip": "192.0.2.40", "padre": "192.0.2.1", "interfaz": "ether4"},
        # Visto por un puerto que lleva a otro equipo: cuelga de ese equipo
        MAC_PC: {"ip": "192.0.2.20", "padre": "192.0.2.254", "interfaz": None},
        MAC_UDM_OTRA: {"ip": None, "padre": "192.0.2.44", "interfaz": None},
        # Solo en la ARP: se sabe que está en la red del router, no en qué puerto
        MAC_SOLO_ARP: {"ip": "192.0.2.50", "padre": "192.0.2.1", "interfaz": None},
    }


def test_inferir_topologia_varios_routers_consultados_sin_duplicar_enlaces():
    """Si también se consulta el UDM, su puerta de enlace es el router de
    casa: el enlace es el mismo que ya se dedujo desde arriba, no otro, y
    el UDM deja de ser 'no consultado'. Sus hosts de la LAN B salen con
    puerto, y un host visto por los dos se queda con la ubicación con
    puerto (la más precisa)."""
    udm = {
        "ip": "192.0.2.44",
        "nombre": "UDM",
        "interfaces": {1: "eth8", 2: "br0", 3: "eth1"},
        "arp": [{"ip": "192.0.2.1", "mac": "02:00:00:00:00:a1", "if_index": 1},
                {"ip": "10.0.10.10", "mac": "02:00:00:00:01:10", "if_index": 2}],
        "rutas": [{"red": "0.0.0.0/0", "siguiente_salto": "192.0.2.1"},
                  {"red": "10.0.10.0/24", "siguiente_salto": "10.0.10.1"}],
        "fdb": [{"mac": "02:00:00:00:01:10", "if_index": 3},
                {"mac": MAC_UDM_OTRA, "if_index": 3}],
        "vecinos": [],
    }

    topologia = inferir_topologia([_router_casa(), udm])

    enlaces_udm = [e for e in topologia["enlaces"] if "192.0.2.44" in (e["padre"], e["hijo"])]
    assert enlaces_udm == [
        {"padre": "192.0.2.1", "hijo": "192.0.2.44", "interfaz_padre": "ether3", "interfaz_hijo": "eth8"},
    ]
    assert topologia["equipos"]["192.0.2.44"]["consultado"] is True
    assert topologia["equipos"]["192.0.2.44"]["nombre"] == "UDM"
    assert topologia["equipos"]["192.0.2.1"]["upstream"] is False
    assert topologia["ubicaciones"]["02:00:00:00:01:10"] == {"ip": "10.0.10.10", "padre": "192.0.2.44",
                                                            "interfaz": "eth1"}
    assert topologia["ubicaciones"][MAC_UDM_OTRA] == {"ip": None, "padre": "192.0.2.44", "interfaz": "eth1"}
