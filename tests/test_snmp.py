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
    OID_FDB_ESTADO,
    OID_FDB_PUERTO,
    OID_IF_NAME,
    OID_LLDP_GESTION,
    OID_LLDP_PUERTOS_LOCALES,
    OID_LLDP_REMOTOS,
    OID_PUERTO_A_IFINDEX,
    OID_RUTAS,
    OID_SYS_NAME,
    OID_VECINOS_MIKROTIK,
    TABLAS_A_CONSULTAR,
    CredencialesV3,
    SnmpError,
    _recorrer,
    combinar_vecinos,
    consultar_equipo,
    credenciales_desde_entorno,
    inferir_topologia,
    obtener_topologia,
    parsear_arp,
    parsear_fdb,
    parsear_interfaces,
    parsear_lista_ips,
    parsear_nombre,
    parsear_rutas,
    parsear_vecinos_lldp,
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


def test_parsear_fdb_descarta_las_macs_propias_del_equipo():
    """dot1dTpFdbStatus: learned(3) es un host de verdad; self(4) es la MAC
    de un puerto del propio switch/router (el hAP mete ahí la de cada uno
    de sus puertos, que salían como "hosts" en el grafo); invalid(2) es
    basura. Las demás (other, mgmt) se conservan."""
    mac_propia = "02:00:00:00:f9:7b"
    filas_fdb = [
        (f"{OID_FDB_PUERTO}.{_mac_en_oid(MAC_PC)}", 1),
        (f"{OID_FDB_PUERTO}.{_mac_en_oid(mac_propia)}", 1),
        (f"{OID_FDB_PUERTO}.{_mac_en_oid(MAC_MOVIL)}", 6),
        (f"{OID_FDB_PUERTO}.{_mac_en_oid(MAC_UDM)}", 3),
    ]
    filas_estado = [
        (f"{OID_FDB_ESTADO}.{_mac_en_oid(MAC_PC)}", 3),
        (f"{OID_FDB_ESTADO}.{_mac_en_oid(mac_propia)}", 4),
        (f"{OID_FDB_ESTADO}.{_mac_en_oid(MAC_MOVIL)}", 2),
        (f"{OID_FDB_ESTADO}.{_mac_en_oid(MAC_UDM)}", 5),
    ]

    assert parsear_fdb(filas_fdb, _filas_puerto_a_ifindex(), filas_estado) == [
        {"mac": MAC_PC, "if_index": 4},
        {"mac": MAC_UDM, "if_index": 5},
    ]


def test_parsear_fdb_sin_tabla_de_estado_conserva_todo():
    """Un equipo que no implemente dot1dTpFdbStatus no debe quedarse sin
    tabla MAC: sin estado, no se descarta nada por ese motivo."""
    filas_fdb = [(f"{OID_FDB_PUERTO}.{_mac_en_oid(MAC_PC)}", 1)]

    assert parsear_fdb(filas_fdb, _filas_puerto_a_ifindex(), []) == [{"mac": MAC_PC, "if_index": 4}]


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


@patch("topology_scanner.snmp._recorrer")
def test_consultar_equipo_filtra_las_macs_propias_con_la_tabla_de_estado(mock_recorrer):
    mac_propia = "02:00:00:00:f9:7b"
    mock_recorrer.return_value = {
        OID_PUERTO_A_IFINDEX: [(f"{OID_PUERTO_A_IFINDEX}.1", 4)],
        OID_FDB_PUERTO: [(f"{OID_FDB_PUERTO}.{_mac_en_oid(MAC_PC)}", 1),
                         (f"{OID_FDB_PUERTO}.{_mac_en_oid(mac_propia)}", 1)],
        OID_FDB_ESTADO: [(f"{OID_FDB_ESTADO}.{_mac_en_oid(MAC_PC)}", 3),
                         (f"{OID_FDB_ESTADO}.{_mac_en_oid(mac_propia)}", 4)],
    }

    assert consultar_equipo("192.0.2.1", "community")["fdb"] == [{"mac": MAC_PC, "if_index": 4}]
    assert OID_FDB_ESTADO in TABLAS_A_CONSULTAR


# === Orquestación (compartida por CLI y web) ================================

def test_parsear_lista_ips_separa_por_comas_y_quita_espacios():
    assert parsear_lista_ips(" 192.0.2.1, 192.0.2.2 ,") == ["192.0.2.1", "192.0.2.2"]


def test_parsear_lista_ips_rechaza_lo_que_no_es_una_ipv4():
    with pytest.raises(ValueError, match="router-casa"):
        parsear_lista_ips("192.0.2.1,router-casa")


@patch("topology_scanner.snmp.inferir_topologia")
@patch("topology_scanner.snmp.consultar_equipo")
def test_obtener_topologia_salta_los_que_no_responden_y_lo_avisa(mock_consultar, mock_inferir):
    mock_consultar.side_effect = [SnmpError("192.0.2.1 no responde por SNMP"), {"ip": "192.0.2.2"}]
    mock_inferir.return_value = {"equipos": {}, "enlaces": [], "redes": {}, "ubicaciones": {}}

    topologia, avisos = obtener_topologia(["192.0.2.1", "192.0.2.2"], "community")

    mock_inferir.assert_called_once_with([{"ip": "192.0.2.2"}])
    assert topologia == mock_inferir.return_value
    assert avisos == ["192.0.2.1 no responde por SNMP"]


@patch("topology_scanner.snmp.inferir_topologia")
@patch("topology_scanner.snmp.consultar_equipo", side_effect=SnmpError("192.0.2.1 no responde por SNMP"))
def test_obtener_topologia_si_no_responde_ninguno_devuelve_none(_mock_consultar, mock_inferir):
    """None = dibujar la estrella: el escaneo de nmap ya ha funcionado y
    perder la topología no es motivo para no mostrar nada."""
    topologia, avisos = obtener_topologia(["192.0.2.1"], "community")

    assert topologia is None
    mock_inferir.assert_not_called()
    assert avisos[-1].endswith("se dibuja la topología en estrella.")


def test_inferir_topologia_ignora_las_rutas_sin_siguiente_salto():
    """Las rutas por interfaz (túneles VPN, PPPoE...) llegan con siguiente
    salto 0.0.0.0: no apuntan a ningún router. Sin filtrarlas, aparecía un
    "equipo" con IP 0.0.0.0 como hijo, o como puerta de enlace upstream si
    la ruta por defecto iba por interfaz."""
    router = _router_casa()
    router["rutas"] = [
        {"red": "0.0.0.0/0", "siguiente_salto": "0.0.0.0"},        # por defecto vía PPPoE
        {"red": "10.201.100.0/28", "siguiente_salto": "0.0.0.0"},  # vía túnel WireGuard
        {"red": "10.0.10.0/24", "siguiente_salto": "192.0.2.44"},
    ]

    topologia = inferir_topologia([router])

    assert "0.0.0.0" not in topologia["equipos"]
    assert topologia["redes"] == {"10.0.10.0/24": "192.0.2.44"}
    assert not any("0.0.0.0" in (e["padre"], e["hijo"]) for e in topologia["enlaces"])


# === LLDP-MIB estándar ======================================================
#
# Dos variantes: la del estándar (IEEE 802.1AB), escrita a partir de la
# especificación, y la de RouterOS v6, que reproduce (anonimizado) lo que
# devolvió un hAP ac2 real: puerto local siempre 0 y la IP de gestión como
# texto en una columna, en vez de dentro del índice.

def _filas_lldp_remotos(vecinos, mac_como_texto=False):
    """vecinos = {(puerto_local, indice_remoto): (mac, puerto_remoto, nombre, descripcion)}.
    Índice de lldpRemTable = timeMark.localPortNum.remIndex. El estándar
    manda la MAC del chassis en 6 bytes; RouterOS v6, como texto
    "C4:AD:34:..." (mac_como_texto=True)."""
    filas = []
    for (puerto_local, indice), (mac, puerto, nombre, descripcion) in vecinos.items():
        sufijo = f"0.{puerto_local}.{indice}"
        filas += [
            (f"{OID_LLDP_REMOTOS}.4.{sufijo}", 4),             # chassis = macAddress(4)
            (f"{OID_LLDP_REMOTOS}.5.{sufijo}", mac.upper().encode() if mac_como_texto else _mac(mac)),
            (f"{OID_LLDP_REMOTOS}.6.{sufijo}", 5),             # puerto = interfaceName(5)
            (f"{OID_LLDP_REMOTOS}.7.{sufijo}", puerto.encode()),
            (f"{OID_LLDP_REMOTOS}.9.{sufijo}", nombre.encode()),
            (f"{OID_LLDP_REMOTOS}.10.{sufijo}", descripcion.encode()),
        ]
    return filas


def test_parsear_vecinos_lldp_formato_estandar():
    """Puerto local por lldpLocPortTable (su número no tiene por qué ser el
    ifIndex: se empareja por nombre con ifName) e IP de gestión dentro del
    índice de lldpRemManAddrTable (subtipo 1 = IPv4, longitud 4, 4 bytes)."""
    remotos = _filas_lldp_remotos({
        (1, 7): (MAC_UPSTREAM, "ge-0/0/5", "Upstream", "Switch de ejemplo"),
        (2, 8): (MAC_AP, "eth0", "AP-Interior", "AP de ejemplo"),
    })
    locales = [(f"{OID_LLDP_PUERTOS_LOCALES}.4.1", b"ether1"), (f"{OID_LLDP_PUERTOS_LOCALES}.4.2", b"ether2")]
    gestion = [
        (f"{OID_LLDP_GESTION}.3.0.1.7.1.4.198.51.100.2", 2),   # lldpRemManAddrIfSubtype
        (f"{OID_LLDP_GESTION}.3.0.2.8.1.4.192.0.2.254", 2),
    ]

    vecinos = parsear_vecinos_lldp(remotos, locales, gestion, {3: "ether1", 4: "ether2"})

    assert vecinos == [
        {"ip": "198.51.100.2", "mac": MAC_UPSTREAM, "identidad": "Upstream", "plataforma": "Switch de ejemplo",
         "version": "", "if_index": 3, "interfaz_remota": "ge-0/0/5"},
        {"ip": "192.0.2.254", "mac": MAC_AP, "identidad": "AP-Interior", "plataforma": "AP de ejemplo",
         "version": "", "if_index": 4, "interfaz_remota": "eth0"},
    ]


def test_parsear_vecinos_lldp_formato_routeros_v6():
    remotos = _filas_lldp_remotos({
        (0, 1): (MAC_UPSTREAM, "ether5", "Upstream", "MikroTik RouterOS 6.48.5 (long-term) RB750Gr3"),
        (0, 2): (MAC_AP, "bridge/ether1", "AP-Interior", "MikroTik RouterOS 6.49.19 (stable) RBcAPGi-5acD2nD"),
    }, mac_como_texto=True)
    gestion = [
        (f"{OID_LLDP_GESTION}.1.0.0.1", 1), (f"{OID_LLDP_GESTION}.2.0.0.1", b"198.51.100.2"),
        (f"{OID_LLDP_GESTION}.1.0.0.2", 1), (f"{OID_LLDP_GESTION}.2.0.0.2", b"192.0.2.254"),
    ]

    vecinos = parsear_vecinos_lldp(remotos, [], gestion, {3: "ether1", 4: "ether2"})

    assert [(v["ip"], v["mac"], v["if_index"], v["interfaz_remota"]) for v in vecinos] == [
        ("198.51.100.2", MAC_UPSTREAM, None, "ether5"),        # puerto local 0: no se sabe
        ("192.0.2.254", MAC_AP, None, "bridge/ether1"),
    ]


def test_parsear_vecinos_lldp_sin_ip_de_gestion_o_con_0000():
    remotos = _filas_lldp_remotos({(0, 21): (MAC_PC, "", "", ""), (0, 22): (MAC_MOVIL, "", "", "")})
    gestion = [(f"{OID_LLDP_GESTION}.2.0.0.21", b"0.0.0.0")]

    vecinos = parsear_vecinos_lldp(remotos, [], gestion, {})

    assert [v["ip"] for v in vecinos] == [None, None]
    assert [v["interfaz_remota"] for v in vecinos] == [None, None]


def test_combinar_vecinos_completa_con_lldp_y_anade_los_que_solo_estan_ahi():
    """La tabla de MikroTik sabe el puerto local; LLDP, el del otro extremo
    (y en RouterOS v6 no sabe el local). Se juntan por MAC; un vecino que
    solo anuncia LLDP (un switch de otra marca) se añade tal cual."""
    mikrotik = [{"ip": "192.0.2.254", "mac": MAC_AP, "identidad": "AP-Interior", "plataforma": "MikroTik",
                 "version": "6.49.19", "if_index": 4}]
    lldp = [
        {"ip": "192.0.2.254", "mac": MAC_AP, "identidad": "AP-Interior", "plataforma": "MikroTik RouterOS ...",
         "version": "", "if_index": None, "interfaz_remota": "bridge/ether1"},
        {"ip": "192.0.2.50", "mac": "02:00:00:00:00:50", "identidad": "Switch-Garaje", "plataforma": "Otro",
         "version": "", "if_index": 5, "interfaz_remota": "port3"},
    ]

    assert combinar_vecinos(mikrotik, lldp) == [
        {"ip": "192.0.2.254", "mac": MAC_AP, "identidad": "AP-Interior", "plataforma": "MikroTik",
         "version": "6.49.19", "if_index": 4, "interfaz_remota": "bridge/ether1"},
        {"ip": "192.0.2.50", "mac": "02:00:00:00:00:50", "identidad": "Switch-Garaje", "plataforma": "Otro",
         "version": "", "if_index": 5, "interfaz_remota": "port3"},
    ]


def test_inferir_topologia_usa_la_interfaz_remota_de_lldp():
    router = _router_casa()
    for vecino in router["vecinos"]:
        vecino["interfaz_remota"] = {"Upstream": "ether5", "AP-Interior": "bridge/ether1"}.get(vecino["identidad"])

    enlaces = {(e["padre"], e["hijo"]): e for e in inferir_topologia([router])["enlaces"]}

    # El upstream es el padre: su puerto (ether5) es el del lado del padre
    assert enlaces["198.51.100.2", "192.0.2.1"]["interfaz_padre"] == "ether5"
    assert enlaces["198.51.100.2", "192.0.2.1"]["interfaz_hijo"] == "ether1"
    assert enlaces["192.0.2.1", "192.0.2.254"]["interfaz_padre"] == "ether2"
    assert enlaces["192.0.2.1", "192.0.2.254"]["interfaz_hijo"] == "bridge/ether1"


@patch("topology_scanner.snmp._recorrer")
def test_consultar_equipo_junta_los_vecinos_de_mikrotik_y_lldp(mock_recorrer):
    sufijo = "0.0.2"
    mock_recorrer.return_value = {
        OID_LLDP_REMOTOS: [(f"{OID_LLDP_REMOTOS}.5.{sufijo}", _mac(MAC_AP)), (f"{OID_LLDP_REMOTOS}.4.{sufijo}", 4),
                           (f"{OID_LLDP_REMOTOS}.6.{sufijo}", 5),
                           (f"{OID_LLDP_REMOTOS}.7.{sufijo}", b"bridge/ether1"),
                           (f"{OID_LLDP_REMOTOS}.9.{sufijo}", b"AP-Interior")],
    }

    vecinos = consultar_equipo("192.0.2.1", "community")["vecinos"]

    assert [(v["identidad"], v["interfaz_remota"]) for v in vecinos] == [("AP-Interior", "bridge/ether1")]
    assert {OID_LLDP_REMOTOS, OID_LLDP_PUERTOS_LOCALES, OID_LLDP_GESTION} <= set(TABLAS_A_CONSULTAR)


# === SNMPv3 =================================================================

def test_credenciales_v3_no_muestran_las_claves_en_el_repr():
    """Un traceback o un log con el objeto no deben filtrar las claves."""
    credenciales = CredencialesV3("lector", "clave-auth-secreta", "clave-priv-secreta")

    assert "clave-auth-secreta" not in repr(credenciales)
    assert "clave-priv-secreta" not in repr(credenciales)
    assert "lector" in repr(credenciales)


def test_credenciales_v3_por_defecto_sha_y_aes():
    """SHA + AES-128: lo que soporta RouterOS v6."""
    credenciales = CredencialesV3("lector", "clave-auth", "clave-priv")

    assert (credenciales.protocolo_auth, credenciales.protocolo_priv) == ("SHA", "AES")


@pytest.mark.parametrize("argumentos, mensaje", [
    (("", "clave-auth"), "usuario"),
    (("lector", "corta"), "8 caracteres"),
    (("lector", "clave-auth", "corta"), "8 caracteres"),
    (("lector", "clave-auth", "", "SHA999"), "SHA999"),
    (("lector", "clave-auth", "clave-priv", "SHA", "ROT13"), "ROT13"),
])
def test_credenciales_v3_se_validan_al_crearlas(argumentos, mensaje):
    with pytest.raises(ValueError, match=mensaje):
        CredencialesV3(*argumentos)


def test_credenciales_v3_los_protocolos_no_distinguen_mayusculas():
    assert CredencialesV3("lector", "clave-auth", "", "sha256").protocolo_auth == "SHA256"


def test_credenciales_desde_entorno_v3_si_hay_usuario():
    entorno = {"TOPOLOGY_SNMP_USER": "lector", "TOPOLOGY_SNMP_AUTH_KEY": "clave-auth",
               "TOPOLOGY_SNMP_PRIV_KEY": "clave-priv", "TOPOLOGY_SNMP_AUTH_PROTO": "SHA256",
               "TOPOLOGY_SNMP_COMMUNITY": "ignorada-si-hay-v3"}

    assert credenciales_desde_entorno(entorno) == CredencialesV3("lector", "clave-auth", "clave-priv", "SHA256")


def test_credenciales_desde_entorno_v2c_con_la_community():
    assert credenciales_desde_entorno({"TOPOLOGY_SNMP_COMMUNITY": "publica-no"}) == "publica-no"


def test_credenciales_desde_entorno_sin_nada_es_none():
    assert credenciales_desde_entorno({}) is None


def test_credenciales_desde_entorno_v3_mal_configurado_es_un_error():
    with pytest.raises(ValueError, match="8 caracteres"):
        credenciales_desde_entorno({"TOPOLOGY_SNMP_USER": "lector", "TOPOLOGY_SNMP_AUTH_KEY": "corta"})


def test_recorrer_con_v3_usa_usm_con_los_protocolos_elegidos(pysnmp_falso):
    from pysnmp.hlapi.v3arch import asyncio as hlapi

    credenciales = CredencialesV3("lector", "clave-auth", "clave-priv", "SHA256", "AES256")
    with pysnmp_falso([[]]), patch(f"{MODULO_PYSNMP}.UsmUserData") as mock_usm:
        _recorrer("192.0.2.1", credenciales, (OID_SYS_NAME,), 1, 0)

    mock_usm.assert_called_once_with(
        "lector", "clave-auth", "clave-priv",
        authProtocol=hlapi.usmHMAC192SHA256AuthProtocol, privProtocol=hlapi.usmAesCfb256Protocol,
    )


def test_recorrer_con_v3_sin_clave_de_cifrado_es_auth_no_priv(pysnmp_falso):
    from pysnmp.hlapi.v3arch import asyncio as hlapi

    with pysnmp_falso([[]]), patch(f"{MODULO_PYSNMP}.UsmUserData") as mock_usm:
        _recorrer("192.0.2.1", CredencialesV3("lector", "clave-auth"), (OID_SYS_NAME,), 1, 0)

    assert mock_usm.call_args.kwargs["privProtocol"] == hlapi.usmNoPrivProtocol


@pytest.mark.parametrize("error, pista", [
    ("unknownUserName", "usuario"),
    ("wrongDigest", "autenticación"),
    ("decryptionError", "cifrado"),
    ("unsupportedSecurityLevel", "nivel de seguridad"),
])
def test_recorrer_explica_los_errores_tipicos_de_v3(pysnmp_falso, error, pista):
    from pysnmp.proto import errind

    credenciales = CredencialesV3("lector", "clave-auth-secreta", "clave-priv-secreta")
    with pysnmp_falso([[(getattr(errind, error), 0, [])]]), pytest.raises(SnmpError) as excinfo:
        _recorrer("192.0.2.1", credenciales, (OID_SYS_NAME,), 1, 0)

    mensaje = str(excinfo.value)
    assert pista in mensaje
    assert "clave-auth-secreta" not in mensaje and "clave-priv-secreta" not in mensaje


def test_v3_con_cifrado_sin_cryptography_da_un_error_claro_antes_de_consultar():
    """pysnmp necesita `cryptography` para AES/DES pero no la declara como
    dependencia: sin ella fallaba con "Ciphering services not available" y
    el mensaje decía que el equipo no respondía (visto con un hAP real)."""
    pytest.importorskip(MODULO_PYSNMP)
    credenciales = CredencialesV3("lector", "clave-auth", "clave-priv")

    with patch.dict(sys.modules, {"cryptography": None}), pytest.raises(SnmpError, match="cryptography") as excinfo:
        _recorrer("192.0.2.1", credenciales, (OID_SYS_NAME,), 1, 0)

    assert r"[snmp]" in str(excinfo.value)
    assert "no responde" not in str(excinfo.value)


def test_recorrer_un_fallo_local_de_cifrado_no_dice_que_el_equipo_no_responde(pysnmp_falso):
    from pysnmp.proto import errind

    credenciales = CredencialesV3("lector", "clave-auth", "clave-priv")
    with pysnmp_falso([[(errind.encryptionError, 0, [])]]), pytest.raises(SnmpError) as excinfo:
        _recorrer("192.0.2.1", credenciales, (OID_SYS_NAME,), 1, 0)

    assert "cryptography" in str(excinfo.value)
    assert "no responde" not in str(excinfo.value)
