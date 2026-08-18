"""
Tests de scanner.py usando unittest.mock para simular nmap.PortScanner
sin necesitar una red real ni el binario nmap instalado.
"""

from unittest.mock import MagicMock, patch

import nmap
import pytest

from topology_scanner.scanner import (
    escanear_red,
    descubrir_hosts_vivos,
    ScannerError,
    DEFAULT_NMAP_ARGS,
    PUERTOS_POR_DEFECTO,
)


class HostInfoFalso(dict):
    """Simula el objeto que nmap devuelve para un host (scanner[host])."""
    def __init__(self, estado="up", hostname="", mac="", vendor="", puertos_tcp=None, osmatch=None):
        super().__init__()
        self._estado = estado
        self["addresses"] = {"ipv4": "192.168.1.10"}
        if mac:
            self["addresses"]["mac"] = mac
            self["vendor"] = {mac: vendor}
        if puertos_tcp:
            self["tcp"] = puertos_tcp
        if osmatch:
            self["osmatch"] = osmatch
        self._hostname = hostname

    def state(self):
        return self._estado

    def hostname(self):
        return self._hostname


@patch("topology_scanner.scanner.nmap.PortScanner")
def test_descubrir_hosts_vivos_filtra_por_estado(mock_portscanner_cls):
    mock_scanner = MagicMock()
    mock_scanner.all_hosts.return_value = ["192.168.1.1", "192.168.1.2"]
    mock_scanner.__getitem__.side_effect = lambda ip: (
        HostInfoFalso(estado="up") if ip == "192.168.1.1" else HostInfoFalso(estado="down")
    )
    mock_portscanner_cls.return_value = mock_scanner

    vivos = descubrir_hosts_vivos("192.168.1.0/24")

    assert vivos == ["192.168.1.1"]


@patch("topology_scanner.scanner.nmap.PortScanner")
def test_escanear_red_sin_2_fases_parsea_host_correctamente(mock_portscanner_cls):
    mock_scanner = MagicMock()
    mock_scanner.all_hosts.return_value = ["192.168.1.10"]
    mock_scanner.__getitem__.return_value = HostInfoFalso(
        estado="up",
        hostname="server01",
        mac="AA:BB:CC:DD:EE:FF",
        vendor="Mikrotik",
        puertos_tcp={22: {"state": "open", "name": "ssh", "product": "OpenSSH"}},
    )
    mock_portscanner_cls.return_value = mock_scanner

    resultados = escanear_red("192.168.1.0/24", "22", "-sV -T4", dos_fases=False)

    assert "192.168.1.10" in resultados
    datos = resultados["192.168.1.10"]
    assert datos["hostname"] == "server01"
    assert datos["vendor"] == "Mikrotik"
    assert datos["categoria"] == "router"
    assert datos["puertos"][0]["servicio"] == "ssh"


@patch("topology_scanner.scanner.nmap.PortScanner")
def test_escanear_red_sin_hosts_devuelve_vacio(mock_portscanner_cls):
    mock_scanner = MagicMock()
    mock_scanner.all_hosts.return_value = []
    mock_portscanner_cls.return_value = mock_scanner

    resultados = escanear_red("192.168.1.0/24", "22", "-sV -T4", dos_fases=False)

    assert resultados == {}


@patch("topology_scanner.scanner.nmap.PortScanner")
def test_escanear_red_incluye_alertas_de_puertos_sensibles(mock_portscanner_cls):
    mock_scanner = MagicMock()
    mock_scanner.all_hosts.return_value = ["192.168.1.10"]
    mock_scanner.__getitem__.return_value = HostInfoFalso(
        estado="up",
        hostname="server01",
        puertos_tcp={
            3389: {"state": "open", "name": "ms-wbt-server", "product": ""},
            80: {"state": "open", "name": "http", "product": ""},
        },
    )
    mock_portscanner_cls.return_value = mock_scanner

    resultados = escanear_red("192.168.1.0/24", "80,3389", "-sV -T4", dos_fases=False)

    alertas = resultados["192.168.1.10"]["alertas"]
    assert len(alertas) == 1
    assert alertas[0]["puerto"] == 3389


@patch("topology_scanner.scanner.nmap.PortScanner")
def test_escanear_red_lanza_scannererror_si_nmap_no_esta_disponible(mock_portscanner_cls):
    """Si nmap.PortScanner() falla al construirse (p.ej. binario nmap no
    instalado), debe dar el mismo error amistoso que si falla scan() -
    no un traceback crudo sin capturar. La decisión de terminar el
    programa (sys.exit) es de cli.py, no de este módulo."""
    mock_portscanner_cls.side_effect = nmap.PortScannerError("nmap program was not found in path")

    with pytest.raises(ScannerError):
        escanear_red("192.168.1.0/24", "22", "-sV -T4", dos_fases=False)


def test_defaults_compartidos_por_cli_y_webapp():
    """DEFAULT_NMAP_ARGS y PUERTOS_POR_DEFECTO viven aquí como única fuente
    de verdad - antes estaban copiados literalmente en cli.py y webapp.py,
    con riesgo de desincronizarse si se cambiaba uno y no el otro."""
    assert DEFAULT_NMAP_ARGS == "-sV -T4"
    assert PUERTOS_POR_DEFECTO == "21-23,25,53,80,110,135,139,143,443,445,3389,8080"
