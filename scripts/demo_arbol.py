"""
demo_arbol.py
-------------
Genera el HTML del árbol SNMP con datos inventados, para la captura del
README (docs/screenshots/arbol-snmp.png). No escanea nada: monta a mano lo
que devolverían scanner.escanear_red y snmp.inferir_topologia y lo pasa por
el pipeline de verdad (construir_grafo -> exportar_html).

Todo es inventado: IPs de documentación (RFC 5737) y MACs locales 02:00:00:...
(lo comprueba tests/test_demo_arbol.py).

Uso:
    python scripts/demo_arbol.py [--output arbol_demo.html]
"""

import argparse

from topology_scanner.classifier import clasificar_dispositivo, puertos_sensibles_abiertos
from topology_scanner.export import exportar_html
from topology_scanner.graph import construir_grafo

RANGOS = ["192.0.2.0/24", "198.51.100.0/24"]

SERVICIOS = {22: "ssh", 53: "domain", 80: "http", 443: "https", 445: "microsoft-ds", 554: "rtsp",
             631: "ipp", 3389: "ms-wbt-server", 8080: "http-proxy", 8291: "unknown"}


def _host(hostname: str, mac: str, vendor: str, puertos: list[int]) -> dict:
    """Un host con el mismo formato que scanner.parsear_host."""
    abiertos = [{"puerto": p, "servicio": SERVICIOS[p], "producto": ""} for p in puertos]
    return {
        "estado": "up",
        "hostname": hostname,
        "so": "desconocido",
        "mac": mac,
        "vendor": vendor,
        "categoria": clasificar_dispositivo(vendor),
        "puertos": abiertos,
        "alertas": puertos_sensibles_abiertos(abiertos),
    }


def _equipo(nombre: str, plataforma: str = "", version: str = "", mac: str | None = None,
            consultado: bool = False, upstream: bool = False) -> dict:
    return {"nombre": nombre, "plataforma": plataforma, "version": version, "mac": mac,
            "consultado": consultado, "upstream": upstream}


def datos_demo() -> tuple[dict, list[str], dict]:
    """(resultados, rangos, topologia): una casa con un router, un switch en
    el salón, un AP en la planta de arriba y una VLAN para las cámaras."""
    resultados = {
        # Equipos de red (nmap también los ve)
        "192.0.2.1": _host("router-core", "02:00:00:00:00:01", "Routerboard.com", [22, 53, 80, 8291]),
        "192.0.2.2": _host("switch-salon", "02:00:00:00:00:02", "Routerboard.com", [80]),
        "192.0.2.3": _host("ap-planta-alta", "02:00:00:00:00:03", "Ubiquiti Networks", [22, 443]),
        # Detrás del switch
        "192.0.2.10": _host("nas", "02:00:00:00:00:10", "Synology Incorporated", [22, 80, 443, 445]),
        "192.0.2.11": _host("pc-oficina", "02:00:00:00:00:11", "Dell Inc.", [3389]),
        "192.0.2.12": _host("impresora", "02:00:00:00:00:12", "Brother Industries", [80, 631]),
        "192.0.2.13": _host("vm-docker", "02:00:00:00:00:13", "QEMU virtual NIC", [22, 8080]),
        # Directo al router
        "192.0.2.20": _host("raspberrypi", "02:00:00:00:00:20", "Raspberry Pi Trading", [22, 53, 80]),
        # WiFi del AP
        "192.0.2.31": _host("galaxy-s24", "02:00:00:00:00:31", "Samsung Electronics", []),
        "192.0.2.32": _host("macbook", "02:00:00:00:00:32", "Apple, Inc.", [22]),
        "192.0.2.33": _host("enchufe-salon", "02:00:00:00:00:33", "Espressif Inc.", [80]),
        # VLAN de cámaras
        "198.51.100.20": _host("camara-entrada", "02:00:00:00:01:20", "Hangzhou Hikvision Digital", [80, 554]),
        "198.51.100.21": _host("camara-jardin", "02:00:00:00:01:21", "Reolink Innovation", [80, 554]),
    }

    topologia = {
        "equipos": {
            "203.0.113.1": _equipo("ISP", upstream=True),
            "192.0.2.1": _equipo("router-core", "MikroTik", "RouterOS 7.16", "02:00:00:00:00:01", consultado=True),
            "192.0.2.2": _equipo("switch-salon", "MikroTik", "SwOS 2.17", "02:00:00:00:00:02"),
            "192.0.2.3": _equipo("ap-planta-alta", "Ubiquiti", "UniFi 6.6", "02:00:00:00:00:03", consultado=True),
        },
        "enlaces": [
            {"padre": "203.0.113.1", "hijo": "192.0.2.1", "interfaz_padre": None, "interfaz_hijo": "ether1"},
            {"padre": "192.0.2.1", "hijo": "192.0.2.2", "interfaz_padre": "ether2", "interfaz_hijo": "port1"},
            {"padre": "192.0.2.1", "hijo": "192.0.2.3", "interfaz_padre": "ether3", "interfaz_hijo": "eth0"},
        ],
        "redes": {},
        "ubicaciones": {
            # El switch no se consulta: se sabe que están detrás de él, no en qué puerto
            "02:00:00:00:00:10": {"ip": "192.0.2.10", "padre": "192.0.2.2", "interfaz": None},
            "02:00:00:00:00:11": {"ip": "192.0.2.11", "padre": "192.0.2.2", "interfaz": None},
            "02:00:00:00:00:12": {"ip": "192.0.2.12", "padre": "192.0.2.2", "interfaz": None},
            "02:00:00:00:00:13": {"ip": "192.0.2.13", "padre": "192.0.2.2", "interfaz": None},
            "02:00:00:00:00:20": {"ip": "192.0.2.20", "padre": "192.0.2.1", "interfaz": "ether4"},
            "02:00:00:00:00:31": {"ip": "192.0.2.31", "padre": "192.0.2.3", "interfaz": "wlan1"},
            "02:00:00:00:00:32": {"ip": "192.0.2.32", "padre": "192.0.2.3", "interfaz": "wlan1"},
            "02:00:00:00:00:33": {"ip": "192.0.2.33", "padre": "192.0.2.3", "interfaz": "wlan2"},
            # Visto solo por SNMP (nmap no lo detectó)
            "02:00:00:00:00:99": {"ip": None, "padre": "192.0.2.3", "interfaz": "wlan2"},
            "02:00:00:00:01:20": {"ip": "198.51.100.20", "padre": "192.0.2.1", "interfaz": "vlan-camaras"},
            "02:00:00:00:01:21": {"ip": "198.51.100.21", "padre": "192.0.2.1", "interfaz": "vlan-camaras"},
        },
    }
    return resultados, RANGOS, topologia


def generar(archivo_salida: str):
    resultados, rangos, topologia = datos_demo()
    exportar_html(construir_grafo(resultados, rangos, topologia), archivo_salida)


def main():
    parser = argparse.ArgumentParser(description="Genera el árbol SNMP de demo (datos inventados).")
    parser.add_argument("--output", default="arbol_demo.html", help="HTML de salida (por defecto: %(default)s)")
    generar(parser.parse_args().output)


if __name__ == "__main__":
    main()
