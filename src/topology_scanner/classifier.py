"""
classifier.py
--------------
Deduce el tipo de dispositivo (router, PC, NAS, impresora...) a partir del
fabricante (vendor) que nmap obtiene de la MAC (OUI), y define el icono/color
que le corresponde en el grafo.

Es una heurística basada en palabras clave: un mismo fabricante puede hacer
routers, switches y APs a la vez, así que no es 100% preciso, pero da una
buena primera aproximación visual.
"""

# Palabras clave (en minúsculas) que suelen aparecer en el nombre del fabricante
CATEGORIA_POR_VENDOR = {
    "router": ["mikrotik", "ubiquiti", "tp-link", "d-link", "netgear", "asus", "cisco", "huawei technologies"],
    "firewall": ["fortinet"],
    "vm": ["vmware", "proxmox", "qemu", "virtualbox", "xen"],
    "nas": ["synology", "qnap", "western digital", "buffalo"],
    "printer": ["brother", "canon", "epson", "lexmark", "xerox"],
    "camera": ["axis communications", "hikvision", "dahua", "reolink"],
    "iot": ["raspberry pi", "espressif", "sonoff", "shelly", "tuya"],
    "mobile": ["samsung electronics", "xiaomi", "oneplus", "huawei device"],
    "apple": ["apple, inc", "apple inc"],
    "pc": ["dell inc", "lenovo", "intel corporate", "hewlett packard", "hp inc", "gigabyte", "asustek"],
}

# Icono Font Awesome 5 (unicode) + color por categoría de dispositivo
ICONOS_POR_CATEGORIA = {
    "router":      {"code": "\uf6ff", "color": "#3498db"},  # network-wired
    "firewall":    {"code": "\uf3ed", "color": "#e67e22"},  # shield-alt
    "vm":          {"code": "\uf0c2", "color": "#9b59b6"},  # cloud
    "nas":         {"code": "\uf0a0", "color": "#f1c40f"},  # hdd
    "printer":     {"code": "\uf02f", "color": "#95a5a6"},  # print
    "camera":      {"code": "\uf03d", "color": "#e74c3c"},  # video
    "iot":         {"code": "\uf2db", "color": "#1abc9c"},  # microchip
    "mobile":      {"code": "\uf3cd", "color": "#2ecc71"},  # mobile-alt
    "apple":       {"code": "\uf179", "color": "#ecf0f1"},  # apple
    "pc":          {"code": "\uf108", "color": "#2ecc71"},  # desktop
    "desconocido": {"code": "\uf059", "color": "#7f8c8d"},  # question-circle
}


def clasificar_dispositivo(vendor: str) -> str:
    """
    Devuelve la categoría de dispositivo deducida del nombre de fabricante.
    Si no hay vendor o no coincide con ninguna palabra clave, devuelve "desconocido".
    """
    if not vendor:
        return "desconocido"
    vendor_lower = vendor.lower()
    for categoria, palabras_clave in CATEGORIA_POR_VENDOR.items():
        if any(palabra in vendor_lower for palabra in palabras_clave):
            return categoria
    return "desconocido"


def icono_para_categoria(categoria: str) -> dict:
    """Devuelve el dict {code, color} de Font Awesome para una categoría dada."""
    return ICONOS_POR_CATEGORIA.get(categoria, ICONOS_POR_CATEGORIA["desconocido"])


# Puertos que merece la pena señalar si están abiertos: protocolos sin
# cifrar o servicios que son objetivo habitual de ataques (fuerza bruta,
# ransomware...). No es una lista exhaustiva de auditoría, es una primera
# señal visual de aviso.
PUERTOS_SENSIBLES = {
    21: "FTP (credenciales sin cifrar)",
    23: "Telnet (sin cifrar)",
    445: "SMB (vector típico de ransomware)",
    3389: "RDP (objetivo habitual de fuerza bruta)",
    5900: "VNC (a menudo sin autenticación)",
}


def puertos_sensibles_abiertos(puertos: list) -> list:
    """
    A partir de la lista de puertos abiertos de un host (formato de
    scanner.py: [{"puerto": .., "servicio": .., "producto": ..}, ...]),
    devuelve los que están en PUERTOS_SENSIBLES junto con el motivo.
    Lista vacía si no hay ninguno.
    """
    return [
        {"puerto": p["puerto"], "motivo": PUERTOS_SENSIBLES[p["puerto"]]}
        for p in puertos
        if p["puerto"] in PUERTOS_SENSIBLES
    ]
