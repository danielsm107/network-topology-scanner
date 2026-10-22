"""
demo_web.py
-----------
Abre la interfaz web con un escaneo inventado ya cargado, para las capturas
del README (docs/screenshots/dashboard.png e inventario.png). No escanea
nada: reutiliza los datos de demo_arbol.py, les añade un diff respecto a un
"escaneo anterior" (para que salga el panel de cambios) y los deja en
session_state antes de llamar a webapp.main(), como si el escaneo acabara
de terminar.

Uso:
    streamlit run scripts/demo_web.py
"""

from datetime import datetime, timedelta

import streamlit as st
from demo_arbol import datos_demo

from topology_scanner import webapp
from topology_scanner.classifier import PUERTOS_SENSIBLES

# SO como lo daría --os-detection, para que la columna del inventario no salga toda "unknown"
SO_DEMO = {"192.0.2.1": "MikroTik RouterOS 7.x", "192.0.2.10": "Synology DSM 7", "192.0.2.11": "Windows 11",
           "192.0.2.13": "Linux 6.x", "192.0.2.20": "Linux 6.x", "192.0.2.32": "macOS"}


def resultado_demo() -> dict:
    """Mismo formato que webapp._finalizar_resultados."""
    resultados, rangos, topologia = datos_demo()
    for ip, so in SO_DEMO.items():
        resultados[ip]["so"] = so
    diff = {
        "primera_vez": False,
        "hosts_nuevos": ["192.0.2.33"],
        "hosts_caidos": ["192.0.2.40"],
        "puertos_cambiados": {
            "192.0.2.11": {"nuevos": [3389], "cerrados": [],
                           "nuevos_sensibles": [{"puerto": 3389, "motivo": PUERTOS_SENSIBLES[3389]}]},
            "192.0.2.13": {"nuevos": [8080], "cerrados": [22], "nuevos_sensibles": []},
        },
    }
    return {"resultados": resultados, "diff": diff, "rango": " ".join(rangos), "rangos": rangos,
            "topologia": topologia, "avisos_snmp": []}


def historial_demo(*_args, **_kwargs) -> list:
    """Sustituye a history.listar_escaneos_recientes: el historial.db del
    directorio de trabajo es el de la red real de quien lance la demo."""
    def hace(**delta) -> str:
        return (datetime.now() - timedelta(**delta)).isoformat()

    return [
        {"rango": "192.0.2.0/24", "fecha": hace(minutes=3), "total_hosts": 11, "alertas": 2},
        {"rango": "198.51.100.0/24", "fecha": hace(minutes=3), "total_hosts": 2, "alertas": 0},
        {"rango": "192.0.2.0/24", "fecha": hace(days=1), "total_hosts": 11, "alertas": 1},
    ]


webapp.listar_escaneos_recientes = historial_demo
st.session_state.setdefault("rango_detectado", "192.0.2.0/24 198.51.100.0/24")
st.session_state.setdefault("resultado", resultado_demo())
webapp.main()
