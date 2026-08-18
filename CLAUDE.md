# network-topology-scanner

Escáner de topología de red en Python: descubre hosts activos en un rango de
red, escanea sus puertos/servicios, identifica el fabricante y tipo de
dispositivo a partir de la MAC, y genera un grafo interactivo en HTML con
iconos por categoría (router, PC, NAS, impresora, cámara, etc.).

## Contexto de quien lo mantiene

Administrador de Sistemas junior (redes, Linux, AWS, Docker), en aprendizaje
activo de Python. El objetivo del proyecto es doble: herramienta útil para el
homelab/trabajo, y pieza de portfolio para entrevistas — así que se valora
tanto que funcione bien como que el código esté limpio, testeado y con buen
historial de commits (features pequeñas, un commit por feature).

## Stack

- Python 3.9+, paquete instalable (`pyproject.toml`, layout `src/`)
- `python-nmap` (wrapper de nmap), `networkx` (grafo), `pyvis` (export HTML interactivo)
- Tests con `pytest` + `unittest.mock` (mockean `nmap.PortScanner`, no requieren red real ni nmap instalado)
- Entorno de trabajo: Windows + VS Code + Git Bash

## Estructura

```
src/topology_scanner/
├── scanner.py      # Todo lo de nmap: descubrimiento (fase 1, ping scan) + escaneo completo (fase 2)
├── classifier.py   # clasificar_dispositivo(vendor) -> categoría, iconos por categoría
├── graph.py        # construir_grafo(resultados, rango) -> networkx.Graph (topología en estrella)
├── export.py       # exportar_html (pyvis + iconos Font Awesome vía CDN), exportar_texto
└── cli.py          # argparse, orquesta scanner -> graph -> export
tests/               # un test_<modulo>.py por módulo
```

**Principio de diseño**: cada módulo no sabe nada de los demás salvo lo
imprescindible. `scanner.py` no conoce grafos, `graph.py` no conoce nmap,
`export.py` no conoce cómo se escanea. Esto es intencional — al añadir una
feature, hay que decidir en qué módulo encaja (o si merece uno nuevo) antes
de escribir código.

## Decisiones ya tomadas (no las cuestiones sin preguntar)

- La topología es una **estrella aproximada** (nodo central = red, hosts
  colgando), no la topología física real. Para eso haría falta SNMP o
  traceroute — ver roadmap.
- La clasificación de dispositivo por MAC es una **heurística por palabras
  clave** sobre el nombre del vendor (ver `CATEGORIA_POR_VENDOR` en
  `classifier.py`), no un lookup exacto. Limitación conocida y aceptada: solo
  funciona si el host está en el mismo segmento L2 que quien escanea (ARP no
  cruza routers/VLANs).
- Por defecto se hace descubrimiento en 2 fases (ping scan rápido, luego
  escaneo completo solo de los hosts vivos) porque escanear un /24 completo
  con `-sV -O` era demasiado lento.
- `-O` (detección de SO) está desactivado por defecto por lentitud; se activa
  con `--con-so`.
- El HTML usa `height: 100vh` + CSS inyectado a mano (no confiar solo en lo
  que genera pyvis) para que el grafo ocupe toda la ventana del navegador.

## Roadmap (por orden de prioridad hablado)

1. **Alertas por puertos sensibles** — marcar visualmente (icono/color de
   aviso) hosts con RDP (3389), Telnet (23), SMB (445) u otros puertos
   sensibles abiertos. Aporta valor de seguridad, conecta con certificación
   ISO 27001 del mantenedor.
2. **Historial en SQLite** — guardar cada escaneo con fecha y comparar contra
   el anterior: hosts nuevos, hosts caídos, puertos que han cambiado de
   estado. Módulo nuevo, probablemente `history.py`.
3. **Exportar a CSV** — IP, hostname, MAC, vendor, SO, puertos — para
   inventario/auditoría.
4. **Leyenda visual en el HTML** — panel fijo explicando qué icono/color es
   cada categoría de dispositivo.
5. **Topología real vía SNMP** — consultar tablas ARP/CDP/LLDP de los
   MikroTik/Fortinet del mantenedor para topología real en vez de estrella
   aproximada. La feature más compleja, dejar para el final.
6. **Interfaz web con Streamlit** — envolver el CLI en una web local con
   botón de escaneo y el grafo embebido.
7. **CI con GitHub Actions** — ejecutar pytest + ruff en cada push, badge en
   el README.

## Forma de trabajar preferida

- Features pequeñas, un commit por feature, mensajes descriptivos.
- Test primero (aunque sea simple) antes de implementar la función.
- `pytest tests/ -v` debe seguir en verde antes de cualquier commit.
- Explicar brevemente en qué módulo encaja cada cambio y por qué, no solo
  soltar el código — el mantenedor está aprendiendo Python activamente.

## Aviso legal (recordar si se toca algo relacionado con el escaneo)

Esta herramienta solo debe usarse contra redes propias o con autorización
explícita. No añadir features que faciliten el escaneo de redes ajenas sin
permiso.
