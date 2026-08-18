# Network Topology Scanner

Escanea un rango de red, detecta hosts activos, sus puertos/servicios, fabricante
(vía MAC) y tipo de dispositivo, y genera un grafo de topología interactivo en
HTML con iconos por categoría (router, PC, NAS, impresora, etc.). Marca en rojo
los hosts con puertos sensibles abiertos (Telnet, SMB, RDP, FTP, VNC), guarda
cada escaneo en SQLite para comparar con el anterior (hosts nuevos/caídos,
puertos que cambian), y puede exportar el inventario a CSV. Disponible como
CLI o como interfaz web local (Streamlit, opcional).

## ⚠️ Aviso legal
Usa esta herramienta **solo en redes propias o con autorización explícita**
(tu homelab, o la red del trabajo si tienes permiso). Escanear redes ajenas
sin consentimiento es ilegal en España y en la mayoría de países.

## Estructura del proyecto

```
network-topology-scanner/
├── src/topology_scanner/
│   ├── scanner.py        # Escaneo con nmap (descubrimiento + puertos)
│   ├── classifier.py      # Clasificación de dispositivo por MAC/vendor
│   ├── graph.py            # Construcción del grafo (networkx)
│   ├── export.py           # Exportación a HTML (pyvis), texto y CSV
│   ├── history.py          # Historial de escaneos en SQLite (diff vs. el anterior)
│   ├── cli.py               # Interfaz de línea de comandos
│   └── webapp.py            # Interfaz web (Streamlit, opcional)
├── tests/                   # pytest, con mocks de nmap (sin red real)
└── pyproject.toml           # única fuente de dependencias (pip install -e ".[dev,web]")
```

## Instalación

```bash
# Dependencia del sistema
sudo apt install nmap        # Linux
# En Windows: descarga el instalador desde nmap.org

# Entorno virtual
python3 -m venv venv
source venv/bin/activate      # Linux/Mac
# venv\Scripts\Activate.ps1   # Windows PowerShell

# Instalación del paquete (modo editable, incluye dependencias de dev)
pip install -e ".[dev]"

# Opcional, solo si quieres la interfaz web
pip install -e ".[web]"
```

## Uso

```bash
sudo topology-scanner 192.168.1.0/24
sudo topology-scanner 192.168.1.0/24 --rapido
sudo topology-scanner 192.168.1.0/24 --con-so --output mi_red.html

# Alternativa sin entry point instalado:
sudo python3 -m topology_scanner 192.168.1.0/24
```

| Flag            | Descripción                                               | Por defecto     |
|-----------------|-------------------------------------------------------------|-----------------|
| `rango`         | Rango CIDR a escanear                                       | (obligatorio)   |
| `--ports`       | Puertos a escanear (formato nmap)                             | puertos comunes |
| `--nmap-args`   | Argumentos extra para nmap                                    | `-sV -T4`       |
| `--output`      | Nombre del HTML de salida                                      | `topologia_red.html` |
| `--con-so`      | Activa detección de SO (-O), la opción más lenta                 | desactivado     |
| `--sin-2-fases` | Desactiva el ping scan previo, escanea el rango completo directo | desactivado     |
| `--rapido`      | Preset de máxima velocidad, solo puertos (incompatible con `--con-so`/`--nmap-args`) | desactivado |
| `--csv`         | Exporta también un inventario CSV a la ruta indicada          | desactivado     |
| `--history-db`  | Archivo SQLite donde guardar el historial de escaneos          | `historial.db`  |
| `--sin-historial` | No guarda el escaneo en el historial ni compara con el anterior | desactivado   |

## Interfaz web

Requiere el extra `[web]` (ver Instalación). Formulario con detección
automática de tu red local, escaneo cancelable de verdad (mata el proceso
nmap, no solo la interfaz), tabla de resultados, descarga de CSV y el grafo
embebido.

```bash
topology-scanner-web
# o, sin el entry point instalado:
streamlit run src/topology_scanner/webapp.py
```

## Clasificación de dispositivos

La MAC de cada host permite identificar el fabricante (vía la base de datos
interna de nmap), que se traduce heurísticamente a una categoría con icono
propio: router, firewall, VM, NAS, impresora, cámara, IoT, móvil, Apple, PC.

**Limitación**: la resolución de MAC solo funciona si el equipo que escanea
está en el **mismo segmento L2** que el host objetivo (ARP no cruza routers/VLANs).
Hosts en otras subredes aparecerán como categoría "desconocido".

## Tests

```bash
pytest tests/ -v
pytest tests/ --cov=topology_scanner   # con cobertura
```

Los tests de `scanner.py` usan `unittest.mock` para simular las respuestas
de nmap, así que se ejecutan sin red real ni el binario nmap instalado.

## Próximos pasos

- [x] Alertas visuales por puertos sensibles (RDP, Telnet, SMB, FTP, VNC expuesto)
- [x] Historial de escaneos en SQLite (hosts nuevos/caídos, puertos que cambian)
- [x] Exportar también a CSV para auditorías/inventario
- [x] Leyenda visual de iconos/colores en el HTML
- [x] Interfaz web con Streamlit
- [ ] Topología real vía SNMP contra switches/routers (en vez de estrella aproximada)
- [ ] GitHub Actions: ejecutar tests + ruff en cada push
