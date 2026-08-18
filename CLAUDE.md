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
- `streamlit` (extra opcional `[web]`) para la interfaz web, `webapp.py`
- Tests con `pytest` + `unittest.mock` (mockean `nmap.PortScanner`, no requieren red real ni nmap instalado).
  Los de `webapp.py` usan además `streamlit.testing.v1.AppTest` (ejecuta el
  script sin navegador) y se saltan solos si `streamlit` no está instalado.
- Entorno de trabajo: Windows + VS Code + Git Bash

## Estructura

```
src/topology_scanner/
├── scanner.py      # Todo lo de nmap: descubrimiento (fase 1, ping scan) + escaneo completo (fase 2)
├── classifier.py   # clasificar_dispositivo(vendor) -> categoría, iconos por categoría
├── graph.py        # construir_grafo(resultados, rango) -> networkx.Graph (topología en estrella)
├── export.py       # exportar_html (pyvis + iconos Font Awesome vía CDN), exportar_texto, exportar_diff_texto, exportar_csv
├── history.py      # registrar_y_comparar(resultados, rango, db_path) -> guarda en SQLite y compara con el escaneo anterior
├── cli.py          # argparse, orquesta scanner -> graph -> export (+ history)
└── webapp.py       # interfaz Streamlit (opcional): mismo pipeline, con escaneo cancelable
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
  Ojo: pyvis también mete un `<center><h1></h1></center>` vacío en el body
  que hay que ocultar (`display: none`), si no deja una franja en blanco.
- Los puertos "sensibles" (`PUERTOS_SENSIBLES` en `classifier.py`: FTP 21,
  Telnet 23, SMB 445, RDP 3389, VNC 5900) son una primera señal visual, no
  una lista exhaustiva de auditoría. El host se marca en rojo (icono +
  prefijo ⚠ en la etiqueta) y el motivo se detalla en el tooltip.
- `history.py` guarda cada escaneo completo en SQLite (no solo el diff) y
  compara contra el escaneo más reciente **del mismo rango** — rangos
  distintos no se mezclan. Un fallo de SQLite (`HistoryError`) no aborta el
  programa: se avisa por log y se sigue con el grafo/export normal, porque
  el escaneo en sí ya ha funcionado.
- `history.py` importa `PUERTOS_SENSIBLES` de `classifier.py` para marcar,
  dentro de `puertos_cambiados`, qué puertos nuevos son además sensibles
  (`nuevos_sensibles`, subconjunto de `nuevos`). Es la única dependencia
  entre módulos fuera de scanner.py -> classifier.py, y está bien: classifier
  sigue sin saber nada de nadie, solo se importa hacia él.
- El `.gitignore` cubre `*.html`/`*.db`/`*.csv` en bloque (no solo los
  nombres de archivo por defecto) porque cualquier `--output`/`--history-db`
  personalizado puede contener datos reales de red (IPs, MACs, puertos
  abiertos) y no debe poder colarse en un commit.
- `webapp.py` usa imports **absolutos** (`from topology_scanner.scanner
  import ...`), no relativos: `streamlit run webapp.py` ejecuta el archivo
  como script suelto sin contexto de paquete, y un import relativo revienta
  con `ImportError: attempted relative import with no known parent package`.
- El escaneo cancelable de `webapp.py` **no** usa `scanner.escanear_red()`
  ni `nmap.PortScannerAsync` — lanza `nmap` a mano como `subprocess.Popen`
  dentro de un `threading.Thread`, guardando la referencia al proceso para
  poder matarlo con `.terminate()` si se pulsa "Parar escaneo".
  `PortScannerAsync` (la clase async de python-nmap) usa
  `multiprocessing.Process`, no hilos, lo que en Windows complica mucho
  recuperar el resultado en el proceso de Streamlit. Parar un escaneo no
  conserva resultados parciales (el XML de nmap no queda bien formado si se
  mata a mitad). `scanner.parsear_host` se hizo pública (antes
  `_parsear_host`) para que `webapp.py` pueda reutilizarla.
- La UI de progreso usa `st.fragment(run_every="1s")`, no un bucle
  `time.sleep()+st.rerun()`: ese patrón redibujaba la página **entera** cada
  segundo (parpadeo) y el clic en "Parar escaneo" competía por turno de
  ejecución contra el propio temporizador, así que a veces no se registraba.
  Con el fragmento, solo se refresca el trocito de progreso; el botón de
  Parar vive fuera del fragmento y se procesa como un clic normal.
- Un mensaje puesto justo antes de un `st.rerun()` no llega a verse (el
  rerun tira el render a medias). Los mensajes que tienen que sobrevivir a
  un rerun se guardan en `st.session_state["mensaje"]` y se muestran al
  principio de la siguiente pasada de `main()` (con `.pop()`, una sola vez).

## Roadmap (por orden de prioridad hablado)

1. ~~**Alertas por puertos sensibles**~~ — hecho.
2. ~~**Historial en SQLite**~~ — hecho (`history.py` + flags `--history-db`/`--sin-historial`).
3. ~~**Cruzar el historial con las alertas**~~ — hecho (`nuevos_sensibles`
   en `puertos_cambiados`, destacado en `exportar_diff_texto`).
4. ~~**Exportar a CSV**~~ — hecho (`exportar_csv`, flag `--csv`). Columnas:
   ip, hostname, mac, vendor, categoria, so, puertos, alertas (se añadieron
   categoria y alertas sobre lo hablado originalmente porque ya estaban
   calculadas y son justo lo relevante para una auditoría de seguridad).
5. ~~**Leyenda visual en el HTML**~~ — hecho (`_generar_leyenda_html`,
   reutiliza `ICONOS_POR_CATEGORIA` como única fuente). De paso se encontró
   y arregló un bug preexistente: el icono de "apple" (`\uf179`) pertenece a
   la fuente "Font Awesome 5 Brands", no a "Font Awesome 5 Free" que se
   usaba a pelo en todos los iconos — salía en blanco tanto en los nodos
   del grafo como en la leyenda. Ahora cada categoría lleva su propio
   `face`/`weight` en `ICONOS_POR_CATEGORIA`.
6. **Topología real vía SNMP** — consultar tablas ARP/CDP/LLDP de los
   MikroTik/Fortinet del mantenedor para topología real en vez de estrella
   aproximada. La feature más compleja, dejar para el final.
7. ~~**Interfaz web con Streamlit**~~ — hecho (`webapp.py`, extra opcional
   `[web]`, entry point `topology-scanner-web`). Formulario con detección
   automática del rango local (botón "📍 Detectar mi red", truco de socket
   UDP sin admin/sudo), escaneo cancelable de verdad (mata el proceso nmap,
   no solo la UI), tabla de resultados, descarga de CSV y el grafo embebido.
8. **CI con GitHub Actions** — ejecutar pytest + ruff en cada push, badge en
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
