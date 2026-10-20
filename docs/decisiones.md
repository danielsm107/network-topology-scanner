# Decisiones de diseño

Registro de decisiones ya tomadas en el proyecto, con su porqué y, cuando lo
hay, el bug o problema real que las motivó. No las cuestiones sin preguntar.
`CLAUDE.md` resume las que más afectan al editar código; aquí está el
contexto completo.

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
  (`nuevos_sensibles`, subconjunto de `nuevos`).
- `history.py` también expone `hay_cambios(diff)` — única fuente de verdad
  para "¿tiene contenido real este diff?", reutilizada por `export.py` y
  `webapp.py`. Antes cada uno reimplementaba su propio `a or b or c`, que no
  da un bool de verdad si el único operando no vacío es un dict
  (`puertos_cambiados`) — causó un `TypeError` real en `st.expander()`.
  Con esto, `classifier.py` sigue sin saber nada de nadie (solo se importa
  hacia él) pero `history.py` ya no es un callejón sin salida: además de
  `scanner.py -> classifier.py`, ahora también `export.py -> history.py`.
- `scanner.py` expone `DEFAULT_NMAP_ARGS`/`PUERTOS_POR_DEFECTO` como única
  fuente de verdad para los valores por defecto de nmap — antes `cli.py` y
  `webapp.py` tenían cada uno su propia copia literal de esas dos cadenas,
  con riesgo de desincronizarse si se cambiaba una y no la otra.
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
- `_construir_comando_nmap` resuelve el binario con
  `nmap.PortScanner()._nmap_path`, no `shutil.which("nmap")`: esta última
  solo mira el `PATH` y podía no encontrarlo aunque la fase 1
  (`descubrir_hosts_vivos`, que sí usa python-nmap) hubiera funcionado.
- `_ejecutar_proceso_nmap` (el hilo del escaneo) guarda cualquier excepción
  en `contenedor["error"]` en vez de dejar que el hilo muera en silencio -
  si no, `_procesar_salida_nmap(None)` revienta más tarde con una excepción
  que no es `nmap.PortScannerError`, sin capturar en ningún sitio.
- Los `.html`/`.csv` temporales de `webapp.py` (`_finalizar_resultados`,
  `_generar_csv_bytes`) se borran con `os.remove()` en un `finally` justo
  después de leerlos - antes se quedaban para siempre en el directorio
  temporal del sistema (se encontraron 40+ archivos huérfanos de sesiones
  de prueba anteriores).
- Si se mata el proceso de Streamlit (Ctrl+C) a media pasada de un escaneo,
  `_matar_si_sigue_vivo` (registrado con `atexit`) intenta matar el
  `nmap.exe` huérfano. No cubre un `taskkill /F`/kill duro del propio
  proceso de Streamlit - eso ningún código de aplicación puede evitarlo.
- `scanner.avisar_si_nmap_reporto_error(scanner)` revisa
  `scanner.scaninfo()["error"]` tras cada `.scan()`: nmap puede "tener
  éxito" (sin lanzar `PortScannerError`) y aun así no haber escaneado nada
  (host no resuelto, etc.), silencioso si nadie lo mira. No es fatal, solo
  se avisa por log. Se llama desde `escanear_red`/`descubrir_hosts_vivos` y
  también desde `webapp._procesar_salida_nmap` (que no pasa por esas dos
  funciones para la fase cancelable).
- `history.registrar_y_comparar` purga automáticamente los escaneos de un
  rango más antiguos que los últimos `mantener_ultimos` (por defecto 50,
  parámetro opcional) — sin esto `historial.db` crecía sin límite.
- El número de versión se lee con `importlib.metadata.version(...)` en
  `__init__.py`, no de una copia a mano: `pyproject.toml` es la única
  fuente de verdad.
- No hay `requirements.txt`/`requirements-dev.txt` (se quitaron por
  obsoletos, no reflejaban `streamlit`): `pyproject.toml` +
  `pip install -e ".[dev,web]"` es el único camino de instalación.
- La interfaz web tuvo un rediseño visual completo ("Command Center": tema
  oscuro con acento leído de `.streamlit/config.toml`, fuentes Space
  Grotesk/JetBrains Mono/IBM Plex Sans, formulario movido al sidebar,
  KPIs/inventario/cambios en HTML propio en vez de `st.metric`/
  `st.dataframe`/`st.expander`). La barra nativa de Streamlit (`Deploy`/
  menú) se oculta con CSS (`[data-testid="stHeader"] { display: none; }`)
  porque el topbar propio la sustituye. Los antiguos `st.checkbox` de
  Opciones son ahora `st.toggle` (más parecido al interruptor del diseño,
  sin reestilar un checkbox nativo a mano). Para dar estilo a un widget
  concreto sin afectar a otros del mismo tipo (p. ej. el botón "Detectar mi
  red" frente a "Parar escaneo", ambos secundarios) se usa `key="..."` +
  la clase CSS que Streamlit genera sola (`.st-key-<key>`) — no hay otra
  forma fiable de distinguirlos por CSS.
- `webapp.py` construye HTML a mano uniendo fragmentos multilínea generados
  en un bucle (`"".join(...)` de divs por fila/tarjeta: inventario, cambios,
  historial, progreso). `st.markdown(unsafe_allow_html=True)` procesa ese
  contenido como Markdown antes de dejar pasar las etiquetas, y una línea en
  blanco entre fragmentos (p. ej. un fragmento condicional que queda vacío)
  corta el bloque de HTML "en crudo" a medias — el resto se veía como texto/
  código en vez de renderizarse. `_compactar_html()` colapsa todo el
  whitespace del HTML generado a un solo espacio antes de pasarlo a
  `st.markdown`, quitando el problema de raíz en vez de perseguirlo caso a
  caso.
- El grafo embebido en la web ya **no** usa pyvis: es un SVG construido a
  mano (`webapp.py::_generar_topologia_html`) con las posiciones de
  `export.posiciones_circulares` (reutilizada, no dos algoritmos de layout
  distintos), pero dentro de un documento HTML autocontenido en
  `st.components.v1.html` (iframe) con JS propio de pan/zoom (rueda = zoom,
  arrastrar = mover, doble clic = ajustar). Va en iframe, no inline como el
  resto del panel, por dos motivos: `st.markdown` ignora cualquier
  `<script>` (sin JS no hay zoom, imprescindible en redes con muchos hosts
  vivos, donde un layout estático siempre amontona algo) y para evitar el
  mismo problema de líneas en blanco de arriba. El iframe importa sus
  propias fuentes/Font Awesome (`CDN_FONTAWESOME`, reexportado desde
  `export.py`) porque no hereda el `<head>` de la página. La exportación de
  pyvis (`export.py::exportar_html`) sigue intacta para el CLI.
- `export.py::posiciones_circulares` (antes privada, ahora pública para que
  `webapp.py` la reutilice — mismo patrón que `scanner.parsear_host`)
  reparte los hosts en anillos concéntricos alrededor del hub en vez de
  dejar que la física de pyvis (`barnes_hut`) decida las posiciones: el
  HTML del CLI también sale ordenado en círculo, no con una disposición
  cambiante. `exportar_html` fija `x`/`y` y `physics=False` por nodo — no
  quita el arrastre manual ni el zoom nativos de vis-network, solo impide
  que el nodo se mueva solo.
- El escaneo cancelable de `webapp.py` ya no espera bloqueado con
  `.communicate()` a que nmap entero termine: la XML de resultado se
  escribe a un archivo temporal (`-oX archivo`, no `-oX -`) y stdout se deja
  libre para leer en vivo la salida verbose de nmap (`-v`) línea a línea.
  `_ejecutar_proceso_nmap` detecta la línea real que nmap suelta al terminar
  cada host ("Nmap scan report for X") y la añade a `contenedor["log"]`,
  que el panel de progreso pinta según van llegando — sin inventar
  fabricante/categoría/alertas por host, que solo se conocen con la XML
  completa al terminar. `stderr` se combina con stdout (`STDOUT`, no un
  `PIPE` aparte) para no arriesgarse a un deadlock si nadie lo vacía.
- La tabla de Inventario pagina de `FILAS_POR_PAGINA` (10) en 10 hosts en
  vez de listarlos todos de golpe. `pagina_inventario` en `session_state`
  se resetea a 1 en cada escaneo nuevo, para no quedarse apuntando a una
  página que ya no existe si el escaneo nuevo tiene menos hosts.
- `exportar_html` crea el `Network` de pyvis con `cdn_resources="remote"`.
  Con el `"local"` por defecto, el HTML enlaza `lib/bindings/utils.js` por
  ruta relativa, pero pyvis solo copia esa carpeta en `write_html()` y aquí
  se usa `generate_html()` — el HTML dependía de una carpeta `lib/` que
  estaba commiteada a mano en la raíz del repo. En `"remote"` ese JS va en
  línea (vis-network ya se cargaba de todas formas desde cdnjs), así que
  `lib/` se quitó del repo y está en `.gitignore`.
- El mínimo es **Python 3.10** (antes 3.9): pysnmp 7, necesario para la
  topología por SNMP, exige `>=3.10`, y 3.9 está fuera de soporte desde
  octubre de 2025. Se prefirió subir el mínimo del proyecto entero a tener
  un extra `[snmp]` que solo se instala en algunas versiones. Con
  `target-version = "py310"`, ruff pasa los `Optional[X]` a `X | None` y
  pide `strict=` en `zip()`: se usa `strict=True` porque los `zip` de hosts
  con `posiciones_circulares(len(hosts))` tienen siempre la misma longitud,
  y si dejaran de tenerla es mejor un error que un host que desaparece del
  grafo en silencio.
- `snmp.py` (topología por SNMP, roadmap 6) separa **consulta** (red,
  pysnmp) de **parseo** (funciones puras). Los parsers reciben filas
  `(oid_completo, valor)` con el valor ya en tipo nativo (`bytes`/`int`),
  no tipos de pysnmp: se testean sin red y sin la librería. Cada parser
  decide el tipo de cada columna por el OID — el script de reconocimiento
  inicial adivinaba por longitud y mostraba `ether1` (6 bytes) como si fuera
  una MAC. Los tests usan la estructura real de un MikroTik hAP ac2 (RouterOS
  v6) anonimizada (IPs de documentación, MACs `02:00:00:…`). Rutas desde
  `ipCidrRouteTable` (destino y máscara van en el índice) en vez de la
  antigua `ipRouteTable`. De vecinos, de momento solo la tabla propia de
  MikroTik (`mtxrNeighborTable`, trae IP e identidad); la `LLDP-MIB`
  estándar queda para cuando haya equipos de otros fabricantes.
