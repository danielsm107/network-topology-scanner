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
  con `--os-detection` (antes `--con-so`).
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
- La capa de consulta de `snmp.py` importa pysnmp **dentro** de las
  funciones, no arriba del módulo: así los parsers (y quien importe
  `snmp.py`) funcionan sin el extra `[snmp]`, y si falta se lanza un
  `SnmpError` con el comando de instalación en vez de un `ImportError` al
  arrancar. pysnmp 7 solo tiene API asyncio; `_recorrer` la envuelve con
  `asyncio.run` para que el resto del programa siga siendo síncrono.
  `sysName` se consulta primero: si falla, el equipo "no responde" y se
  lanza `SnmpError`; si falla una tabla posterior, se avisa por log y se
  sigue con esa tabla vacía (mismo criterio que `HistoryError`: perder un
  trozo no tira lo que sí ha funcionado). Una tabla que el equipo no
  implementa sale vacía sin error. Los marcadores `NoSuchObject`/
  `EndOfMibView` de pysnmp también tienen `asOctets()` (devuelven `b""`),
  así que `_convertir_valor` los descarta antes de convertir. La community
  nunca aparece en mensajes de error ni en el log.
- `snmp.inferir_topologia(equipos)` es pura y devuelve un dict neutral
  (`equipos`/`enlaces`/`redes`/`ubicaciones`) indexado por IP, igual que
  los nodos del grafo, para que `graph.py` lo cruce con nmap sin saber nada
  de SNMP. Reglas: equipos de red = consultados + vecinos **con identidad**
  (un PC que manda LLDP no cuenta) + siguientes saltos de rutas (el UDM no
  anuncia LLDP: solo se le conoce por la ruta a su LAN). Una ruta cuyo
  salto está dentro de la propia red es una red conectada, no otro router.
  La puerta de enlace es el padre; si no se ha consultado, `upstream`. Un
  host visto por un puerto donde hay otro equipo de red cuelga de ese
  equipo sin puerto (no se sabe cuál de los suyos); si varios routers lo
  ven, gana la ubicación con interfaz. La ARP no sirve para decir en qué
  puerto está nada dentro de un bridge (diría "Bridge LAN" para todos):
  solo se usa para etiquetar enlaces cuando no hay vecino ni tabla MAC.
- `graph.construir_grafo(resultados, rango, topologia=None)`: sin
  topología, la estrella de siempre (mismo código, solo se extrajo
  `_atributos_host`). Con topología, árbol real: los equipos de red son
  nodos `tipo="equipo"` (con los datos de nmap si también los escaneó;
  categoría `router` si nmap no la sabe) y cada host de nmap se cuelga
  por IP, si no por MAC (en minúsculas: nmap las da en mayúsculas), si no
  del router de su red remota (la más específica). Solo si algo no encaja
  en nada aparece el nodo "Red <rango>", y sin enlazar al árbol. Los hosts
  que solo ha visto SNMP (en la ARP/tabla MAC pero no detectados por nmap,
  o sin IP) **se muestran**, con `solo_snmp=True` e id = IP o MAC: un
  equipo desconocido en un puerto es justo lo interesante para seguridad.
  Todo nodo lleva `padre` (None en las raíces) para el layout por niveles,
  y las aristas `interfaz` (la del padre, o la del hijo si es la única que
  se conoce).
- `export.posiciones_jerarquicas(grafo)`: cuando el grafo trae equipos de
  red (topología SNMP), `exportar_html` dibuja un árbol por niveles en vez
  del círculo. Cada nodo ocupa un hueco tan ancho como su subárbol y se
  centra sobre sus hijos; las hojas de un mismo padre van en un bloque de
  `COLUMNAS_HOJAS` (4) columnas ordenadas por interfaz, para que 20 hosts
  colgando de un router no den un árbol de 20 de ancho. Varias raíces (p.
  ej. el nodo "Red" de hosts sin ubicar) van una al lado de otra. Ajustes
  visuales salidos de probarlo con datos reales: aristas `cubicBezier`
  verticales (las rectas hacia la 2ª/3ª fila del bloque atravesaban la 1ª),
  una sola etiqueta de interfaz por padre+puerto (8 "wlan1" iguales
  ensuciaban), la IP una sola vez si no hay hostname, y la leyenda arriba a
  la izquierda (abajo tapaba hosts). Además se fuerza `network.fit()` tras
  el primer dibujado: el encuadre inicial venía de rebote al terminar la
  simulación física de las aristas `dynamic` por defecto, y en el árbol no
  hay nada que simular — la vista se quedaba centrada en la raíz.
- `parsear_fdb` descarta las entradas con `dot1dTpFdbStatus` invalid(2) o
  self(4). Se vio al dibujar el árbol con datos reales: 4 "hosts sin IP"
  con MACs consecutivas de MikroTik eran las MACs de los puertos del propio
  hAP (estado self), que BRIDGE-MIB lista junto a los hosts aprendidos. Si
  el equipo no implementa la tabla de estado, no se filtra por eso (mejor
  algún falso positivo que quedarse sin tabla MAC).
- `cli.py --snmp IP[,IP...]`: la community se lee de la variable de entorno
  `TOPOLOGY_SNMP_COMMUNITY`, nunca de un argumento (se vería en `ps` y en
  el historial de la shell; en Linux, `sudo -E` para que llegue). Si falta,
  `parser.error` **antes** de escanear: no tiene sentido descubrirlo tras
  minutos de nmap. Las IPs de `--snmp` se validan en argparse. Un equipo
  que no responde se salta con un aviso; si no responde ninguno, se dibuja
  la estrella (mismo criterio que `HistoryError`). La consulta SNMP va
  después del escaneo de nmap y antes de construir el grafo.
- `scanner._reparar_codificacion` arregla el vendor que nmap rompe: en la
  XML escribe cada byte UTF-8 de un carácter no ASCII como una referencia
  aparte (`&#xef;&#xbc;&#x8c;` en vez de `&#xff0c;`), y el parser lo lee
  como caracteres Latin-1 sueltos ("Shenzhen Bilian Electronicï¼LTD" en
  una red real; el archivo `nmap-mac-prefixes` sí está bien en UTF-8). Se
  recompone con `encode("latin-1").decode("utf-8")` solo si eso forma
  UTF-8 válido: ASCII no cambia y un "Société" bien decodificado no pasa
  la prueba, así que se queda igual.
- SNMP en `webapp.py`: interruptor en el sidebar + IPs + community en un
  `text_input(type="password")`; si se deja vacía, `TOPOLOGY_SNMP_COMMUNITY`
  (`VARIABLE_COMMUNITY` vive en `snmp.py`, compartida con el CLI). Se valida
  **antes** que el rango y antes de lanzar nmap (`_validar_snmp`, pura). La
  orquestación es la misma función que usa el CLI (`snmp.obtener_topologia`,
  que devuelve los avisos en vez de loguearlos para que la web los pinte con
  `st.warning`). La community viaja en `parametros_pendientes` solo hasta
  `_finalizar_resultados` y se borra en el `finally` del fragmento de
  progreso: no queda en `st.session_state["resultado"]`. El árbol del panel
  reutiliza `construir_grafo` + `posiciones_jerarquicas` (mismo layout que
  el HTML del CLI). Se partió `_generar_topologia_html` en piezas
  compartidas por círculo y árbol (`_nodo_topologia_html`,
  `_hub_topologia_html`, `_documento_topologia_html`), y el nodo escapa
  todo el texto con `html.escape`: la identidad SNMP la define cada equipo
  y el hostname sale del DNS inverso.
- Todo texto externo que `webapp.py` mete en HTML pasa por `html.escape`:
  hostname (DNS inverso: cualquiera con un PTR en la red lo controla), SO,
  rango (lo escribe el usuario y se guarda en el historial) y las líneas
  del log en vivo (copian lo que nmap imprime tras "Nmap scan report
  for", que puede ser un hostname). Antes ningún panel escapaba nada; se
  vio al añadir SNMP (la identidad de los equipos la define cada equipo).
  Hay un test por panel con un valor malicioso. Los mensajes de
  `st.warning`/`st.error` no lo necesitan: Streamlit no interpreta HTML ahí.
- Varios rangos por ejecución (`topology-scanner A B`): módulo nuevo
  `rangos.py`, puro, porque "a qué rango pertenece cada IP" lo necesitan
  CLI, historial y grafo y no es cosa de nmap. nmap recibe todos los
  objetivos de una vez (python-nmap ya acepta varios separados por
  espacios). Se pasan como **argumentos separados**, no partiendo por
  comas: `192.168.1.1,5` es sintaxis de nmap. Con un solo objetivo se
  admite cualquier sintaxis de nmap, como antes; con varios, cada uno tiene
  que ser IP o CIDR para poder repartir los hosts (`parsear_rangos`, error
  antes de escanear). El historial se guarda **por rango**
  (`repartir_por_rango`, incluidos los rangos sin hosts, para que salgan
  sus caídos): así se respeta "rangos distintos no se mezclan" y un rango
  que antes se escaneaba solo sigue comparándose con su historia. En la
  estrella hay un centro por rango, y con más de uno `exportar_html` usa el
  layout por niveles (en el círculo todos los centros irían al origen).
- Varios rangos en la web: el campo de rango acepta varios separados por
  espacios (`_validar_rangos`, pura, antes de lanzar nmap), con el mismo
  `rangos.parsear_rangos` que el CLI. `_finalizar_resultados` guarda el
  historial por rango y junta los diffs con `history.combinar_diffs` (es
  "primera vez" solo si lo es para todos los rangos) para el KPI y el
  panel de cambios. Con más de un rango el panel de topología usa el árbol
  por niveles (un centro por rango, con el rango completo: dos "/24" no se
  distinguirían). El nodo central lleva el atributo `rango` para no tener
  que recortar el nombre "Red ...".
- Fixture `sin_escaneos_reales` en `test_webapp.py`: un test de AppTest
  que pulsaba "Escanear" confiaba en que la validación cortara antes de
  nmap, pero en la fase roja de TDD (validación aún sin escribir) lanzó un
  ping scan real de unos segundos, incluido un rango que no era de la red
  del mantenedor. Ahora `nmap.PortScanner` está parcheado con un mock que
  falla el test si se llama: un fallo de validación da un test en rojo, no
  un escaneo. AppTest no reutiliza el módulo webapp pero sí `nmap`
  (cacheado en `sys.modules`), así que el parche le llega.
- `inferir_topologia` ignora las rutas con siguiente salto `0.0.0.0`
  (rutas por interfaz: túneles VPN, PPPoE...). Sin el filtro aparecía un
  "equipo" con IP 0.0.0.0, como hijo o como puerta de enlace upstream si la
  ruta por defecto iba por interfaz. El hAP del mantenedor no tiene rutas
  así; se detectó al pensar en routers con VPN (p. ej. FortiGate).
- Vecinos por LLDP-MIB estándar (`parsear_vecinos_lldp`), además de la
  tabla propia de MikroTik, combinados por MAC (`combinar_vecinos`: la
  primera fuente manda, las demás rellenan huecos). LLDP aporta el puerto
  **del otro extremo** (`interfaz_remota`), así que los enlaces entre
  equipos muestran ambos lados (`ether2 ↔ bridge/ether1`). RouterOS v6 no
  sigue el estándar en tres cosas, vistas con el hAP real y cubiertas por
  tests: el puerto local del índice es siempre 0 (no se sabe por LLDP por
  qué puerto se ve a cada vecino; lo da la tabla de MikroTik), la IP de
  gestión va como texto en una columna y no dentro del índice, y la MAC del
  chassis llega como texto "C4:AD:34:..." en vez de 6 bytes. Esto último
  no lo detectaron los tests (construidos según la especificación) sino la
  prueba en vivo: los vecinos salían duplicados porque no se emparejaban
  por MAC. La variante estándar (puerto local por `lldpLocPortTable`
  emparejado por nombre con `ifName`, IP en el índice) está escrita a
  partir de la especificación, sin un equipo real que la confirme.
- SNMPv3: `snmp.CredencialesV3` (dataclass congelada) con usuario, claves
  y protocolos; por defecto SHA + AES-128, lo que soporta RouterOS v6. Las
  claves llevan `repr=False` para que un traceback o un log no las
  muestre, y se validan al crearlas (8+ caracteres, como pide RFC 3414;
  protocolos conocidos). Sin clave de cifrado es authNoPriv; noAuthNoPriv
  no se admite porque no aporta nada frente a v2c. Las credenciales son
  `str` (community v2c) o `CredencialesV3` en todo el pipeline, y
  `credenciales_desde_entorno` (compartida con la web) elige v3 si existe
  `TOPOLOGY_SNMP_USER`. Los fallos de credenciales de v3 (usuario
  desconocido, clave/protocolo de autenticación o de cifrado incorrectos,
  nivel de seguridad no soportado) se reconocen por **tipo** de
  `pysnmp.proto.errind`, no por texto, y abortan la consulta del equipo
  con una pista de qué revisar: el equipo sí responde, así que el mensaje
  genérico de "no responde" despistaría.
- El extra `[snmp]` instala también `cryptography>=43`: pysnmp la usa para
  cifrar en SNMPv3 (AES/DES, importa `cryptography.hazmat.decrepit`, de la
  43 en adelante) pero solo la declara en su extra de desarrollo. Sin ella,
  la primera prueba real contra el hAP falló con "Ciphering services not
  available", y el mensaje decía que el router no respondía. Ahora se
  comprueba antes de tocar la red si se pide cifrado, y `EncryptionError`
  (mismo texto que `DecryptionError`, pero local) se trata como fallo de
  este equipo, no del consultado.
- SNMPv3 en la web: selector v2c/v3 en el sidebar; en v3, usuario, claves
  (`type="password"`) y protocolos. La configuración guarda
  `credenciales` (community o `CredencialesV3`) en vez de `community`, y se
  borra igual al terminar el escaneo. Con los campos vacíos se usan las
  variables de entorno, pero **solo las de la versión elegida**: elegir v3
  y tener solo la community en el entorno es un error, no una consulta v2c
  silenciosa (y al revés, con v2c no cuenta un usuario v3 del entorno).
- `webapp._finalizar_resultados` ya no genera el HTML de pyvis del CLI:
  desde que la web dibuja su propio SVG, cada escaneo construía el grafo,
  lo exportaba a un `.html` temporal, lo leía, lo borraba y lo devolvía en
  `resultado["html"]` sin que nadie lo usara. La entrada de más arriba
  sobre los temporales `.html` de la web queda solo como historia.
- Captura del árbol SNMP del README (`docs/screenshots/arbol-snmp.png`):
  sale de `scripts/demo_arbol.py`, que monta a mano resultados y topología
  inventados y los pasa por `construir_grafo` + `exportar_html` de verdad.
  Un script, no una captura hecha a mano de una red real: se puede
  regenerar si cambia el diseño y `tests/test_demo_arbol.py` garantiza que
  todo dato es de documentación (RFC 5737, MACs `02:00:00:…`). Vive en
  `scripts/`, fuera del paquete, porque no es parte de la herramienta;
  por eso CI pasa también `ruff` sobre `scripts/`. La captura se hace con
  Chrome headless (`--screenshot --virtual-time-budget=8000`, 1600x900).
  El AP de la demo tiene 4 hojas a propósito: con 5, la quinta baja a otra
  fila (`COLUMNAS_HOJAS`) y su arista cruza las demás.
- Publicación en PyPI (`release.yml`), disparada por un tag `v*`, no a
  mano: es la pieza más "DevOps" del repo y evita subir desde un portátil
  con lo que haya en el directorio. Decisiones:
  - Trusted publishing (OIDC) en vez de un token de API en los secrets:
    no hay credencial que rotar ni que se pueda filtrar.
  - `ci.yml` es reutilizable (`workflow_call`) y la release la llama: una
    sola definición de qué es "estar en verde".
  - Todo lo que puede fallar va **antes** de publicar (tag == versión de
    `pyproject.toml`, sección del CHANGELOG, `twine check --strict`): una
    versión publicada en PyPI no se puede volver a subir, ni borrándola.
  - `workflow_dispatch` publica solo en TestPyPI (`skip-existing`), para
    estrenar el pipeline sin gastar una versión real.
  - Las imágenes del README van con URL absoluta (raw.githubusercontent):
    PyPI muestra el README y no resuelve rutas relativas del repo.
- Interfaz en inglés (v1.1), para poder enseñar el proyecto fuera (Reddit,
  público anglohablante). Solo lo que ve el usuario: el código (funciones,
  variables, docstrings, tests) sigue en español, porque traducirlo es una
  refactorización enorme que nadie que use la herramienta nota. Nada de
  i18n con selector de idioma: sobreingeniería para un proyecto sin
  usuarios todavía. Se hace por partes, un commit por superficie (CLI,
  web, salidas, capturas). En el CLI:
  - Flags nuevos en inglés (`--fast`, `--os-detection`, `--no-discovery`,
    `--no-history`). Los de la v1.0 en español siguen funcionando como
    alias ocultos (`help=argparse.SUPPRESS`, mismo `dest`): la v1.0 ya está
    en PyPI y romper un cron al actualizar no compensa.
  - El HTML por defecto pasa a `network_topology.html`, pero el historial
    sigue en `historial.db`: renombrarlo dejaría de comparar con los
    escaneos anteriores sin avisar.
  - Los mensajes se traducen en el módulo que los genera (scanner, snmp,
    rangos, history, export), no en quien los muestra: así salen en inglés
    en el CLI y en la web sin duplicar nada.
  - Valores de datos: la categoría y el SO sin identificar pasan de
    `desconocido` a `unknown` (las demás claves de categoría ya estaban en
    inglés), y el nodo central de cada rango de `Red <rango>` a
    `Network <rango>`. Es seguro porque el historial guarda la categoría
    pero nunca la vuelve a leer para comparar. Las columnas del CSV
    también cambian, y queda avisado en el CHANGELOG.
- Capturas de la web del README (`dashboard.png`, `inventario.png`): salen
  de `scripts/demo_web.py`, que reutiliza los datos de `demo_arbol.py`, les
  añade un diff inventado y los deja en `session_state` antes de llamar a
  `webapp.main()`. Antes se hicieron a mano y no se podían regenerar.
  **La demo sustituye `listar_escaneos_recientes`**: el `historial.db` del
  directorio de trabajo es el de la red real de quien la lance, y en la
  primera captura en inglés salieron rangos reales en "Recent history"
  (se vio antes de publicar). Lo cubre `tests/test_demo_web.py`. El
  `--screenshot` de Chrome dispara antes de que Streamlit pinte (el
  websocket no avanza con `--virtual-time-budget`), así que se captura por
  DevTools Protocol esperando a que la página muestre "Changes", con una
  ventana de 1600x2900, y se recorta: dashboard `(0, 0, 1600, 1030)`,
  inventario `(300, 1035, 1600, 2400)`.
- GIF de la topología del README (`docs/screenshots/topologia.gif`): también
  sale de `scripts/demo_web.py` por DevTools Protocol (ventana de 1600x1100):
  vista plana, clic en "Isometric", 3 pasos de rueda y un arrastre, con una
  captura del iframe de la topología cada ~100 ms. Los fotogramas se juntan
  con ffmpeg a 9,5 fps, 960 px de ancho y paleta de 128 colores (~1 MB).
  Al grabarlo salió un bug real: el `mousedown` del pan no hacía
  `preventDefault()` y arrastrar seleccionaba el texto de los nodos.
- Vista isométrica de la topología en la web (estilo FossFLOW), con un
  botón Flat / Isometric junto a "Topology" (`st.radio`, `key="vista_topologia"`):
  cambiar de vista es un rerun normal con el resultado ya en `session_state`,
  no vuelve a escanear. **No es un tercer layout**: siempre usa
  `graph.construir_grafo` + `export.posiciones_jerarquicas` y proyecta esas
  posiciones como si fueran el suelo (`_proyectar_isometrico`). Por eso, sin
  SNMP y con un solo rango, la isométrica sale por niveles (rango -> hosts)
  y no en círculo: un círculo en perspectiva es una elipse sin cuadrícula.
  - El suelo se comprime (`ESCALA_SUELO_ISO = 0.7`) antes de proyectar:
    girado 45°, el ancho y la profundidad del árbol se suman en las dos
    direcciones y el lienzo salía ~1,6 veces más grande que el plano, con
    los iconos diminutos tras el ajuste inicial.
  - Rejilla, cables y baldosas van en el SVG; los iconos son los mismos
    nodos HTML del panel plano (tooltip, alertas, `html.escape`), con la
    clase `iso`. Se ordenan por `x + y` del suelo (orden del pintor) para
    que lo de delante tape a lo de detrás.
  - Cables en ángulo recto siguiendo los ejes del suelo (4 puntos), como
    en FossFLOW, en vez de las curvas del árbol plano.
  - Plataformas por zona: los hijos sin hijos de cada nodo (el bloque de
    hojas que ya agrupa `posiciones_jerarquicas`, así que nunca se solapan)
    van sobre una plataforma elevada con el nombre de su padre (el rango,
    sin SNMP). Un equipo con sus propios hijos no va a la plataforma de su
    padre: es el centro de otra rama. Los cables hacia una plataforma
    cruzan todos a la misma altura (como un bus), llegan a su borde por el
    suelo y siguen por encima en otro trazo (`topo-iso-edge-top`), pintado
    después de la plataforma para que no lo tape. El nombre va bajo el
    centro del borde delantero: en una esquina quedaba pegado a la
    plataforma de al lado y parecía de esa.
- El panel de topología va en `st.iframe` (Streamlit >=1.56) en vez de
  `st.components.v1.html`, obsoleto y con aviso de eliminación tras el
  2026-06-01: como `pyproject.toml` no pone techo a Streamlit, el día que
  lo quiten la web se rompería en toda instalación nueva. Alto fijo (no el
  `"content"` por defecto), porque el lienzo de pan/zoom necesita un
  viewport concreto. `st.iframe` ejecuta el JS del HTML con acceso a la
  app, igual que antes: por eso sigue valiendo la regla de escapar todo
  texto externo. El mínimo sube de 1.33 a 1.56; el 1.33 ya era falso
  (`st.fragment(run_every=...)` es de 1.37). Validado pasando la suite con
  Streamlit 1.56.0 exacto. Lo cubre `test_la_web_de_demo_no_usa_la_api_obsoleta_de_componentes`.
- Imagen Docker (fase DevOps 1, runbook `docs/devops/runbooks/01-contenedor.md`):
  - **nmap sin root**: capacidades de archivo en el binario (`setcap
    cap_net_raw,cap_net_admin+eip`) + `NMAP_PRIVILEGED=1`
    y usuario `scanner` con UID fijo 10001. El contenedor necesita
    `--cap-add NET_RAW --cap-add NET_ADMIN` y nada de `no-new-privileges` /
    `allowPrivilegeEscalation: false`, que anulan las capacidades de archivo.
    Sin ellas el kernel no ejecuta nmap y python-nmap lo disfraza de "nmap
    program was not found in path": `scanner.error_de_nmap` lo distingue
    (nmap está en el PATH pero no arranca) y dice qué hacer. Se encontró al
    probar la imagen como la usaría alguien de fuera, igual que el traceback
    de un `/data` sin permisos (ahora `ExportError`, ver `export._escribir_archivo`).
  - **Trivy como imagen oficial fijada por digest, sin su action**, y las
    actions de Docker por SHA: en marzo de 2026 robaron credenciales de Aqua y
    reescribieron casi todas las tags de `aquasecurity/trivy-action` y
    `setup-trivy`. Versión 0.75.0 y no la última (0.76.x): llevaba tres semanas
    publicada, y una versión recién salida es justo el riesgo de ese ataque.
    La CI falla con críticas que tengan arreglo (`--ignore-unfixed`).
  - **amd64 + arm64** en la release (Raspberry Pi en homelabs), arm64 emulado
    con QEMU. La CI solo construye amd64: arm64 no se prueba antes de publicar.
  - **GHCR crea los paquetes privados**: tras la primera publicación hay que
    ponerlo en público a mano (una vez). Sin eso k3s no la descarga sin credenciales.
  - **`compose.yaml` en inglés y con la web en `127.0.0.1`**: es para que lo
    copie gente de fuera, y la web no tiene autenticación y escanea lo que le
    pidan. Abrirla a la LAN es una línea, pero tiene que ser una decisión
    consciente. En el clúster lo resuelve la lista de rangos permitidos (fase 3).
  - **Solo `cap_net_raw,cap_net_admin` en el binario.** Llevaba también
    `cap_net_bind_service`, que nmap no usa: el kernel no ejecuta un binario
    cuyas capacidades de archivo no estén todas en el contenedor, así que con
    `--cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN` (lo mismo que el
    `drop: [ALL]` habitual en Kubernetes) nmap no arrancaba. Lo encontró la
    revisión final de la fase 1; la CI lo prueba con `--cap-drop ALL`.
- VM de Proxmox como código (fase DevOps 2, runbook `docs/devops/runbooks/02-proxmox-vm.md`):
  - **Bucket del estado de Terraform ya en esta fase**, no en la fase 4 (AWS
    como código) como decía el diseño: sin él, el estado de Proxmox viviría en
    el PC y habría que migrarlo después. El bucket se crea con estado local
    (`infra/aws/bootstrap/`, no puede guardarse en sí mismo), con
    `prevent_destroy`, versionado y **SSE-S3, no KMS**: una clave KMS propia
    cuesta ~1 $/mes y no aporta nada a un estado que solo lee una persona.
    Bloqueo con `use_lockfile` (objeto en S3), sin tabla de DynamoDB.
  - **Token de API con un rol de privilegios mínimos** (`TerraformProv`, lista
    en el runbook), no el de la documentación del provider, que cubre todos sus
    recursos. El secreto va por entorno (`PROXMOX_VE_API_TOKEN`), nunca en
    variables: acabaría en el plan y en el estado.
  - **SSH como root al nodo solo para los snippets**: la API de Proxmox no deja
    subirlos y es lo que exige `bpg/proxmox`. Con la huella del host verificada
    a mano antes de aceptarla.
  - **IP fija fuera del pool DHCP**, en `terraform.tfvars` (no versionado). Se
    descartó una reserva DHCP: exige MAC fija en la VM y DHCP en cloud-init, y
    ata la VM a la configuración del router.
  - **8 GiB de RAM** (lo del diseño): implica tener apagada la VM 202. Si se
    enciende, `memoria_mib = 6144`.
  - **Red por network-config propio, no `ip_config`** (el `ipconfig0` de
    Proxmox): ese genera la red para `eth0` y renombra la tarjeta, y en Ubuntu
    26.04 el renombrado falla porque dracut ya la ha levantado por DHCP; la VM
    se quedaba con una IP del pool. El snippet busca la tarjeta por `en*` sin
    renombrarla. Se vio en el primer `apply` real (los tests con el provider
    simulado no lo pueden ver); ahora lo fija `terraform test`.
  - **`apply` solo desde el PC**, nunca en la CI: la API de Proxmox está en la
    LAN y no se abre hacia fuera. La CI hace `fmt`, `validate` y `terraform test`.
- v1.3.0, cambios en la app para desplegarla en el clúster (fase DevOps 3,
  diseño `docs/superpowers/specs/2026-10-29-fase-3-kubernetes-design.md`):
  - **Rangos permitidos solo en la web** (`TOPOLOGY_ALLOWED_RANGES`), no en el
    CLI: quien ejecuta el CLI ya tiene la máquina. Con la variable, solo IPs y
    CIDRs (la sintaxis de nmap como `.1-5` no se puede comprobar de forma
    fiable), contenidos enteros en un permitido (un /23 que contiene al /24
    permitido se rechaza), y **también las IPs de SNMP**, para que la web no
    sirva para consultar equipos de fuera. Si la variable está mal escrita, la
    web no escanea nada: falla cerrado, nunca "sin límites" por una errata.
  - **Ejecuciones en el historial**: una pasada guarda todos sus rangos y la
    topología SNMP (JSON) juntos, para que la web la reabra entera. Cada rango
    se sigue comparando con su propio escaneo anterior. Al reabrir una antigua,
    el diff es contra el escaneo anterior a ella, no contra el último. Migración
    en sitio al abrir la base: cada escaneo de antes pasa a ser una ejecución de
    un rango (origen "antiguo", sin topología), sin perder nada. Las alertas se
    recalculan al cargar (como ya hacía la lista antigua), no se guardan aparte.
  - **Espera de 30 s ante bloqueos de SQLite**: el CronJob y la web escriben en
    el mismo archivo. Con escrituras de milisegundos basta de sobra; sqlite3 ya
    esperaba 5 s por defecto, los 30 son margen.
  - **La lista de la web es un `st.selectbox`**, no el panel HTML de antes:
    tiene que poder elegirse, y en texto plano no hay HTML que escapar. Vuelve a
    "sin elegir" tras cada escaneo cambiando su `key` (no se puede asignar la
    de un widget ya creado). El origen se muestra tal cual (`cli`, `web`, `old`):
    deducir "nocturno" de la hora sería inventar.
