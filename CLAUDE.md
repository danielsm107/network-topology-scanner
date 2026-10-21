# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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

- Python 3.10+, paquete instalable (`pyproject.toml`, layout `src/`)
- `python-nmap` (wrapper de nmap), `networkx` (grafo), `pyvis` (export HTML interactivo)
- `streamlit` (extra opcional `[web]`) para la interfaz web, `webapp.py`
- `pysnmp` (extra opcional `[snmp]`) para la topología por SNMP, `snmp.py`
- Tests con `pytest` + `unittest.mock` (mockean `nmap.PortScanner`, no requieren red real ni nmap instalado).
  Los de `webapp.py` usan además `streamlit.testing.v1.AppTest` (ejecuta el
  script sin navegador) y se saltan solos si `streamlit` no está instalado.
  **Todo test de AppTest que pulse "Escanear" usa el fixture
  `sin_escaneos_reales`**: AppTest ejecuta la app de verdad, y si la
  validación que debería cortar antes de nmap falta o falla, el test lanza
  un escaneo real (pasó una vez en la fase roja de TDD).
- Lint con `ruff` (config en `pyproject.toml`: `line-length = 120`, reglas `E,F,I,UP,B,SIM,RUF`)
- Entorno de trabajo: Windows + VS Code + Git Bash

## Comandos

```bash
pip install -e ".[dev,web,snmp]"                # único camino de instalación (no hay requirements.txt)
pytest tests/ -v                                # suite completa (no necesita nmap ni red)
pytest tests/test_history.py -v                 # un módulo
pytest tests/test_history.py::test_nombre -v    # un test concreto
pytest tests/ --cov=topology_scanner            # cobertura
ruff check src/ tests/                          # lint (lo mismo que ejecuta CI)

topology-scanner 192.168.1.0/24 [--rapido] [--con-so] [--output x.html] [--csv x.csv]
topology-scanner 192.168.1.0/24 10.0.10.0/24 [--snmp 192.168.1.1]   # varios rangos a la vez
topology-scanner-web                            # o: streamlit run src/topology_scanner/webapp.py
```

El escaneo real necesita nmap instalado y, para MAC/`-O`, privilegios
(`sudo` en Linux, terminal de administrador en Windows).

CI (`.github/workflows/ci.yml`) ejecuta `ruff check src/ tests/` + `pytest`
en Python 3.10 y 3.12 en cada push/PR a `main` — ambos tienen que pasar.

## Estructura

```
src/topology_scanner/
├── scanner.py      # Todo lo de nmap: descubrimiento (fase 1, ping scan) + escaneo completo (fase 2)
├── classifier.py   # clasificar_dispositivo(vendor) -> categoría, iconos por categoría
├── graph.py        # construir_grafo(resultados, rango, topologia=None) -> networkx.Graph (estrella, o árbol real con topología SNMP)
├── export.py       # exportar_html (pyvis; círculo, o árbol por niveles con topología SNMP), exportar_texto, exportar_diff_texto, exportar_csv
├── history.py      # registrar_y_comparar(resultados, rango, db_path) -> guarda en SQLite y compara con el escaneo anterior
├── rangos.py       # varios rangos: parsear_rangos (validación), rango_de / repartir_por_rango (qué host es de qué rango)
├── snmp.py         # topología real por SNMP (roadmap 6, en curso): consulta con pysnmp, parsers puros e inferir_topologia (quién cuelga de quién)
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

El registro completo, con el porqué y los bugs que motivó cada una, está en
[`docs/decisiones.md`](docs/decisiones.md). **Añade ahí cada decisión
nueva.** Aquí solo va lo que hay que tener presente al editar:

**Alcance (limitaciones aceptadas, no bugs)**
- Sin `--snmp`, la topología es una **estrella aproximada** (hub = red), no
  la física real. Con `--snmp`, árbol real a partir de las tablas de los
  routers (CLI y web). Si SNMP falla, se avisa y se dibuja la
  estrella: nunca aborta un escaneo de nmap que sí ha funcionado.
- Categoría por MAC = **heurística por palabras clave** sobre el vendor
  (`CATEGORIA_POR_VENDOR`). Solo funciona en el mismo segmento L2.
- Escaneo en 2 fases (ping scan → escaneo completo solo de vivos); `-O`
  solo con `--con-so`. `PUERTOS_SENSIBLES` es una señal visual, no una
  auditoría.

**Fuentes únicas de verdad (reutilizar, no duplicar)**
- `scanner.DEFAULT_NMAP_ARGS` / `PUERTOS_POR_DEFECTO`: valores por defecto de nmap.
- `history.hay_cambios(diff)`: "¿tiene contenido este diff?" — no reimplementar
  con `a or b or c` (devuelve un dict, no un bool; causó un `TypeError`).
- `classifier.ICONOS_POR_CATEGORIA`: iconos de nodos y leyenda, cada uno con su
  propio `face`/`weight` (los de marca como Apple van en "Font Awesome 5 Brands").
- `export.posiciones_circulares`: único layout, lo usan el HTML de pyvis y el
  SVG de la web. `scanner.parsear_host`: parseo de host, lo reutiliza la web.
- Versión: `importlib.metadata` en `__init__.py`; `pyproject.toml` manda.
- Grafo de imports permitido además del principio de arriba:
  `scanner → classifier`, `history → classifier`, `export → history`.

**Trampas conocidas**
- `history.py`: compara solo contra el último escaneo **del mismo rango**, purga
  más allá de `mantener_ultimos` (50), y un `HistoryError` se loguea pero no aborta.
  Con varios rangos, `cli.py` reparte los resultados (`rangos.repartir_por_rango`)
  y registra uno por rango: nunca se guarda "a b" como si fuera un rango.
  La web hace lo mismo y junta los diffs con `history.combinar_diffs` para
  mostrarlos en un solo panel.
- Varios rangos van como **argumentos separados**, nunca partiendo por comas:
  `192.168.1.1,5` es sintaxis de nmap (.1 y .5). Con uno solo se admite cualquier
  sintaxis de nmap; con varios, cada uno tiene que ser IP o CIDR.
- `export.exportar_html`: CSS inyectado a mano (`100vh`, ocultar el
  `<center><h1>` vacío de pyvis), `x`/`y` + `physics=False` por nodo, y
  `cdn_resources="remote"` para no depender de una carpeta `lib/` local.
- `scanner.avisar_si_nmap_reporto_error()` tras cada `.scan()`: nmap puede
  "terminar bien" sin haber escaneado nada.
- `.gitignore` cubre `*.html`/`*.db`/`*.csv` en bloque: pueden contener IPs/MACs reales.
- Tests, docstrings y documentación usan datos **inventados**: IPs de documentación
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) o rangos privados genéricos, y
  MACs locales `02:00:00:…`. Nunca IPs, MACs ni nombres de la red real del mantenedor,
  aunque se hayan usado para validar algo en vivo (el repo es público).

**`webapp.py` (Streamlit)**
- Imports **absolutos** (`streamlit run` lo ejecuta como script suelto).
- Escaneo cancelable: `subprocess.Popen` de nmap en un `threading.Thread`
  (no `escanear_red()` ni `PortScannerAsync`). XML a archivo temporal
  (`-oX`), stdout+stderr combinados leídos en vivo (`-v`) para el log.
  Excepciones del hilo → `contenedor["error"]`. Binario vía
  `nmap.PortScanner()._nmap_path`, no `shutil.which`. `atexit` mata nmap huérfano.
- Progreso con `st.fragment(run_every="1s")`, nunca `sleep()+st.rerun()`.
  Mensajes que deben sobrevivir a un rerun → `st.session_state["mensaje"]`.
- Todo HTML pasado a `st.markdown` pasa por `_compactar_html()` (una línea en
  blanco corta el HTML en crudo). Lo que necesita `<script>` (el grafo SVG con
  pan/zoom) va en `st.components.v1.html` e importa sus propias fuentes/FA.
- Estilo de un widget concreto: `key="..."` + selector `.st-key-<key>`.
- Todo texto externo (hostname, SO, rango, identidad SNMP, log de nmap) que
  se mete en HTML va con `html.escape` — hay un test por panel.
- Temporales `.xml`/`.csv` se borran en un `finally` (el `.html` de pyvis ya no se genera en la web). `pagina_inventario`
  se resetea a 1 en cada escaneo.

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
6. ~~**Topología real vía SNMP**~~ — hecho en el CLI (`snmp.py`, flag
   `--snmp`, community en `TOPOLOGY_SNMP_COMMUNITY`, extra `[snmp]`),
   validado contra el MikroTik hAP ac2 del mantenedor; también en la web
   (interruptor en el sidebar), y vecinos también por LLDP-MIB estándar
   (cualquier fabricante), y SNMPv3 además de v2c.
7. ~~**Interfaz web con Streamlit**~~ — hecho (`webapp.py`, extra opcional
   `[web]`, entry point `topology-scanner-web`). Formulario con detección
   automática del rango local (botón "Detectar mi red", truco de socket
   UDP sin admin/sudo), escaneo cancelable de verdad (mata el proceso nmap,
   no solo la UI), tabla de resultados, descarga de CSV y el grafo embebido.
   Más tarde tuvo un rediseño visual completo ("Command Center" — ver
   `docs/decisiones.md`): sidebar, topología en SVG propio con pan/zoom,
   log de escaneo en vivo, paginación del inventario.
8. ~~**CI con GitHub Actions**~~ — hecho (`.github/workflows/ci.yml`, pytest +
   ruff en 3.10/3.12, badge en el README).

## Forma de trabajar preferida

- Features pequeñas, un commit por feature, mensajes descriptivos.
- Test primero (aunque sea simple) antes de implementar la función.
- `pytest tests/ -v` y `ruff check src/ tests/` deben seguir en verde antes de cualquier commit.
- Explicar brevemente en qué módulo encaja cada cambio y por qué, no solo
  soltar el código — el mantenedor está aprendiendo Python activamente.

## Aviso legal (recordar si se toca algo relacionado con el escaneo)

Esta herramienta solo debe usarse contra redes propias o con autorización
explícita. No añadir features que faciliten el escaneo de redes ajenas sin
permiso.
