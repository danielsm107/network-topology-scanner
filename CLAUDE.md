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
ruff check src/ tests/ scripts/                 # lint (lo mismo que ejecuta CI)

topology-scanner 192.168.1.0/24 [--fast] [--os-detection] [--output x.html] [--csv x.csv]
topology-scanner 192.168.1.0/24 10.0.10.0/24 [--snmp 192.168.1.1]   # varios rangos a la vez
# --snmp: credenciales por entorno, TOPOLOGY_SNMP_COMMUNITY (v2c) o TOPOLOGY_SNMP_USER/_AUTH_KEY/_PRIV_KEY (v3)
topology-scanner-web                            # o: streamlit run src/topology_scanner/webapp.py

docker build -t topology-scanner:dev .          # imagen (en el PC: context `docker-lab`, la VM de Proxmox)
docker run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN -v ts-datos:/data topology-scanner:dev <rango> --fast

# Terraform (infra/): fmt/validate/test sin credenciales; plan/apply solo desde el PC del mantenedor
terraform fmt -check -recursive infra/
cd infra/proxmox && terraform init -backend=false && terraform validate && terraform test
# apply real: runbook docs/devops/runbooks/02-proxmox-vm.md (token por entorno, perfil AWS `personal`)
```

El escaneo real necesita nmap instalado y, para MAC/`-O`, privilegios
(`sudo` en Linux, terminal de administrador en Windows).

CI (`.github/workflows/ci.yml`) ejecuta `ruff check src/ tests/ scripts/` + `pytest`
en Python 3.10 y 3.12 en cada push/PR a `main` — ambos tienen que pasar. El job
`imagen` construye la imagen Docker, la prueba por fuera (UID 10001, nmap con y
sin capacidades) y la escanea con Trivy (falla con críticas que tengan arreglo).
El job `terraform` pasa `fmt`, `validate` en cada raíz de `infra/` (un test
obliga a añadir las nuevas) y `terraform test` con el provider simulado; nunca
`apply` (la API de Proxmox solo es accesible desde la LAN). Toda action que no sea de GitHub (`actions/...`) va **fijada por SHA**, y Trivy
por digest, no por tag (ataque a las tags de `trivy-action`, marzo de 2026); lo
comprueba `tests/test_workflows.py`. Las de `actions/` van por tag.

Release (`.github/workflows/release.yml`): un tag `vX.Y.Z` reutiliza CI,
comprueba que el tag coincide con la versión de `pyproject.toml` y que
`CHANGELOG.md` tiene su sección, publica en PyPI (trusted publishing, sin
tokens) y la imagen en `ghcr.io/danielsm107/topology-scanner:X.Y.Z` + `latest`
(amd64 y arm64), y crea la release de GitHub con esas notas. Lanzado a mano solo
publica en TestPyPI. Para sacar versión: subir `version`, añadir la sección
al CHANGELOG, commit, y `git tag vX.Y.Z && git push origin vX.Y.Z`.

## Estructura

```
src/topology_scanner/
├── scanner.py      # Todo lo de nmap: descubrimiento (fase 1, ping scan) + escaneo completo (fase 2)
├── classifier.py   # clasificar_dispositivo(vendor) -> categoría, iconos por categoría
├── graph.py        # construir_grafo(resultados, rango, topologia=None) -> networkx.Graph (estrella, o árbol real con topología SNMP)
├── export.py       # exportar_html (pyvis; círculo, o árbol por niveles con topología SNMP), exportar_texto, exportar_diff_texto, exportar_csv
├── history.py      # registrar_y_comparar(resultados, rango, db_path) -> guarda en SQLite y compara con el escaneo anterior
├── rangos.py       # varios rangos: parsear_rangos (validación), rango_de / repartir_por_rango (qué host es de qué rango)
├── snmp.py         # topología real por SNMP v2c/v3: consulta (pysnmp), parsers puros (ARP, rutas, MAC, vecinos MikroTik y LLDP) e inferir_topologia
├── cli.py          # argparse, orquesta scanner -> graph -> export (+ history)
└── webapp.py       # interfaz Streamlit (opcional): mismo pipeline, con escaneo cancelable
tests/               # un test_<modulo>.py por módulo
scripts/demo_arbol.py  # árbol SNMP con datos inventados para la captura del README (no se instala)
scripts/demo_web.py    # web con un escaneo inventado cargado, para las capturas del README (streamlit run)
Dockerfile, .dockerignore  # imagen: nmap sin root (setcap, UID 10001), /data, web por STREAMLIT_*
compose.yaml           # uso con Docker Compose (en inglés: es para copiarlo); web solo en 127.0.0.1
docs/devops/           # fase DevOps: README (estado por fase) y runbooks/NN-<fase>.md
infra/aws/bootstrap/   # Terraform: bucket S3 del estado (estado local, ignorado)
infra/proxmox/         # Terraform: VM k3s en Proxmox (cloud-init + network-config propios); tfvars/backend.hcl ignorados
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
  solo con `--os-detection`. `PUERTOS_SENSIBLES` es una señal visual, no una
  auditoría.

**Fuentes únicas de verdad (reutilizar, no duplicar)**
- `scanner.DEFAULT_NMAP_ARGS` / `PUERTOS_POR_DEFECTO`: valores por defecto de nmap.
- `history.hay_cambios(diff)`: "¿tiene contenido este diff?" — no reimplementar
  con `a or b or c` (devuelve un dict, no un bool; causó un `TypeError`).
- `classifier.ICONOS_POR_CATEGORIA`: iconos de nodos y leyenda, cada uno con su
  propio `face`/`weight` (los de marca como Apple van en "Font Awesome 5 Brands").
- Layouts: `export.posiciones_circulares` (estrella de un rango) y
  `export.posiciones_jerarquicas` (árbol SNMP o varios rangos). Los usan tanto el
  HTML de pyvis como el SVG de la web: nunca un tercer algoritmo de layout. La
  vista isométrica de la web proyecta `posiciones_jerarquicas`, no calcula las suyas.
- `scanner.parsear_host`: parseo de host, lo reutiliza la web.
- `snmp.obtener_topologia` / `credenciales_desde_entorno` / `VARIABLE_*` y
  `rangos.parsear_rangos` / `repartir_por_rango`: compartidos por CLI y web.
- `history.combinar_diffs`: juntar los diffs de varios rangos para mostrarlos.
- `history.registrar_ejecucion` / `listar_ejecuciones` / `cargar_ejecucion`: una
  pasada (todos sus rangos + topología SNMP) es una ejecución; CLI y web guardan
  con `registrar_ejecucion` (`registrar_y_comparar` queda como envoltorio de un rango).
- `rangos.parsear_permitidos` / `validar_permitidos` (`TOPOLOGY_ALLOWED_RANGES`):
  la web valida con ellos rangos **e IPs de SNMP**; si la variable está mal, no escanea.
- Versión: `importlib.metadata` en `__init__.py`; `pyproject.toml` manda.
- Grafo de imports entre módulos de lógica: `scanner → classifier`,
  `history → classifier`, `export → classifier, history`, `graph → rangos`.
  `snmp`, `rangos` y `classifier` no importan a nadie. `cli`/`webapp` orquestan
  e importan lo que necesiten.

**Trampas conocidas**
- `history.py`: compara solo contra el último escaneo **del mismo rango**, purga
  más allá de `mantener_ultimos` (50), y un `HistoryError` se loguea pero no aborta.
  Con varios rangos, `cli.py` reparte los resultados (`rangos.repartir_por_rango`)
  y guarda un escaneo por rango dentro de una ejecución: nunca se guarda "a b"
  como si fuera un rango. La web hace lo mismo y junta los diffs con
  `history.combinar_diffs` para mostrarlos en un solo panel. El esquema se migra
  solo al abrir la base (`_migrar_a_ejecuciones`): un cambio de esquema nuevo
  tiene que migrar también, porque hay `historial.db` de versiones anteriores.
  Conexiones con `_conectar` (timeout 30 s): CronJob y web comparten el archivo.
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
  pan/zoom) va en `st.iframe` (no `st.components.v1.html`, obsoleto) e importa sus propias fuentes/FA.
- Estilo de un widget concreto: `key="..."` + selector `.st-key-<key>`.
- Todo texto externo (hostname, SO, rango, identidad SNMP, log de nmap) que
  se mete en HTML va con `html.escape` — hay un test por panel.
- Temporales `.xml`/`.csv` se borran en un `finally` (el `.html` de pyvis ya no
  se genera en la web). `pagina_inventario`
  se resetea a 1 en cada escaneo.

## Roadmap (por orden de prioridad hablado)

1. ~~**Alertas por puertos sensibles**~~ — hecho.
2. ~~**Historial en SQLite**~~ — hecho (`history.py` + flags `--history-db`/`--no-history`).
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
9. ~~**Varios rangos por ejecución**~~ — hecho (`rangos.py`; CLI y web; historial
   por rango, un centro por rango en la estrella).
10. ~~**Vecinos por LLDP-MIB estándar**~~ — hecho (cualquier fabricante; puerto de
    ambos extremos en las aristas; tolera las desviaciones de RouterOS v6).
11. ~~**SNMPv3**~~ — hecho (CLI y web; SHA + AES por defecto; `[snmp]` instala
    también `cryptography`, que pysnmp necesita para cifrar).
12. ~~**v1.0 en PyPI**~~ — hecho (`release.yml`, `CHANGELOG.md`, captura del
    árbol en el README con `scripts/demo_arbol.py`). Lo siguiente es la fase
    DevOps (contenedor, AWS, Kubernetes, Jenkins...), sin diseñar todavía.

**Ideas pendientes** (sin orden decidido):
- Fabricante (por OUI, con la base de datos de nmap) para los hosts que solo
  ve SNMP, que hoy salen como "?" aunque se conoce su MAC.
- Distinguir AP / switch / router en el árbol con las capacidades que anuncia
  LLDP (`lldpRemSysCapEnabled`); hoy todos los equipos de red salen como router.

## Forma de trabajar preferida

- Features pequeñas, un commit por feature, mensajes descriptivos.
- Test primero (aunque sea simple) antes de implementar la función.
- `pytest tests/ -v` y `ruff check src/ tests/ scripts/` deben seguir en verde antes de cualquier commit.
- Explicar brevemente en qué módulo encaja cada cambio y por qué, no solo
  soltar el código — el mantenedor está aprendiendo Python activamente.

## Aviso legal (recordar si se toca algo relacionado con el escaneo)

Esta herramienta solo debe usarse contra redes propias o con autorización
explícita. No añadir features que faciliten el escaneo de redes ajenas sin
permiso.
