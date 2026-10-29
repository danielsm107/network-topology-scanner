# Fase 3 (despliegue en Kubernetes) — plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** el escáner corre en el k3s del homelab: un CronJob escanea las dos redes de casa cada noche a
las 3:00 y la web (detrás del NPM de casa) lista las ejecuciones guardadas, las reabre completas y lanza
escaneos solo contra rangos permitidos.

**Architecture:** Primero la app (v1.3.0): `rangos.py` gana la validación de rangos permitidos (pura),
`history.py` pasa a guardar **ejecuciones** (todos los rangos de una pasada + topología SNMP en JSON) con
migración en sitio, CLI y web registran ejecuciones, y la web lista y reabre las guardadas. Después, un
chart de Helm (`deploy/helm/topology-scanner/`) con CronJob y Deployment (misma imagen de GHCR,
`hostNetwork`, UID 10001, solo `NET_RAW`/`NET_ADMIN`) que comparten un PVC con `historial.db`. Sin
Service ni Ingress: NPM apunta a `<IP del nodo>:8501`.

**Tech Stack:** Python 3.10+ (sqlite3, ipaddress), Streamlit (`AppTest`), Helm 3, k3s (`local-path`),
GitHub Actions (`azure/setup-helm`).

**Spec:** `docs/superpowers/specs/2026-10-29-fase-3-kubernetes-design.md` (y el diseño general
`2026-10-22-fase-devops-design.md`, fila 3).

## Global Constraints

- Rama `fase-3-kubernetes`. Un commit por tarea; `pytest tests/ -v` y `ruff check src/ tests/ scripts/`
  en verde antes de cada commit (con `.venv/Scripts/` en el PC del mantenedor).
- Variables de entorno nuevas, en inglés: `TOPOLOGY_ALLOWED_RANGES` (CIDRs separados por espacios) y
  `TOPOLOGY_HISTORY_DB` (por defecto `historial.db`). Sin ellas, todo se comporta como en la v1.2.2.
- Grafo de imports intacto: `rangos` y `classifier` no importan a nadie; `history → classifier`.
- Textos de la interfaz en inglés; docstrings, comentarios y docs en castellano.
- Datos inventados en tests, docs y `values` versionados: `192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`, MACs `02:00:00:…`. Nada de la red real (IPs, dominio, usuario SNMP) en git.
- Imagen `ghcr.io/danielsm107/topology-scanner` con **tag fijo** (`1.3.0`), nunca `latest`.
- Pods: `hostNetwork: true`, `dnsPolicy: ClusterFirstWithHostNet`, `runAsNonRoot`, UID/GID/fsGroup 10001,
  `capabilities: {drop: [ALL], add: [NET_RAW, NET_ADMIN]}`; **nunca** `privileged` ni
  `allowPrivilegeEscalation: false` (anula las capacidades de archivo de nmap, fase 1).
- CronJob: `schedule: "0 3 * * *"`, `timeZone: Europe/Madrid`, `concurrencyPolicy: Forbid`,
  `backoffLimit: 0`, 3 Jobs buenos y 3 fallidos de historial.
- Actions de terceros fijadas por SHA con `# vX.Y.Z` al lado (lo comprueba `tests/test_workflows.py`).
- Lo marcado **[A MANO]** lo hace el mantenedor con supervisión.

## Review Focus

1. **Un `historial.db` de la v1.2.x** abierto por la v1.3.0 → migra solo, no pierde escaneos y cada uno
   sale en la lista como una ejecución de un rango → `test_migra_historial_antiguo` (Tarea 2).
2. **CronJob y web escribiendo a la vez** en el mismo `historial.db` → espera y escribe, sin
   `database is locked` → `test_registrar_espera_a_otra_escritura` (Tarea 2).
3. **Rangos escritos de otra forma**: una IP suelta o un /25 dentro del /24 permitido se aceptan; un /23
   que *contiene* al permitido, otra red, o IPv6 contra una lista IPv4 se rechazan sin excepción →
   `test_validar_permitidos_*` (Tarea 1).
4. **`TOPOLOGY_ALLOWED_RANGES` mal escrita** → la web no escanea "sin límites" en silencio: error visible y
   ningún escaneo (falla cerrado) → `test_variable_de_permitidos_invalida_bloquea_el_escaneo` (Tarea 1).
5. **Ejecución con SNMP fallido** (`topologia=None`) → se guarda, se lista y se reabre como estrella sin
   error → `test_cargar_ejecucion_sin_topologia` (Tarea 2).

---

### Task 1: Rangos permitidos en la web

**Files:**
- Modify: `src/topology_scanner/rangos.py`, `src/topology_scanner/webapp.py` (`_validar_rangos`,
  `_validar_snmp`)
- Test: `tests/test_rangos.py`, `tests/test_webapp.py`

**Interfaces:**
- Produces (en `rangos.py`):
  - `VARIABLE_RANGOS_PERMITIDOS = "TOPOLOGY_ALLOWED_RANGES"`
  - `parsear_permitidos(texto: str | None) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None`:
    `None` si la variable no está o está vacía (sin límite); `ValueError` si algún elemento no es CIDR/IP.
  - `validar_permitidos(objetivos: list[str], permitidos: list[...]) -> None`: `ValueError` con
    `"'<objetivo>' is outside the allowed ranges (<permitidos separados por comas>)"` si alguno no es
    IP/CIDR o no está contenido (`subnet_of`, misma versión de IP) en algún permitido.

- [ ] **Step 1: tests en `tests/test_rangos.py`**
  - `test_parsear_permitidos_sin_variable` → `parsear_permitidos(None) is None` y `parsear_permitidos("  ") is None`.
  - `test_parsear_permitidos_lista` → `"192.0.2.0/24 198.51.100.0/24"` da dos redes.
  - `test_parsear_permitidos_invalida` → `"192.0.2.0/24 basura"` lanza `ValueError`.
  - `test_validar_permitidos_acepta_contenidos` → `["192.0.2.7", "192.0.2.128/25", "198.51.100.0/24"]`
    contra `192.0.2.0/24 198.51.100.0/24`: no lanza.
  - `test_validar_permitidos_rechaza_supered` → `["192.0.2.0/23"]` lanza `ValueError` con `"192.0.2.0/23"` en el mensaje.
  - `test_validar_permitidos_rechaza_otra_red_e_ipv6` → `["203.0.113.0/24"]` y `["2001:db8::/64"]` lanzan `ValueError`.
  - `test_validar_permitidos_rechaza_sintaxis_nmap` → `["192.0.2.1-5"]` lanza `ValueError`.
- [ ] **Step 2:** `pytest tests/test_rangos.py -v` → FAIL (`ImportError`).
- [ ] **Step 3:** implementar en `rangos.py` (`ip_network(strict=False)`; comparar `version` antes de `subnet_of`).
- [ ] **Step 4: tests en `tests/test_webapp.py`** (todos con el fixture `sin_escaneos_reales`):
  - `test_rango_fuera_de_permitidos_no_escanea` → con `TOPOLOGY_ALLOWED_RANGES="192.0.2.0/24"` (vía
    `monkeypatch.setenv`) y rango `203.0.113.0/24`, pulsar "Scan" muestra un error con
    `"outside the allowed ranges"` y nmap no se lanza.
  - `test_ip_snmp_fuera_de_permitidos_no_escanea` → rango `192.0.2.0/24`, SNMP activado con IP
    `203.0.113.1`: error, sin escaneo.
  - `test_variable_de_permitidos_invalida_bloquea_el_escaneo` → variable `"basura"`: error que nombra
    `TOPOLOGY_ALLOWED_RANGES`, sin escaneo.
  - `test_sin_variable_se_escanea_como_antes` → sin la variable, un rango `203.0.113.0/24` pasa la validación.
- [ ] **Step 5:** `_validar_rangos` y `_validar_snmp` leen `os.environ.get(VARIABLE_RANGOS_PERMITIDOS)` y,
  si hay lista, llaman a `validar_permitidos` (rangos, e IPs SNMP). Error de la variable:
  `"TOPOLOGY_ALLOWED_RANGES is invalid: <motivo>. No scans until it is fixed."`.
- [ ] **Step 6:** suite + ruff en verde. Commit `feat(web): solo escanea rangos permitidos (TOPOLOGY_ALLOWED_RANGES)`.

### Task 2: Ejecuciones en el historial (`history.py`)

**Files:**
- Modify: `src/topology_scanner/history.py`
- Test: `tests/test_history.py`

**Interfaces:**
- Consumes: `classifier.puertos_sensibles_abiertos(puertos: list) -> list`.
- Produces:
  - `VARIABLE_DB = "TOPOLOGY_HISTORY_DB"`
  - `registrar_ejecucion(resultados_por_rango: dict[str, dict], topologia: dict | None = None,
    origen: str = "cli", db_path: str = DB_POR_DEFECTO, mantener_ultimos: int = MANTENER_ULTIMOS_POR_DEFECTO)
    -> dict[str, dict]`: guarda una ejecución con un escaneo por rango y devuelve `{rango: diff}` (diff con
    el formato de `registrar_y_comparar`). El llamador junta con `combinar_diffs` si quiere uno.
  - `listar_ejecuciones(db_path: str = DB_POR_DEFECTO, limite: int = 20) -> list[dict]`, más reciente
    primero: `{"id": int, "fecha": str, "origen": str, "rangos": list[str], "total_hosts": int, "alertas": int}`.
  - `cargar_ejecucion(ejecucion_id: int, db_path: str = DB_POR_DEFECTO) -> dict`:
    `{"id", "fecha", "origen", "rangos": list[str], "resultados": dict, "topologia": dict | None, "diff": dict}`.
    `resultados[ip]` con las claves de `scanner.parsear_host` (`estado="up"`, `producto=""`, `alertas`
    recalculadas); `diff` = `combinar_diffs` de comparar cada escaneo con el **anterior del mismo rango**
    a esa ejecución (no con el último).
- `registrar_y_comparar` se queda (mismo contrato) como envoltorio de un solo rango de `registrar_ejecucion`.
  `listar_escaneos_recientes` se queda hasta la Tarea 4.

- [ ] **Step 1: tests** (con `tmp_path`):
  - `test_registrar_ejecucion_varios_rangos` → dos rangos en una llamada: `listar_ejecuciones` da **una**
    entrada con `rangos` = los dos, `total_hosts` y `alertas` (un 23/telnet) correctos.
  - `test_cargar_ejecucion_completa` → ida y vuelta de resultados y de una topología de ejemplo (dict con
    `equipos`, `enlaces`, `redes`, `ubicaciones`), igual a la original.
  - `test_cargar_ejecucion_sin_topologia` → `topologia=None` se lista y se carga con `topologia is None`.
  - `test_diff_de_una_ejecucion_antigua` → tres ejecuciones; cargar la 2.ª compara con la 1.ª, no con la 3.ª.
  - `test_migra_historial_antiguo` → crear a mano una base con el esquema de la v1.2.2 (tablas `escaneos`,
    `hosts`, `puertos` sin `ejecucion_id`) con dos escaneos; `listar_ejecuciones` da dos entradas de un
    rango con origen `"antiguo"` y `cargar_ejecucion` las abre.
  - `test_purga_borra_ejecuciones_huerfanas` → con `mantener_ultimos=2` y 3 ejecuciones, quedan 2 y ninguna vacía.
  - `test_registrar_espera_a_otra_escritura` → un hilo abre la misma base, `BEGIN IMMEDIATE`, duerme 1 s y
    hace commit; `registrar_ejecucion` en paralelo termina sin `HistoryError`.
  - Los tests existentes de `registrar_y_comparar` siguen pasando sin tocarlos.
- [ ] **Step 2:** `pytest tests/test_history.py -v` → los nuevos FAIL.
- [ ] **Step 3: implementar.**
  - Esquema: tabla `ejecuciones (id INTEGER PRIMARY KEY AUTOINCREMENT, fecha TEXT NOT NULL, origen TEXT
    NOT NULL, topologia TEXT)` y columna `escaneos.ejecucion_id INTEGER REFERENCES ejecuciones(id)`.
  - Migración en `_crear_tablas`: si falta la columna (`PRAGMA table_info(escaneos)`), `ALTER TABLE` y una
    ejecución `origen="antiguo"` (misma fecha, `topologia` NULL) por cada escaneo sin ella.
  - Todas las conexiones con `sqlite3.connect(db_path, timeout=30)`.
  - La purga por rango borra después las ejecuciones que se queden sin escaneos.
- [ ] **Step 4:** `pytest tests/test_history.py -v` → PASS; suite + ruff en verde.
- [ ] **Step 5:** commit `feat(history): guarda ejecuciones completas con su topología SNMP`.

### Task 3: CLI y web registran ejecuciones

**Files:**
- Modify: `src/topology_scanner/cli.py` (`main`), `src/topology_scanner/webapp.py` (`_finalizar_resultados`,
  llamadas al historial)
- Test: `tests/test_cli.py`, `tests/test_webapp.py`

**Interfaces:**
- Consumes: `history.registrar_ejecucion`, `history.VARIABLE_DB`, `history.combinar_diffs`.
- Produces: en la web, `_ruta_historial() -> str` = `os.environ.get(VARIABLE_DB, DB_POR_DEFECTO)`; toda
  llamada al historial de `webapp.py` usa esa ruta.

- [ ] **Step 1: tests.**
  - `tests/test_cli.py::test_cli_registra_una_ejecucion_con_topologia` → con nmap y SNMP mockeados, dos
    rangos y `--snmp`: `registrar_ejecucion` se llama **una vez** con los dos rangos, la topología y
    `origen="cli"`; la salida de texto sigue mostrando el diff de cada rango.
  - `tests/test_cli.py::test_cli_sin_snmp_registra_topologia_none`.
  - `tests/test_webapp.py::test_finalizar_registra_ejecucion_web` → `_finalizar_resultados(..., guardar_historial=True, snmp=...)`
    con SNMP mockeado llama a `registrar_ejecucion(..., origen="web", db_path=<TOPOLOGY_HISTORY_DB>)` con la topología.
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** en `cli.main`, obtener la topología **antes** del historial y sustituir el bucle de
  `registrar_y_comparar` por una llamada a `registrar_ejecucion(repartir_por_rango(...), topologia,
  origen="cli", db_path=args.history_db)`; imprimir cada diff como hoy. En `_finalizar_resultados`, lo mismo
  con `origen="web"` y `combinar_diffs` para mostrar. `HistoryError` sigue sin abortar.
- [ ] **Step 4:** suite + ruff en verde. Commit `feat: CLI y web guardan cada pasada como una ejecución`.

### Task 4: La web lista y reabre ejecuciones

**Files:**
- Modify: `src/topology_scanner/webapp.py` (panel "Recent history" del sidebar, `_mostrar_resultado`,
  `_generar_historial_html` se elimina), `src/topology_scanner/history.py` (se elimina
  `listar_escaneos_recientes` si ya no la usa nadie), `scripts/demo_web.py` si la usa
- Test: `tests/test_webapp.py`, `tests/test_history.py`

**Interfaces:**
- Consumes: `history.listar_ejecuciones`, `history.cargar_ejecucion`, `_ruta_historial()`.
- Produces:
  - `_etiqueta_ejecucion(ejecucion: dict) -> str`: `"29 Oct 03:00 · cli · 2 ranges · 34 hosts · 2⚠"`.
    El origen tal cual (`cli`, `web`; el `"antiguo"` de la migración se muestra como `old`): no se deduce
    "nightly" de la hora. `· N⚠` solo si hay alertas; `1 range` en singular.
  - `_resultado_desde_ejecucion(ejecucion: dict) -> dict`: mismo formato que devuelve `_finalizar_resultados`
    (`resultados`, `diff`, `rango`, `rangos`, `topologia`, `avisos_snmp=[]`) más `"guardado": {"fecha", "origen"}`.

- [ ] **Step 1: tests.**
  - `test_etiqueta_ejecucion` → singular/plural, sin `⚠` cuando no hay alertas.
  - `test_resultado_desde_ejecucion_tiene_formato_de_finalizar` → mismas claves que `_finalizar_resultados`.
  - `test_elegir_ejecucion_la_muestra` (AppTest, `sin_escaneos_reales`) → `TOPOLOGY_HISTORY_DB` apunta a
    una base de `tmp_path` con dos ejecuciones registradas; elegir la más antigua en la lista del sidebar
    muestra sus hosts en el inventario y un aviso `"Saved scan · <fecha> · <origen>"`.
  - `test_lista_vacia` → sin base: `"No saved scans yet."`.
  - Los rangos de una ejecución que salen en el HTML van con `html.escape` (test como en los demás paneles).
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** el panel pasa a un `st.selectbox` (`key="ejecucion_elegida"`, `index=None`,
  `placeholder="Choose a saved scan"`) con las ejecuciones de `listar_ejecuciones(_ruta_historial())`; al
  elegir, `st.session_state.resultado = _resultado_desde_ejecucion(cargar_ejecucion(id, ...))` y
  `pagina_inventario = 1`. Un escaneo nuevo deja la selección en `None`. `_mostrar_resultado` pinta el aviso
  de "Saved scan" si el resultado trae `guardado`.
- [ ] **Step 4:** suite + ruff en verde. Commit `feat(web): lista de escaneos guardados para reabrirlos`.

### Task 5: Release v1.3.0

**Files:**
- Modify: `pyproject.toml` (`version = "1.3.0"`), `CHANGELOG.md` (sección `[1.3.0] - <fecha>`: Added rangos
  permitidos, ejecuciones y lista en la web; Changed historial con migración automática), `README.md`
  (las dos variables nuevas), `CLAUDE.md` (fuentes únicas: `rangos.validar_permitidos`,
  `history.registrar_ejecucion`/`cargar_ejecucion`), `docs/decisiones.md`

- [ ] **Step 1:** cambios de arriba; suite + ruff en verde; commit `release: v1.3.0`.
- [ ] **Step 2:** push y PR a `main` con las Tareas 1-5; CI en verde.
- [ ] **Step 3: [A MANO]** merge del PR; `git tag v1.3.0 && git push origin v1.3.0`.
- [ ] **Step 4:** comprobar la release: `pip index versions topology-scanner` muestra 1.3.0 y
  `docker pull ghcr.io/danielsm107/topology-scanner:1.3.0` funciona sin `docker login`.
- [ ] **Step 5:** `fase-3-kubernetes` se rebasa sobre `main` para seguir con el chart.

### Task 6: Chart de Helm y CI

**Files:**
- Create: `deploy/helm/topology-scanner/{Chart.yaml,values.yaml,values.example.yaml}`,
  `deploy/helm/topology-scanner/templates/{_helpers.tpl,cronjob.yaml,deployment.yaml,pvc.yaml,NOTES.txt}`,
  `deploy/helm/.gitignore` (`values.local.yaml`), `tests/test_helm.py`
- Modify: `.github/workflows/ci.yml` (job `helm`), `tests/test_workflows.py`

**Interfaces:**
- Produces — claves de `values.yaml` (valores por defecto entre paréntesis):
  `image.repository` (`ghcr.io/danielsm107/topology-scanner`), `image.tag` (`"1.3.0"`),
  `escaneo.schedule` (`"0 3 * * *"`), `escaneo.timeZone` (`Europe/Madrid`), `escaneo.rangos`
  (`["192.0.2.0/24"]`), `escaneo.osDetection` (`true`), `escaneo.snmp` (`[]`, IPs de routers),
  `escaneo.activeDeadlineSeconds` (`14400`), `rangosPermitidos` (`[]` = los de `escaneo.rangos`),
  `web.puerto` (`8501`), `snmpSecret` (`topology-scanner-snmp`), `persistencia.tamano` (`1Gi`),
  `resources.escaneo` / `resources.web` (requests 100m/256Mi, limits 1 CPU/1Gi).

- [ ] **Step 1:** instalar Helm en el PC (`winget install Helm.Helm`); `helm version` → v3.
- [ ] **Step 2: tests en `tests/test_helm.py`** (se saltan con `pytest.skip` si `shutil.which("helm")` es
  `None`; renderizan con `helm template t deploy/helm/topology-scanner -f .../values.example.yaml` y
  `yaml.safe_load_all`):
  - `test_pods_con_hostnetwork_y_capacidades_minimas` → CronJob y Deployment: `hostNetwork`,
    `dnsPolicy: ClusterFirstWithHostNet`, `runAsNonRoot`, `runAsUser: 10001`, `fsGroup: 10001`,
    `drop == ["ALL"]`, `add == ["NET_RAW", "NET_ADMIN"]`, ni `privileged` ni `allowPrivilegeEscalation`.
  - `test_cronjob_nocturno` → `schedule`, `timeZone`, `concurrencyPolicy: Forbid`, `backoffLimit: 0`, y los
    args incluyen los rangos, `--os-detection`, `--history-db /data/historial.db` y `--snmp <ip>`.
  - `test_imagen_con_tag_fijo` → ninguna imagen termina en `:latest` ni va sin tag.
  - `test_web_recreate_y_variables` → `strategy.type: Recreate`, comando `topology-scanner-web`,
    `TOPOLOGY_ALLOWED_RANGES` no vacía, `TOPOLOGY_HISTORY_DB=/data/historial.db`, `STREAMLIT_SERVER_PORT`.
  - `test_permitidos_por_defecto_son_los_rangos` → con `rangosPermitidos: []`, la variable vale los rangos del escaneo.
  - `test_pvc_se_conserva_al_desinstalar` → anotación `helm.sh/resource-policy: keep`, `ReadWriteOnce`.
  - `test_credenciales_snmp_desde_secret` → las tres `TOPOLOGY_SNMP_*` v3 vienen de `secretKeyRef` del
    `snmpSecret`, con `optional: true` (sin `escaneo.snmp` no hace falta el Secret).
- [ ] **Step 3:** `pytest tests/test_helm.py -v` → FAIL (no existe el chart).
- [ ] **Step 4:** el chart. Sin Service ni Ingress. Volumen `/data` del PVC en los dos pods.
  `NOTES.txt` dice cómo lanzar un escaneo a mano (`kubectl create job --from=cronjob/...`) y que NPM apunte
  a `<IP del nodo>:<web.puerto>` con websockets.
- [ ] **Step 5:** `helm lint` y tests → PASS.
- [ ] **Step 6:** job `helm` en `ci.yml`: checkout, `azure/setup-helm` fijado por SHA (resolverlo con
  `gh api repos/Azure/setup-helm/git/ref/tags/<tag>`), `helm lint` y `helm template` con
  `values.example.yaml`; el job `test` instala Helm también, para que `test_helm.py` no se salte en CI.
  `tests/test_workflows.py`: test que exige el job `helm` con esos dos pasos.
- [ ] **Step 7:** suite + ruff en verde. Commit `feat(deploy): chart de Helm con escaneo nocturno y web`.

### Task 7: Instalación en el k3s y documentación

**Files:**
- Create: `docs/devops/runbooks/03-kubernetes.md`
- Modify: `docs/devops/README.md` (fase 3 → "Hecha", piezas nuevas), `docs/decisiones.md`, `CLAUDE.md`
  (estructura `deploy/helm/`, comandos de Helm, job `helm`)

- [ ] **Step 1: [A MANO] RouterOS:** comprobar desde la VM que la red A responde (`ping` al hAP) y permitir
  SNMPv3 del usuario de solo lectura desde la IP con la que el UDM saca a la red B. Probar desde la VM con
  `snmpwalk -v3 ... sysName`.
- [ ] **Step 2: [A MANO] Secret:** las tres claves en un archivo fuera del repo (como `proxmox.env`) y
  `kubectl create namespace topology-scanner` + `kubectl -n topology-scanner create secret generic
  topology-scanner-snmp --from-env-file=<archivo>`. Nada en el historial de la shell.
- [ ] **Step 3:** `deploy/helm/values.local.yaml` con los rangos y la IP SNMP reales (ignorado; comprobar
  con `git status`).
- [ ] **Step 4: [A MANO]** `helm install topology-scanner deploy/helm/topology-scanner -n topology-scanner
  -f deploy/helm/values.local.yaml`; `kubectl -n topology-scanner get pods` → web `Running`.
- [ ] **Step 5: [A MANO]** `kubectl -n topology-scanner create job --from=cronjob/topology-scanner-escaneo
  prueba` y `kubectl logs -f job/prueba`: termina bien, con MAC en la red B y árbol SNMP. Apuntar la
  duración y ajustar `activeDeadlineSeconds` si hace falta (`helm upgrade`).
- [ ] **Step 6: [A MANO] NPM:** proxy host `scanner.<dominio>` → `<IP del nodo>:8501`, "Websockets Support"
  activado. Comprobar en el navegador: la ejecución `prueba` sale en la lista y se abre completa; un rango
  de fuera se rechaza; un escaneo lanzado desde la web aparece en la lista.
- [ ] **Step 7:** runbook (formato de `02-proxmox-vm.md`): requisitos, tareas a mano y por qué (SNMP desde la
  IP del UDM y por qué v3, Secret, NPM con websockets, Access List opcional), install/upgrade, escaneo a
  mano, comprobaciones, cómo cambiar rangos u horario, desinstalar sin perder el historial (PVC con
  `keep`), riesgos (SO a través del NAT, duración de `-O`). `docs/decisiones.md`: las decisiones del spec
  (hostNetwork sin Service/Ingress, Recreate, sin reintentos, v3, permitidos con IPs SNMP, ejecuciones).
- [ ] **Step 8:** suite + ruff en verde; commit `docs: runbook de la fase 3 (despliegue en Kubernetes)`;
  push y PR a `main`.
- [ ] **Step 9:** a la mañana siguiente, la lista tiene una ejecución de las 3:00 con origen `cli`
  (cierre de la fase; se anota en el PR).
