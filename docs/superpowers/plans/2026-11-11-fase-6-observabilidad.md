# Fase 6: observabilidad, plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prometheus, Alertmanager (→ Telegram), Grafana y Pushgateway en k3s, con healthchecks.io vigilando la cadena de alertas desde fuera y las métricas del escaneo nocturno en un panel.

**Architecture:** La app escribe sus métricas a un archivo (`--metrics-file`, formato de texto de Prometheus) y un contenedor del Job las sube al Pushgateway: la app no sabe de Prometheus. La monitorización es el chart oficial `kube-prometheus-stack` con nuestros valores, más un chart propio pequeño (`deploy/monitoring/topology-monitoring/`) con las reglas de alerta y el panel, ambos instalados desde el PC. La alerta `Watchdog` (siempre activa) sale por Alertmanager hacia la URL de ping de healthchecks.io: si deja de llegar, healthchecks.io avisa por Telegram.

**Tech Stack:** Python 3.10+ (sin dependencias nuevas), Helm 4, `kube-prometheus-stack` y `prometheus-pushgateway` (prometheus-community), promtool (imagen `prom/prometheus` por digest) para los tests de reglas, curl (imagen `curlimages/curl` por digest), healthchecks.io, bot de Telegram.

**Spec:** `docs/superpowers/specs/2026-11-11-fase-6-observabilidad-design.md`

## Global Constraints

- La app no importa nada de Prometheus ni añade dependencias: escribe texto plano.
- Secretos (token del bot, URL de ping, contraseña de Grafana) solo en Secrets creados a mano desde archivos en `~/.config/topology-scanner/`; Claude no ve sus valores. El chat ID de Telegram y el dominio de Grafana, en `deploy/monitoring/values.local.yaml` (ignorado por git).
- Datos inventados en repo, tests y docs: `192.0.2.0/24`, `198.51.100.0/24`, `example.com`, MACs `02:00:00:…`.
- Charts de terceros con versión exacta; imágenes de terceros por digest; actions de terceros por SHA (lo comprueba `tests/test_workflows.py`).
- Monitorización instalada y actualizada **desde el PC**; Jenkins solo despliega la app.
- Retención de Prometheus: 15 días. Presupuesto de memoria de todo `monitoring`: ~1,5 GiB de límites.
- Grafana: sin anónimo, NodePort `30300`, publicada por NPM solo en la LAN.
- Plazo de healthchecks.io: 10 min de periodo + 5 min de gracia. Watchdog repetido cada 1 min hacia healthchecks.io.
- Avisos en español; métricas y nombres de alertas en inglés (la interfaz de la app es inglesa desde la 1.1.0).
- Un commit por tarea; `pytest tests/ -v` y `ruff check src/ tests/ scripts/` en verde antes de cada commit.

## Review Focus

1. **Escaneo sin ningún host vivo**: el archivo de métricas se escribe igual, con `topology_scanner_hosts_up 0` por rango (es justo lo que hay que ver en el panel). Test en la Tarea 2.
2. **Pushgateway caído o inexistente**: el Job termina bien y deja un aviso en el log; el hueco lo detecta la alerta de métricas viejas. Test en la Tarea 3.
3. **Un rango que deja de escanearse**: el push usa `PUT` (sustituye el grupo entero), así que sus series no se quedan congeladas para siempre. Test en la Tarea 3.
4. **Sin `--snmp`**: no se escribe `topology_scanner_snmp_success` (ni 0 ni 1), para que no salte una alerta por algo que no se pidió. Test en la Tarea 1.
5. **Rango con caracteres raros** (con un solo rango se admite sintaxis de nmap): los valores de etiqueta escapan `\`, `"` y saltos de línea según el formato de texto. Test en la Tarea 1.

---

### Tarea 1: `export.metricas_prometheus`

**Files:**
- Modify: `src/topology_scanner/export.py` (al final)
- Test: `tests/test_export.py`

**Interfaces:**
- Consumes: `classifier.puertos_sensibles_abiertos(puertos: list) -> list`; el diff de `history.registrar_ejecucion` (claves `hosts_nuevos`, `hosts_caidos`, `hosts_nunca_vistos`).
- Produces:
  - `metricas_prometheus(resultados_por_rango: dict[str, dict], diffs: dict[str, dict] | None, duracion: float, snmp_ok: bool | None, ahora: float) -> str`
  - `exportar_metricas(archivo_salida: str, resultados_por_rango: dict[str, dict], diffs: dict[str, dict] | None, duracion: float, snmp_ok: bool | None, ahora: float) -> None` (escribe con `_escribir_archivo`; `ExportError` si no puede)
  - Métricas (gauges, con `# HELP` y `# TYPE`):
    - Por rango, etiqueta `range`: `topology_scanner_hosts_up`, `topology_scanner_hosts_with_open_ports`, `topology_scanner_hosts_with_sensitive_ports`, `topology_scanner_open_ports`.
    - Por rango, solo si `diffs` no es None y el diff de ese rango no es `primera_vez`: `topology_scanner_hosts_new`, `topology_scanner_hosts_never_seen`, `topology_scanner_hosts_down`.
    - Globales: `topology_scanner_scan_duration_seconds`, `topology_scanner_last_scan_timestamp_seconds` (= `ahora`), y `topology_scanner_snmp_success` (1/0) solo si `snmp_ok` no es None.

- [ ] **Step 1: Tests (rojo)**

```python
def test_metricas_por_rango():
    resultados = {
        "192.0.2.0/24": {"192.0.2.10": _con_puertos([22, 3389]), "192.0.2.11": _con_puertos([])},
        "198.51.100.0/24": {},
    }
    texto = metricas_prometheus(resultados, None, 98.5, None, 1_700_000_000)
    assert 'topology_scanner_hosts_up{range="192.0.2.0/24"} 2' in texto
    assert 'topology_scanner_hosts_up{range="198.51.100.0/24"} 0' in texto
    assert 'topology_scanner_hosts_with_open_ports{range="192.0.2.0/24"} 1' in texto
    assert 'topology_scanner_hosts_with_sensitive_ports{range="192.0.2.0/24"} 1' in texto
    assert 'topology_scanner_open_ports{range="192.0.2.0/24"} 2' in texto
    assert "topology_scanner_scan_duration_seconds 98.5" in texto
    assert "topology_scanner_last_scan_timestamp_seconds 1700000000" in texto
    assert "# TYPE topology_scanner_hosts_up gauge" in texto

def test_metricas_del_diff():          # hosts_new / never_seen / down con un diff real (no primera vez)
def test_metricas_sin_historial_no_trae_las_del_diff():   # diffs=None -> "hosts_new" not in texto
def test_metricas_primera_vez_no_trae_las_del_diff():     # primera_vez=True -> sin hosts_new para ese rango
def test_metricas_sin_snmp_no_escribe_snmp_success():     # snmp_ok=None -> "snmp_success" not in texto
def test_metricas_snmp_fallido_es_cero():                 # snmp_ok=False -> "topology_scanner_snmp_success 0"
def test_metricas_escapa_las_etiquetas():
    texto = metricas_prometheus({'a"b\\c': {}}, None, 1, None, 0)
    assert 'range="a\\"b\\\\c"' in texto
def test_metricas_cada_metrica_con_help_y_type_una_vez():  # cada "# TYPE x" aparece exactamente una vez
def test_exportar_metricas_si_no_puede_escribir_lanza_export_error(tmp_path):  # como el de exportar_csv
```

`_con_puertos(lista)` es un helper del test: `_resultado_fake()` con `puertos=[{"puerto": p, ...}]` en el formato de `scanner.parsear_host` (mirar `_resultado_fake` del mismo archivo).

- [ ] **Step 2:** `.venv/Scripts/pytest tests/test_export.py -k metricas -v` → FAIL (`ImportError`).
- [ ] **Step 3:** Implementar ambas funciones. "Sensible" = `puertos_sensibles_abiertos(host["puertos"])` no vacío. Los rangos salen ordenados para que el texto sea estable. Termina en `\n`.
- [ ] **Step 4:** La suite y ruff en verde.
- [ ] **Step 5:** Commit `feat: métricas del escaneo en formato de texto de Prometheus`.

### Tarea 2: flag `--metrics-file`

**Files:**
- Modify: `src/topology_scanner/cli.py` (parser y `main`)
- Modify: `CHANGELOG.md` (sección `[Unreleased]`, Added)
- Modify: `README.md` (tabla/lista de flags, si la hay)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `export.exportar_metricas` (Tarea 1); `rangos.repartir_por_rango`.
- Produces: `topology-scanner RANGO… --metrics-file RUTA`.

- [ ] **Step 1: Tests (rojo)**, siguiendo los de `--changes-dir` en `tests/test_cli.py` (mockean `escanear_red`, `registrar_ejecucion` y el export HTML):
  - `test_metrics_file_escribe_las_metricas`: con 1 host, el archivo existe y contiene `topology_scanner_hosts_up{range="192.0.2.0/24"} 1` y `topology_scanner_scan_duration_seconds`.
  - `test_metrics_file_sin_hosts_escribe_ceros`: `escanear_red` devuelve `{}` → el archivo existe con `topology_scanner_hosts_up{range="192.0.2.0/24"} 0` (hoy `main` sale antes: la escritura tiene que ocurrir también en ese camino).
  - `test_metrics_file_con_no_history`: funciona y no trae `hosts_new`.
  - `test_metrics_file_con_snmp_fallido`: `_obtener_topologia` devuelve None → `topology_scanner_snmp_success 0`.
  - `test_metrics_file_no_escribible_sale_con_error`: `sys.exit` con mensaje, como `--csv`.
- [ ] **Step 2:** Ver que fallan (argumento desconocido).
- [ ] **Step 3:** Implementar: argumento `--metrics-file FILE` (help en inglés: "Write scan metrics in the Prometheus text format to FILE (for a Pushgateway)"); duración con `time.monotonic()` desde antes de `escanear_red` hasta después del historial; `snmp_ok = topologia is not None` si `args.snmp`, si no `None`; `ahora = time.time()`. Se escribe después del historial (necesita los diffs) y, en el camino de "no hosts", antes del `return`.
- [ ] **Step 4:** Suite y ruff en verde. Probar a mano: `.venv/Scripts/topology-scanner --help` muestra el flag.
- [ ] **Step 5:** CHANGELOG `[Unreleased]` → Added: `--metrics-file`. Commit `feat(cli): --metrics-file para el Pushgateway`.

### Tarea 3: el Job sube las métricas (chart de la app)

**Files:**
- Create: `deploy/helm/topology-scanner/files/empujar_metricas.sh`
- Modify: `deploy/helm/topology-scanner/templates/cronjob.yaml`, `templates/_helpers.tpl` (`contenedorEscaneo`), `templates/configmap-subida.yaml` (añadir el script, ConfigMap si `aws.enabled` **o** `metricas.enabled`), `values.yaml`, `values.example.yaml`
- Test: `tests/test_helm.py`

**Interfaces:**
- Consumes: `--metrics-file` (Tarea 2).
- Produces: valores
  ```yaml
  metricas:
    enabled: false
    # Servicio del Pushgateway (Tarea 4); el pod usa ClusterFirstWithHostNet, resuelve nombres del clúster
    pushgateway: http://prometheus-pushgateway.monitoring.svc:9091
    imagen: curlimages/curl:<versión>@sha256:<digest>
  ```
  Con `metricas.enabled`: el escaneo pasa a initContainer con `--metrics-file /salida/metricas.prom` y volumen `salida`; un contenedor `metricas` ejecuta `sh /script/empujar_metricas.sh` con `PUSHGATEWAY` en el entorno. Grupo del push: `/metrics/job/topology_scanner`.

- [ ] **Step 1: Tests (rojo)** en `tests/test_helm.py` (reutilizar `_renderizar`, `_ejecutar_subida` como modelo con un `curl` falso en el PATH):
  - `test_metricas_desactivadas_por_defecto`: sin el valor, el CronJob es igual que hoy (un contenedor `escaneo`, sin `--metrics-file`).
  - `test_metricas_sin_aws`: `--set metricas.enabled=true` → initContainer `escaneo` con `--metrics-file /salida/metricas.prom`, contenedor `metricas`, volumen `salida`, sin contenedor `subida`.
  - `test_metricas_con_aws`: ambos contenedores, `subida` y `metricas`.
  - `test_contenedor_metricas_endurecido`: sin root, `readOnlyRootFilesystem`, `drop: [ALL]`, `allowPrivilegeEscalation: false`, imagen con `@sha256:`.
  - `test_empujar_usa_put_al_grupo_del_job`: ejecutando el script con `curl` falso, la llamada lleva `-X PUT`, `--data-binary @/…/metricas.prom` y termina en `/metrics/job/topology_scanner`.
  - `test_empujar_sin_pushgateway_no_tumba_el_job`: `curl` falso que falla → exit 0 y un aviso en stderr.
  - `test_empujar_sin_archivo_avisa`: sin `metricas.prom` → exit 0 y aviso (el escaneo no lo dejó).
- [ ] **Step 2:** Ver que fallan.
- [ ] **Step 3:** Implementar. El script, `set -eu`, `curl -sS --fail --max-time 30 --retry 3 -X PUT --data-binary @"$SALIDA/metricas.prom" "$PUSHGATEWAY/metrics/job/topology_scanner"`; en fallo, `echo "AVISO: …" >&2` y `exit 0`. Elegir la imagen de curl con unas semanas publicada y fijarla por digest (`docker buildx imagetools inspect` o la página de Docker Hub). Recursos del contenedor nuevo en `resources.metricas` (`requests: {cpu: 10m, memory: 16Mi}`, `limits: {cpu: 100m, memory: 64Mi}`).
- [ ] **Step 4:** Suite, ruff y `helm lint … --strict` (con y sin `--set metricas.enabled=true`) en verde.
- [ ] **Step 5:** Commit `feat(chart): el nocturno sube sus métricas al Pushgateway`.

### Tarea 4: valores de la monitorización (kube-prometheus-stack + Pushgateway)

**Files:**
- Create: `deploy/monitoring/values.yaml`, `deploy/monitoring/values.example.yaml`, `deploy/monitoring/pushgateway.values.yaml`
- Modify: `.gitignore` (`deploy/monitoring/values.local.yaml`), `.github/workflows/ci.yml` (job `helm`)
- Create: `tests/test_monitoring.py`
- Modify: `tests/test_workflows.py`

**Interfaces:**
- Produces: release `monitoring` (chart `prometheus-community/kube-prometheus-stack`, versión fijada) y release `pushgateway` (chart `prometheus-community/prometheus-pushgateway`, versión fijada, Service `prometheus-pushgateway` en `monitoring`, puerto 9091, `serviceMonitor.enabled: true`) en el namespace `monitoring`. Secret `alertas` (claves `TELEGRAM_BOT_TOKEN`, `HEALTHCHECKS_URL`) montado en Alertmanager en `/etc/alertmanager/secrets/alertas/`. Secret `grafana-admin` (`admin-user`, `admin-password`).

- [ ] **Step 1:** Elegir versiones: `helm repo add prometheus-community https://prometheus-community.github.io/helm-charts && helm search repo prometheus-community/kube-prometheus-stack --versions | head` (y lo mismo para `prometheus-pushgateway`). La última con al menos dos semanas publicada; apuntarla en la cabecera de cada values y en ci.yml.
- [ ] **Step 2: Tests (rojo)** en `tests/test_monitoring.py`, leyendo los YAML con `yaml.safe_load` (sin Helm):
  - `test_k3s_sin_componentes_que_no_expone`: `kubeControllerManager`, `kubeScheduler`, `kubeEtcd`, `kubeProxy` con `enabled: false`, y sus `defaultRules.rules.*` a `false`.
  - `test_retencion_y_limites`: `prometheus.prometheusSpec.retention == "15d"`, PVC `local-path`, y límites de memoria en Prometheus, Alertmanager y Grafana cuya suma (más operator, kube-state-metrics, node-exporter) ≤ 1,5 GiB.
  - `test_watchdog_va_a_healthchecks`: en `alertmanager.config.route.routes`, la ruta con `alertname="Watchdog"` va al receptor `healthchecks` con `repeat_interval: 1m`; ese receptor es un `webhook_configs` con `url_file: /etc/alertmanager/secrets/alertas/HEALTHCHECKS_URL` y `send_resolved: false`.
  - `test_resto_va_a_telegram`: el receptor por defecto es `telegram` con `bot_token_file: /etc/alertmanager/secrets/alertas/TELEGRAM_BOT_TOKEN`; `chat_id` no está en `values.yaml` (va en el local) y sí en `values.example.yaml` con un número inventado; `alertmanager.alertmanagerSpec.secrets == ["alertas"]`.
  - `test_avisos_sin_ruido`: la ruta raíz agrupa por `alertname` y `namespace`, `repeat_interval` ≥ `4h`, `send_resolved: true` en Telegram; `InfoInhibitor` y `Watchdog` nunca llegan a Telegram.
  - `test_grafana_sin_anonimo_y_admin_por_secret`: `grafana.admin.existingSecret == "grafana-admin"`, `auth.anonymous` desactivado, `service.type: NodePort`, `nodePort: 30300`, sidecar de dashboards activo con `label: grafana_dashboard`.
  - `test_secretos_fuera_del_repo`: ningún values contiene `api.telegram.org/bot`, `hc-ping.com/` con UUID, ni `admin-password:` con valor.
  - En `tests/test_workflows.py`: `test_la_ci_valida_los_valores_de_monitorizacion`, como el de Jenkins (`helm template ci prometheus-community/kube-prometheus-stack --version X.Y.Z … deploy/monitoring/values.yaml`).
- [ ] **Step 3:** Ver que fallan.
- [ ] **Step 4:** Escribir los values. La plantilla del mensaje de Telegram en español (título con el estado, resumen y descripción de cada alerta). Alertmanager con `route.group_by: [alertname, namespace]`, `group_wait: 30s`, `group_interval: 5m`, `repeat_interval: 4h`.
- [ ] **Step 5:** CI: en el job `helm`, añadir el repo y `helm template` de los dos charts con `values.yaml` + `values.example.yaml`. Ejecutar esos comandos en local.
- [ ] **Step 6:** Suite y ruff en verde. Commit `feat(monitoring): valores de kube-prometheus-stack y Pushgateway`.

### Tarea 5: reglas de alerta propias, con tests de promtool

**Files:**
- Create: `deploy/monitoring/topology-monitoring/` (chart propio: `Chart.yaml` versión 0.1.0, `templates/reglas.yaml` como `PrometheusRule` que incluye `files/reglas.yaml`, `files/reglas.yaml`)
- Create: `deploy/monitoring/pruebas/reglas.test.yaml` (tests de unidad de promtool)
- Modify: `.github/workflows/ci.yml` (`helm lint` del chart y promtool), `tests/test_monitoring.py`, `tests/test_workflows.py`

**Interfaces:**
- Consumes: métricas de la Tarea 1 y de kube-state-metrics.
- Produces: grupo de reglas `topology-scanner`. La etiqueta `release: monitoring` en el `PrometheusRule` (la que el operador de la Tarea 4 selecciona; comprobar `ruleSelector` en sus valores). Alertas, todas con `summary` y `description` en español:

| Alerta | Expresión (orientativa) | for | severity |
|---|---|---|---|
| `NightlyScanNotSucceeded` | `time() - kube_cronjob_status_last_successful_time{namespace="topology-scanner"} > 26*3600` | 15m | warning |
| `ScanJobFailed` | `kube_job_status_failed{namespace="topology-scanner"} > 0` | 0m | warning |
| `ScanMetricsStale` | `time() - topology_scanner_last_scan_timestamp_seconds > 26*3600` | 15m | warning |
| `PodNotHealthy` | pods de `topology-scanner`, `jenkins` o `monitoring` en `CrashLoopBackOff`/`ImagePullBackOff`, o reinicios > 3 en 1 h | 10m | warning |
| `VolumeAlmostFull` | `kubelet_volume_stats_used_bytes / kubelet_volume_stats_capacity_bytes > 0.85` | 30m | warning |

- [ ] **Step 1: Tests (rojo)** de promtool en `pruebas/reglas.test.yaml`: para cada alerta, un caso que dispara y uno que no (p. ej. último éxito hace 25 h → nada; hace 27 h → `NightlyScanNotSucceeded`; un Job con `failed=1` → `ScanJobFailed`). Y en `tests/test_monitoring.py`:
  - `test_reglas_con_resumen_y_descripcion`: cada regla del archivo tiene `labels.severity` y `annotations.summary`/`description`.
  - `test_reglas_las_carga_el_operador`: el `PrometheusRule` renderizado (`helm template`) lleva `release: monitoring`.
  - `test_cada_alerta_tiene_test_de_promtool`: cada `alert:` del archivo aparece en algún `exp_alerts` del test de promtool.
  - En `tests/test_workflows.py`: la CI ejecuta promtool sobre `deploy/monitoring/pruebas/` con `prom/prometheus@sha256:`.
- [ ] **Step 2:** Ejecutar promtool en local (en `docker-lab` o con el binario: `promtool test rules deploy/monitoring/pruebas/reglas.test.yaml`) → FAIL.
- [ ] **Step 3:** Escribir las reglas. `promtool check rules` y `promtool test rules` en verde.
- [ ] **Step 4:** CI: en el job `helm`, `helm lint deploy/monitoring/topology-monitoring --strict` y `docker run --rm -v "$PWD/deploy/monitoring:/m" --entrypoint promtool prom/prometheus:<v>@sha256:<digest> test rules /m/pruebas/reglas.test.yaml`.
- [ ] **Step 5:** Suite y ruff en verde. Commit `feat(monitoring): reglas de alerta del escáner con tests de promtool`.

### Tarea 6: panel de Grafana del escaneo

**Files:**
- Create: `deploy/monitoring/topology-monitoring/files/panel-escaneo.json`, `templates/panel.yaml` (ConfigMap con etiqueta `grafana_dashboard: "1"`)
- Modify: `tests/test_monitoring.py`

**Interfaces:**
- Consumes: métricas de la Tarea 1 (nombres exactos), datasource por defecto del stack (`uid: prometheus`).
- Produces: panel "Escaneo nocturno" con: hosts vivos por rango (serie temporal), hosts con puertos sensibles por rango, hosts nunca vistos por rango (barras), duración del escaneo, edad del último escaneo (stat, rojo > 26 h) y éxito de SNMP.

- [ ] **Step 1: Tests (rojo):**
  - `test_panel_es_json_valido_con_uid_fijo` (uid fijo para que los enlaces no cambien al reinstalar).
  - `test_panel_solo_usa_metricas_que_existen`: cada `topology_scanner_\w+` de las consultas del JSON está en la lista de métricas de `metricas_prometheus` (sacada ejecutándola con datos de ejemplo, no copiada a mano).
  - `test_panel_lo_carga_el_sidecar`: el ConfigMap renderizado tiene `grafana_dashboard: "1"`.
- [ ] **Step 2:** Ver que fallan.
- [ ] **Step 3:** Escribir el JSON del panel (esquema de Grafana del chart fijado en la Tarea 4). Se retoca en vivo en la Tarea 8 si hace falta, exportándolo de vuelta al archivo. Sin datos reales en el JSON.
- [ ] **Step 4:** Suite, ruff y `helm lint` en verde. Commit `feat(monitoring): panel de Grafana del escaneo nocturno`.

### Tarea 7: release v1.6.0

**Files:** `pyproject.toml` (1.6.0), `CHANGELOG.md` (`[Unreleased]` → `[1.6.0] - <fecha>`, con el chart 0.5.0), `deploy/helm/topology-scanner/Chart.yaml` (0.5.0 / appVersion 1.6.0), `values.yaml` (`tag: "1.6.0"`).

- [ ] **Step 1:** Cambiar las versiones; `pip install -e .`; suite, ruff y `helm lint` en verde.
- [ ] **Step 2:** Commit `release: v1.6.0` (el tag, después del merge, Tarea 8).

### Tarea 8: instalación y ensayos (con el mantenedor)

**Files:** `deploy/monitoring/values.local.yaml` (ignorado), Secret `topology-scanner-values` (valores reales de la app, en el clúster).

- [ ] **Step 1 (mantenedor):** bot con BotFather, chat ID; cuenta de healthchecks.io, check con periodo 10 min y gracia 5 min, integración de Telegram; archivo `~/.config/topology-scanner/alertas.env` (`TELEGRAM_BOT_TOKEN=…`, `HEALTHCHECKS_URL=…`, sin comillas, LF) y `grafana.env`.
- [ ] **Step 2:** `kubectl create namespace monitoring`; `kubectl -n monitoring create secret generic alertas --from-env-file=…`; ídem `grafana-admin`. Comprobar claves sin ver valores (`kubectl get secret … -o jsonpath='{.data}' | jq 'keys'`).
- [ ] **Step 3:** `helm install monitoring …`, `helm install pushgateway …`, `helm install topology-monitoring deploy/monitoring/topology-monitoring -n monitoring`. Comprobar: pods Ready, memoria real (`kubectl top`), targets de Prometheus en UP, alertas disparadas = solo `Watchdog`, healthchecks.io recibe pings.
- [ ] **Step 4:** Entrada de NPM para Grafana (Access List solo LAN); login con el Secret; el panel aparece.
- [ ] **Step 5:** Push, PR, CI verde, merge; `metricas.enabled: true` en el Secret `topology-scanner-values`; `git tag v1.6.0 origin/main && git push origin v1.6.0`; Jenkins despliega solo (helm test OK).
- [ ] **Step 6: Ensayo 1** — `kubectl -n topology-scanner create job falla-a-proposito --image=busybox -- false` → Telegram con `ScanJobFailed`; borrar el Job → "resuelto".
- [ ] **Step 7: Ensayo 2** — `kubectl -n monitoring scale … alertmanager --replicas=0` (el `Alertmanager` CR: `kubectl patch alertmanager … --type merge -p '{"spec":{"replicas":0}}'`) → aviso de healthchecks.io en Telegram en ~15 min; volver a 1 → aviso de recuperación.
- [ ] **Step 8: Ensayo 3** — `helm uninstall` de los tres releases (anotar si se lleva el PVC de Prometheus) y reinstalar desde el repo: reglas, panel y avisos igual; 0 alertas salvo `Watchdog`.
- [ ] **Step 9:** Al día siguiente, el nocturno con 1.6.0 aparece en el panel; `ScanMetricsStale` no dispara.

### Tarea 9: documentación

**Files:** `docs/devops/runbooks/06-observabilidad.md` (nuevo: instalación, Secrets, versiones, ensayos con fechas, tropiezos, casillas de "Resultado verificable" del diseño), `docs/decisiones.md` (healthchecks.io y por qué Watchdog; Pushgateway y `--metrics-file`; chart propio para reglas/panel; reglas desactivadas en k3s), `docs/devops/README.md` (fase 6 Hecha; piezas nuevas), `CLAUDE.md` (estructura `deploy/monitoring/`, comandos de helm/promtool, CI, `--metrics-file`, roadmap), `README.md` (flag nuevo).

- [ ] **Step 1:** Escribir las docs. Sin IPs, dominios ni IDs reales.
- [ ] **Step 2:** Suite y ruff en verde. Commit `docs: runbook de la fase 6 y decisiones`; PR.
