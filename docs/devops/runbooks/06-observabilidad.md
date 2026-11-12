# Fase 6 — Observabilidad

**Objetivo:** enterarse **por Telegram** cuando algo del homelab se rompe, sin
mirar nada: el nocturno que falla o no corre, un pod en bucle, un disco que se
llena. Y, sobre todo, enterarse también cuando **lo que se rompe es la propia
monitorización**: un vigilante externo (healthchecks.io) espera una señal de
vida cada minuto y avisa si deja de llegar. Sin eso, una monitorización caída
se parece a "todo va bien". Diseño:
[`docs/superpowers/specs/2026-11-11-fase-6-observabilidad-design.md`](../../superpowers/specs/2026-11-11-fase-6-observabilidad-design.md).

**Resultado verificable:**

- [x] Monitorización instalada desde el repo; en reposo, solo `Watchdog` (y
      `InfoInhibitor`, que existe para silenciar) disparadas (2026-11-11).
- [x] Ensayo 1, un Job que falla a propósito en `topology-scanner`: Telegram con
      `ScanJobFailed` al minuto; al borrarlo, el "resuelto" a los 4 min (2026-11-11).
- [x] Ensayo 2, Alertmanager a 0 réplicas: aviso de healthchecks.io por
      Telegram pasado el plazo; al volver a 1, aviso de recuperación (2026-11-11).
- [x] Ensayo 3, `helm uninstall` de los tres releases y reinstalar desde el repo:
      todo `Running` en 1 min, reglas y panel de vuelta en 2, 14/14 targets,
      ninguna alerta `warning`/`critical` (2026-11-12).
- [x] v1.6.0 desplegada por Jenkins con `metricas.enabled`; un escaneo lanzado a
      mano llega al Pushgateway, a Prometheus y al panel (2026-11-12).
- [ ] El nocturno siguiente aparece en el panel sin intervención.

## Piezas

```
deploy/monitoring/
├── values.yaml                   # kube-prometheus-stack 92.14.1: k3s, memoria, rutas de Alertmanager, Grafana
├── values.example.yaml           # → values.local.yaml (ignorado): root_url de Grafana con el dominio real
├── pushgateway.values.yaml       # prometheus-pushgateway 3.10.0 (release aparte)
├── topology-monitoring/          # chart propio: reglas del escáner (PrometheusRule) y panel (ConfigMap)
│   ├── files/reglas.yaml
│   └── files/panel-escaneo.json
└── pruebas/reglas.test.yaml      # tests de unidad de las reglas con promtool
deploy/helm/topology-scanner/files/empujar_metricas.sh   # contenedor metricas del Job nocturno
src/topology_scanner/export.py    # metricas_prometheus(); flag --metrics-file en cli.py
tests/test_monitoring.py          # los values leídos como YAML: k3s, rutas, secretos, digests, panel
```

Tres releases de Helm en el namespace `monitoring`, instalados **desde el PC**
(Jenkins solo despliega la app):

| Release | Chart | Qué es |
|---|---|---|
| `monitoring` | `prometheus-community/kube-prometheus-stack` 92.14.1 | Prometheus, Alertmanager, Grafana, operator, kube-state-metrics, node-exporter |
| `pushgateway` | `prometheus-community/prometheus-pushgateway` 3.10.0 | Recibe las métricas del Job nocturno, que vive 2 min |
| `topology-monitoring` | `deploy/monitoring/topology-monitoring` | Reglas propias y panel "Escaneo nocturno" |

Objetos que se crean **a mano** y sobreviven a `helm uninstall`:

| Objeto | Namespace | Qué lleva |
|---|---|---|
| Secret `alertas` | `monitoring` | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `HEALTHCHECKS_URL` |
| Secret `grafana-admin` | `monitoring` | `admin-user`, `admin-password` |
| PVC de Prometheus | `monitoring` | 15 días de métricas (es de un StatefulSet: Helm no lo borra) |

## Cómo funciona

```
Job nocturno ─ escaneo (--metrics-file) ─► metricas (curl PUT) ─► Pushgateway
                                                                     │
kube-state-metrics, node-exporter, kubelet ──────────► Prometheus ◄──┘
                                                         │ reglas (las del chart + topology-monitoring)
                                                         ▼
                                                    Alertmanager
                              ┌──────────────────────────┼─────────────────────┐
                    Watchdog, cada minuto          resto de alertas      InfoInhibitor
                              ▼                          ▼                     ▼
                  healthchecks.io (webhook)        Telegram (bot)            null
                              │ si deja de llegar 10 + 5 min
                              ▼
                     Telegram (integración de healthchecks.io)
```

- **Reglas propias** (`files/reglas.yaml`, todas `warning`):
  `NightlyScanNotSucceeded` (sin éxito del CronJob en 26 h: falló o no corrió),
  `ScanJobFailed` (un Job de `topology-scanner` fallido en las últimas 26 h),
  `ScanMetricsStale` (el último escaneo que llegó al Pushgateway tiene más de
  26 h) y `ScanMetricsMissing` (no hay métricas del escáner en 26 h).
- **Reglas del chart**: las de nodo y Kubernetes, salvo las que en k3s o con un
  nodo serían ruido permanente (ver `values.yaml` y `docs/decisiones.md`).
- **Telegram**: un mensaje por `alertname` y namespace, recordatorio cada 4 h
  mientras siga, y "Resuelto" al terminar. Si salta `NightlyScanNotSucceeded`,
  se inhiben `ScanMetricsStale`/`Missing` (mismo problema).

## Requisitos en el PC

`kubectl` y `helm` con el kubeconfig del homelab (`03-kubernetes.md`), y el repo
de los charts:

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update prometheus-community
```

## 1. Antes de instalar

```bash
kubectl top node     # presupuesto de la monitorización: ~1,8 GiB de límites en total
```

El 2026-11-12, con todo instalado, el nodo usaba 4,1 de 8 GiB. En reposo:
Grafana ~430 MiB (con sus dos sidecars), Prometheus ~390 MiB, el resto por
debajo de 30 MiB cada uno.

## 2. Telegram, healthchecks.io y Secrets (a mano)

**Bot de Telegram.** Con `@BotFather`, `/newbot` → token. Mandar un mensaje
al bot y sacar el chat ID de `https://api.telegram.org/bot<token>/getUpdates`
(en el navegador, no en un chat ni en un log).

**healthchecks.io.** Cuenta gratuita, un check con **periodo 10 min y gracia
5 min** (un reinicio normal de la VM o del stack no avisa) y su integración de
Telegram. La URL de ping es un secreto: quien la tenga puede "dar señales de
vida" en nombre del clúster.

**Archivos** en `~/.config/topology-scanner/` (mismo patrón que SNMP y AWS),
`KEY=valor` sin comillas:

```bash
umask 077
# alertas.env: TELEGRAM_BOT_TOKEN=…, TELEGRAM_CHAT_ID=…, HEALTHCHECKS_URL=…
# grafana.env: admin-user=…, admin-password=…   (la contraseña: openssl rand -base64 24)
sed -i 's/\r$//' ~/.config/topology-scanner/alertas.env ~/.config/topology-scanner/grafana.env
```

El `sed` **no es opcional**: un editor de Windows deja `\r\n` y el `\r` acaba
dentro del valor del Secret (el token deja de valer y la URL de ping también,
sin un error claro). Pasó en la instalación real.

```bash
kubectl create namespace monitoring
kubectl -n monitoring create secret generic alertas \
  --from-env-file="$HOME/.config/topology-scanner/alertas.env"
kubectl -n monitoring create secret generic grafana-admin \
  --from-env-file="$HOME/.config/topology-scanner/grafana.env"
# Claves y longitudes, sin ver los valores
kubectl -n monitoring get secret alertas \
  -o go-template='{{range $k, $v := .data}}{{$k}} {{len ($v | base64decode)}}{{"\n"}}{{end}}'
```

Alertmanager lee los tres valores de archivos (`*_file`) montados desde el
Secret: ni el token ni el chat ID pasan por los values, que son públicos.

## 3. Instalar

```bash
cp deploy/monitoring/values.example.yaml deploy/monitoring/values.local.yaml   # root_url de Grafana

helm upgrade --install monitoring prometheus-community/kube-prometheus-stack \
  --version 92.14.1 -n monitoring -f deploy/monitoring/values.yaml \
  -f deploy/monitoring/values.local.yaml --wait --timeout 10m
helm upgrade --install pushgateway prometheus-community/prometheus-pushgateway \
  --version 3.10.0 -n monitoring -f deploy/monitoring/pushgateway.values.yaml --wait
helm upgrade --install topology-monitoring deploy/monitoring/topology-monitoring -n monitoring
```

En ese orden: `topology-monitoring` crea un `PrometheusRule`, cuya CRD instala
el stack. Cambiar values: el mismo comando.

**Comprobaciones** (por el proxy de la API, sin port-forward):

```bash
P=/api/v1/namespaces/monitoring/services/monitoring-kube-prometheus-prometheus:9090/proxy/api/v1
kubectl get pods -n monitoring                         # 7 pods Running
kubectl get --raw "$P/targets" | jq '[.data.activeTargets[].health] | group_by(.) | map({(.[0]): length}) | add'   # todos up
kubectl get --raw "$P/rules"   | jq '[.data.groups[].rules[].name | select(test("^(Nightly|Scan)"))]'          # las 4 propias
kubectl get --raw "$P/alerts"  | jq '.data.alerts[] | [.labels.alertname, .labels.severity, .state]'
```

Las reglas propias tardan **1-2 min** en aparecer: el operator las añade con una
recarga, después del arranque. En healthchecks.io el check tiene que pasar a
"up" en un par de minutos.

## 4. NPM

Proxy Host `grafana.<dominio>` hacia `http://<IP del nodo>:30300`, certificado
SSL y la **Access List solo LAN** (igual que la web y Jenkins). El mismo nombre
va en `root_url` de `values.local.yaml`: con él salen bien los enlaces. Entrar
con el usuario del Secret `grafana-admin`; el panel está en Dashboards →
"Escaneo nocturno" (uid fijo `topology-scanner-escaneo`).

## 5. Activar las métricas del escáner

Con la v1.6.0 o posterior desplegada, añadir a los values reales y actualizar
el Secret (proceso de `05-jenkins.md`, "Cambiar los values"):

```yaml
# deploy/helm/values.local.yaml
metricas:
  enabled: true
```

```bash
kubectl -n topology-scanner create secret generic topology-scanner-values \
  --from-file=values.yaml=deploy/helm/values.local.yaml --dry-run=client -o yaml | kubectl apply -f -
```

Y lanzar `desplegar` en Jenkins con `VERSION` vacía. El CronJob pasa a tener
`escaneo` (init) + `metricas` + `subida`. Para verlo sin esperar a las 3:00:

```bash
kubectl -n topology-scanner create job --from=cronjob/topology-scanner-escaneo escaneo-manual-$(date +%H%M)
kubectl -n topology-scanner logs job/escaneo-manual-<HHMM> -c metricas   # "Métricas subidas a …"
```

Ojo: es un escaneo real, como el nocturno (historial, S3 y email si hay cambios).

## 6. Ensayos

**Ensayo 1, Job que falla** (2026-11-11). Telegram al minuto; "resuelto" al
borrarlo:

```bash
kubectl -n topology-scanner create job falla-a-proposito --image=busybox -- false
# … llega 🔥 ScanJobFailed
kubectl -n topology-scanner delete job falla-a-proposito
```

**Ensayo 2, monitorización caída** (2026-11-11). Alertmanager a 0 réplicas: el
Watchdog deja de llegar a healthchecks.io, que avisa pasados periodo + gracia.
Hay que tocar el recurso `Alertmanager` (el operator deshace un `scale` del
StatefulSet):

```bash
kubectl -n monitoring patch alertmanager monitoring-kube-prometheus-alertmanager \
  --type merge -p '{"spec":{"replicas":0}}'
# … ~15 min: aviso "down" de healthchecks.io
kubectl -n monitoring patch alertmanager monitoring-kube-prometheus-alertmanager \
  --type merge -p '{"spec":{"replicas":1}}'
# … al primer ping: aviso "up"
```

**Ensayo 3, reconstrucción** (2026-11-12, de 12:04:55 a 12:05:57). Desinstalar
en orden inverso y volver a instalar con los comandos del paso 3:

```bash
helm uninstall topology-monitoring -n monitoring
helm uninstall pushgateway -n monitoring
helm uninstall monitoring -n monitoring --wait
kubectl get pvc,secret -n monitoring    # el PVC de Prometheus, alertas y grafana-admin siguen
```

Resultado: reglas, panel y avisos igual; el histórico de Prometheus también,
porque el PVC no se borra. Las CRD del operator tampoco (Helm no borra CRDs).

## 7. Uso diario

- **Subir de versión el stack**: cambiar `--version` en el comando, en `ci.yml`
  y en las cabeceras de los values; actualizar los digests de las imágenes
  (`tests/test_monitoring.py` falla si alguna queda sin digest). **Helm no
  actualiza las CRDs** en un `upgrade`: aplicar antes las del chart nuevo,
  como indiquen sus notas de actualización.
- **Reglas nuevas**: en `topology-monitoring/files/reglas.yaml`, con su caso que
  dispara y su caso que no en `pruebas/reglas.test.yaml` (un test lo exige);
  `helm upgrade --install topology-monitoring …`.
- **Panel**: editar en Grafana, exportar el JSON a `files/panel-escaneo.json`
  (uid fijo, datasource `prometheus`, sin datos reales) y `helm upgrade`.
- **Probar la plantilla de Telegram** sin mandar nada, con la misma versión de
  Alertmanager (en un pod efímero, por ejemplo):
  `amtool template render --template.glob=telegram.tmpl --template.data=datos.json --template.text='{{ template "telegram.mensaje" . }}'`.

## Riesgos y limitaciones conocidas

- **Un solo nodo**: si la VM cae, cae todo; por eso el vigilante está fuera.
  Cortes de luz: no son objetivo, avisa healthchecks.io como de cualquier caída.
- **Las alertas de reglas propias empiezan a contar de cero al reinstalar**.
  Prometheus recupera al arrancar cuánto llevaba pendiente cada alerta
  (`ALERTS_FOR_STATE`), pero solo de las reglas que ya tiene cargadas; las de
  `topology-monitoring` llegan después, con la recarga del operator. En el
  ensayo 3, `ScanMetricsMissing` (que espera 26 h) volvió a empezar.
- **`CPUThrottlingHigh` de nivel `info`** (node-exporter, el sidecar de Grafana,
  agentes de Jenkins): límites de CPU ajustados. Las silencia `InfoInhibitor` y
  van a `null`; se ven en Prometheus, no llegan a Telegram.
- **Pushgateway sin disco**: si se reinicia, pierde las métricas hasta el
  siguiente nocturno (`ScanMetricsMissing` lo cubre si pasan 26 h).
- **Grafana sin PVC**: lo que se edite a mano en la interfaz se pierde al
  reiniciar; lo que vale va al repo.
- **OOM en la instalación real**: Grafana con 256 MiB moría en el primer
  arranque (migraciones de la base) y sus sidecars con 64 MiB también. Ahora
  512 y 128 MiB. Grafana ronda los 430 MiB con sidecars: si crece, mirar aquí.
