# Fase 7 — Logs

**Objetivo:** que los logs del escaneo nocturno (y de cualquier pod) y los
eventos de Kubernetes sigan ahí cuando se va a mirar por qué algo ha fallado,
aunque el Job ya no exista. Desde la fase 6, un fallo llega por Telegram; con
esta, se puede investigar en Grafana sin `kubectl logs`. Diseño:
[`docs/superpowers/specs/2026-11-16-fase-7-logs-design.md`](../../superpowers/specs/2026-11-16-fase-7-logs-design.md).

**Resultado verificable:**

- [x] `loki` y `alloy` instalados desde el repo, `Running`, sin errores en sus
      logs; logs de los 5 namespaces y eventos en Loki (2026-11-16).
- [x] Datasource `Loki` en Grafana (`uid: loki`), recargado en caliente por el
      sidecar, sin reiniciar Grafana (2026-11-16).
- [x] Un Job lanzado a mano desde el CronJob: sus tres contenedores en Loki;
      **borrado el Job, los logs siguen** (249 líneas) (2026-11-16).
- [x] Memoria en reposo dentro de los límites: Loki ~100 MiB (512), Alloy
      ~55 MiB (256), config-reloader ~7 MiB (32) (2026-11-16).
- [ ] El nocturno siguiente aparece en el panel sin intervención.

## Piezas

```
deploy/monitoring/
├── loki.values.yaml              # grafana/loki 7.5.0: un solo binario, disco local, 15 días
├── alloy.values.yaml             # grafana/alloy 1.15.0: Deployment, logs por la API + eventos
├── values.yaml                   # (stack) grafana.additionalDataSources: Loki, uid fijo
└── topology-monitoring/files/panel-escaneo.json   # + paneles "Logs del escaneo" y "Eventos…"
tests/test_monitoring.py          # values leídos como YAML: modo, retención, RBAC, digests, panel
```

Dos releases más en el namespace `monitoring`, instalados **desde el PC**, como
los de la fase 6:

| Release | Chart | Qué es |
|---|---|---|
| `loki` | `grafana/loki` 7.5.0 (Loki 3.6.16) | Guarda los logs; StatefulSet `loki-0` con PVC de 5 GiB |
| `alloy` | `grafana/alloy` 1.15.0 (Alloy 1.21.3) | Recoge logs de todos los pods y eventos, y los manda a Loki |

El PVC de Loki (`storage-loki-0`) es de un StatefulSet: **sobrevive a
`helm uninstall`**, como el de Prometheus.

## Cómo funciona

```
pods (todos los namespaces) ─┐
                             ├─► API de Kubernetes ─► Alloy ─► Loki (:3100) ◄─ Grafana (datasource "Loki")
eventos del clúster ─────────┘    (pods/log, events)   loki.write    15 días        panel "Escaneo nocturno"
```

- **Alloy** (`loki.source.kubernetes`) pide los logs a la API, no lee el disco
  del nodo: sin `hostPath` ni root. Etiquetas: `namespace`, `pod`, `container`.
  Los eventos llevan `job="eventos"` y el `namespace` del objeto.
- **RBAC de Alloy**: solo pods, `pods/log`, namespaces y eventos. **No puede
  leer Secrets** (el chart lo permitía por defecto).
- **Loki** solo es accesible dentro del clúster (sin autenticación propia);
  quien mira es Grafana, con su usuario.
- **Panel "Escaneo nocturno"**, al final: "Logs del escaneo"
  (`{namespace="topology-scanner", container=~"escaneo|metricas|subida"}`,
  también los Jobs lanzados a mano) y "Eventos de Kubernetes del escaneo"
  (`{job="eventos", namespace="topology-scanner"}`).

## Requisitos en el PC

Los de la fase 6 (`kubectl`, `helm`, kubeconfig del homelab) y el repo de Helm
de Grafana:

```bash
export KUBECONFIG=~/.kube/config-homelab
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
```

## 1. Instalar

```bash
helm upgrade --install loki grafana/loki --version 7.5.0 -n monitoring \
  -f deploy/monitoring/loki.values.yaml --wait --timeout 5m
helm upgrade --install alloy grafana/alloy --version 1.15.0 -n monitoring \
  -f deploy/monitoring/alloy.values.yaml --wait
# El datasource (y el panel) son de los releases de la fase 6
helm upgrade --install monitoring prometheus-community/kube-prometheus-stack \
  --version 92.14.1 -n monitoring -f deploy/monitoring/values.yaml \
  -f deploy/monitoring/values.local.yaml --wait --timeout 10m
helm upgrade --install topology-monitoring deploy/monitoring/topology-monitoring -n monitoring
```

En ese orden: Loki antes de que Alloy le mande nada, y el datasource antes que
el panel que lo usa. El sidecar de Grafana recarga el datasource en caliente.

**Comprobaciones** (por el proxy de la API, sin port-forward):

```bash
L=/api/v1/namespaces/monitoring/services/loki:3100/proxy/loki/api/v1
kubectl get pods -n monitoring -l 'app.kubernetes.io/name in (loki,alloy)'   # Running
kubectl get --raw /api/v1/namespaces/monitoring/services/loki:3100/proxy/ready  # ready
kubectl get --raw "$L/label/namespace/values"     # todos los namespaces
kubectl get --raw "$L/label/job/values"           # eventos y loki.source.kubernetes.pods
kubectl logs -n monitoring deploy/alloy -c alloy | grep -E 'level=(error|warn)'   # nada (o "tailer stopped" pasajeros)
```

**Lo que se ve justo después de instalar** (no son fallos):

- Alloy manda de golpe lo que los pods tenían (hasta 7 días). En el log de
  Loki salen `timestamp too old` (más de 7 días, se descartan a propósito),
  algún `ingestion rate limit exceeded` (Alloy reintenta) y, si se reinicia
  Alloy, `entry too far behind` (líneas antiguas de un stream que ya tiene
  otras más nuevas).
- **Los logs de más de 3 horas tardan en salir en las consultas**: Loki busca lo
  reciente en la memoria del ingester y lo anterior en disco, donde llega al
  volcar los chunks (~30 min sin actividad). Para verlo ya:
  `kubectl port-forward -n monitoring svc/loki 3100:3100` y
  `curl -X POST localhost:3100/flush`. En el día a día los logs llegan al
  momento y no pasa.

## 2. Comprobar que guarda lo que `kubectl` pierde

```bash
kubectl create job -n topology-scanner --from=cronjob/topology-scanner-escaneo prueba-loki
kubectl wait -n topology-scanner --for=condition=complete job/prueba-loki --timeout=5m
kubectl delete job -n topology-scanner prueba-loki
```

En Grafana → "Escaneo nocturno" → "Logs del escaneo", o en Explore con
`{namespace="topology-scanner", pod=~"prueba-loki.*"}`: las líneas siguen.
Un escaneo de verdad: usa la red real, igual que el nocturno.

## 3. Uso diario

- **Investigar un aviso de Telegram**: Explore → datasource Loki, ajustar el
  rango a la hora del aviso. Consultas útiles:
  - `{namespace="topology-scanner", container="escaneo"} |= "ERROR"`
  - `{job="eventos", namespace="topology-scanner"} |~ "OOMKilled|BackOff|Failed"`
  - `{namespace="jenkins"}` para un despliegue que falló.
- **Subir de versión**: `--version` en el comando, en `ci.yml` (un test exige
  que coincidan con la cabecera de los values) y el digest de la imagen nueva
  (otro test falla si falta). Los digests se sacan del registro, por ejemplo
  con `docker buildx imagetools inspect grafana/loki:X.Y.Z`.
- **Cambiar la configuración de Alloy**: validarla antes con la misma imagen,
  en un pod efímero:
  `kubectl run alloy-validar --rm -i --restart=Never --image=docker.io/grafana/alloy@sha256:… --command -- sh -c 'cat > /tmp/c.alloy && alloy validate /tmp/c.alloy' < config.alloy`.
  El config-reloader la aplica sin reiniciar el pod.
- **Cambiar el esquema de Loki**: añadir **otra** entrada a `schemaConfig` con
  fecha futura; nunca editar la primera (Loki dejaría de encontrar lo guardado).

## Riesgos y limitaciones conocidas

- **Si Alloy está caído, se pierden los logs de ese rato** (lee por la API, sin
  posiciones en disco). Al volver, relee lo que los pods sigan teniendo.
- **Un reinicio de Alloy reenvía todo** lo que los pods tienen (hasta 7 días):
  Loki descarta lo repetido, pero salen los avisos del apartado 1.
- **Sin alertas sobre Loki ni Alloy**: si se caen, se nota al abrir Grafana.
  Las alertas siguen saliendo de Prometheus (fase 6).
- **Los logs pueden contener datos de la red** (IPs, hostnames del escaneo):
  viven en el clúster, accesibles solo por Grafana (LAN, con usuario). Nada de
  esto va al repo.
- **Disco**: 5 GiB para 15 días. Si se llena, Loki deja de aceptar escrituras;
  `kubectl exec` no sirve (imagen sin shell): mirar el uso del PVC en el panel
  de nodo de Grafana.
