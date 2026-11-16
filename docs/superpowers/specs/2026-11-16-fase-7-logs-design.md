# Fase 7: logs, diseño

Continúa [`2026-11-11-fase-6-observabilidad-design.md`](2026-11-11-fase-6-observabilidad-design.md),
que dejaba Loki en "ideas para después". El mantenedor pidió saltarse las
preguntas; las decisiones de abajo son de Claude salvo que se diga otra cosa.

## Intención

Desde la fase 6, si el nocturno falla, llega un Telegram. Pero el aviso dice
*qué* ha fallado, no *por qué*: para eso hay que hacer `kubectl logs` a tiempo.
El CronJob solo guarda los últimos Jobs, un pod borrado se lleva sus logs y los
eventos de Kubernetes (OOMKilled, BackOff, imagen que no baja) caducan en una
hora. Por la mañana, muchas veces ya no queda nada que mirar.

Loki guarda los logs de todos los pods y los eventos del clúster durante
15 días (lo mismo que las métricas), y Grafana los enseña al lado del panel
del escaneo. Con eso, la observabilidad tiene las dos patas: métricas y avisos
(fase 6) y logs (fase 7).

Para el portfolio: responde a "te llega una alerta a las 3:00, ¿cómo
investigas?" sin depender de que el pod siga vivo.

## Objetivos

1. Loki en k3s (namespace `monitoring`), instalado con Helm desde el PC, como
   los otros tres releases de la fase 6.
2. Alloy recoge los logs de **todos** los pods y los **eventos** del clúster y
   los manda a Loki.
3. Loki como datasource del Grafana que ya existe, como código (values del
   stack), con `uid` fijo.
4. El panel "Escaneo nocturno" muestra los logs del último escaneo.
5. Igual de comprobado que la fase 6: values leídos como YAML en tests,
   `helm template` en CI, imágenes por digest, presupuesto de memoria.

## No-objetivos

- **Alertas sobre logs** (ruler de Loki). Las alertas siguen saliendo de
  Prometheus; si hace falta una sobre logs, otra fase.
- **Logs de fuera del clúster** (Proxmox, router, `journald` de la VM).
- **Alta disponibilidad o almacenamiento en S3**. Un solo nodo, un solo disco.
- **Métricas de Loki y Alloy en Prometheus** y sus paneles: más memoria y
  ruido para un homelab. Si Loki se cae, se nota al abrir Grafana; no es un
  sistema que avise.

## Anti-objetivos (fracaso aunque "funcione")

- Que Loki o Alloy dejen sin memoria al nocturno o a Jenkins.
- Que Alloy pueda leer los **Secrets** del clúster (el RBAC por defecto del
  chart lo permite).
- Que el recolector necesite root o montar el disco del nodo.
- Que acabe en el repo algo real de la red (los logs no: viven en el clúster).

## Decisiones

### Piezas y versiones

| Release | Chart | Por qué |
|---|---|---|
| `loki` | `grafana/loki` 7.5.0 (Loki 3.6.16) | Modo `SingleBinary`: un pod, disco local. El modo por defecto (`SimpleScalable`) son 3 componentes + caché + almacenamiento de objetos |
| `alloy` | `grafana/alloy` 1.15.0 (Alloy 1.21.3) | El recolector actual de Grafana; Promtail está obsoleto |

Versiones con más de dos semanas publicadas (las últimas, 7.6.0 y 1.16.0,
tenían menos de una).

### Loki

- Almacenamiento `filesystem` en un PVC `local-path` de 5 Gi; esquema `v13`
  con índice `tsdb` (lo recomendado en Loki 3). **Corregido en la
  instalación**: el primer esquema empieza en el pasado (`2024-01-01`), no el
  día de la instalación; si no, Loki rechaza los logs que los pods ya tenían y
  Alloy se atasca reintentándolos (`docs/decisiones.md`).
- Retención **15 días**, como Prometheus, borrada por el compactor
  (`retention_enabled`).
- Fuera todo lo que no hace falta con un solo binario: gateway (nginx),
  cachés (memcached), canary, test, minio, pattern ingester y el sidecar de
  reglas.
- Sin autenticación propia (`auth_enabled: false`): solo es accesible dentro
  del clúster (Service `ClusterIP`); quien mira es Grafana, que sí la tiene.
- 512 Mi de límite de memoria.

### Alloy

- **`loki.source.kubernetes`** (lee los logs por la API de Kubernetes) en vez
  de leer `/var/log/pods` del nodo: sin `hostPath` ni root, y basta un
  **Deployment de una réplica** en vez de un DaemonSet. A cambio, si Alloy
  está caído, se pierden los logs de ese rato; aceptado en un homelab de un
  nodo.
- **`loki.source.kubernetes_events`**: los eventos, con `job="eventos"`.
- Etiquetas: `namespace`, `pod`, `container`. Nada más (cada etiqueta
  multiplica los streams de Loki).
- RBAC recortado: `rules` solo con pods, `pods/log`, namespaces y eventos
  (las `clusterRules` por defecto son lectura de nodos; vaciarlas rompe la
  plantilla del chart).
- `enableReporting: false` (telemetría de uso a Grafana Labs) y sin CRDs.
- 256 Mi de límite de memoria.
- La configuración se validó con `alloy validate` de la misma imagen (que
  aplica el nivel `generally-available`).

### Grafana

- Datasource `Loki` en `grafana.additionalDataSources` del stack, `uid: loki`,
  hacia `http://loki.monitoring.svc:3100`.
- Panel de logs en "Escaneo nocturno": `{namespace="topology-scanner",
  container=~"escaneo|metricas|subida"}` (por contenedor y no por nombre de
  pod, para incluir los Jobs lanzados a mano; corregido en la prueba real),
  con los eventos del namespace al lado.

### Verificación (lo que demuestra que está hecha)

1. Los dos releases `Running`; en Grafana → Explore, logs de pods de varios
   namespaces y eventos.
2. Un Job lanzado a mano desde el CronJob: sus logs aparecen en el panel.
3. Borrar ese Job: los logs **siguen** en Loki (lo que `kubectl logs` ya no da).
4. El nocturno siguiente aparece en el panel sin intervención.
5. La memoria de los dos pods en reposo, dentro de sus límites.

## Lo que hace el mantenedor a mano

- `helm upgrade --install` de `loki`, `alloy` y el del stack (que añade el
  datasource), desde el PC.
- La primera búsqueda en Explore (LogQL) y la prueba de borrar el Job.

## Lo que queda para quien construya

Nombres de archivos, textos del runbook y la forma exacta del panel, siguiendo
el patrón de `deploy/monitoring/` y `tests/test_monitoring.py`.

## Ideas para después

- Alertas sobre logs (`Traceback` en el escaneo) con el ruler de Loki.
- Logs de Proxmox y del router por syslog hacia Alloy.
