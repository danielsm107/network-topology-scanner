# Fase 3 — Despliegue en Kubernetes (diseño)

Concreta la fila "3 | Despliegue en Kubernetes" del diseño general
([`2026-10-22-fase-devops-design.md`](2026-10-22-fase-devops-design.md)), sobre
el k3s de la fase 2 (VM 210, un nodo, en la red B del homelab).

## Para qué

Hasta ahora el escáner se usa a mano desde el PC. Con esta fase vive en el
k3s de casa:

- **Escaneo nocturno automático** de las dos redes de casa. Cada noche queda
  en el historial y se ve qué ha cambiado (hosts nuevos o caídos, puertos
  sensibles que aparecen).
- **Una web en la LAN** con dos usos: **elegir de una lista** cualquier escaneo
  anterior (el nocturno u otro) y verlo completo, y **lanzar escaneos a mano**
  como hoy, pero solo contra las redes de casa.

Éxito: a la mañana siguiente, el mantenedor abre `scanner.<su dominio>`, elige
el nocturno de las 3:00 en la lista y ve inventario, cambios y el árbol SNMP
de las dos redes sin haber hecho nada. Y si intenta escanear una red que no es
suya, la web lo rechaza.

## Objetivos

1. Cambios en la app para que tenga sentido desplegarla:
   - **Rangos permitidos** en la web (lo pedía ya el diseño general).
   - **El historial guarda ejecuciones completas** (todos sus rangos y la
     topología SNMP), y la web las lista y las reabre.
2. **Release v1.3.0** con esos cambios (PyPI + GHCR), porque el clúster usa la
   imagen publicada.
3. **Chart de Helm** en `deploy/helm/topology-scanner/`: CronJob nocturno,
   web, volumen del historial y la configuración por `values`.
4. Instalación real en el k3s, la web detrás del Nginx Proxy Manager de casa,
   y runbook `docs/devops/runbooks/03-kubernetes.md`.

## Fuera de alcance (y en qué fase va)

- Avisos de hallazgos por email (fase 4, SNS) y de salud por Telegram (fase 6).
  En esta fase los cambios solo se ven en la web.
- Copia del historial a S3 (fase 4).
- Prometheus, Grafana y métricas del escaneo (fase 6). No hace falta preparar
  nada aquí: el historial ya guarda lo que esas métricas necesitarán.
- Despliegue automático al sacar un tag (fase 5, Jenkins). Aquí `helm install`
  / `helm upgrade` los lanza el mantenedor desde el PC.
- Login en la web. La protección es la lista de rangos permitidos.

## Anti-objetivos (fracaso aunque funcione)

- Que la web del clúster pueda escanear algo fuera de las redes de casa
  (aviso legal del proyecto).
- Credenciales SNMP, IPs o nombres reales de la red en git. Todo va en un
  `values` local no versionado y en Secrets creados a mano.
- Que la web quede accesible desde Internet. El NPM de casa no está publicado
  fuera y así sigue.
- Que el escáner corra como root o `privileged` en el clúster.
- Romper el uso local: sin la configuración nueva, el CLI y la web se
  comportan como hoy.

## Decidido con el mantenedor

- **Redes**: las dos de casa. La red B (donde está el nodo) se escanea con MAC
  directa. La red A (la del router principal) se completa con **SNMP contra el
  router principal** (MikroTik hAP), que da MACs y el árbol.
- **Nocturno a las 3:00 (hora de Madrid), escaneo completo con detección de SO**
  (`--os-detection`, sin `--fast`).
- **La web lanza escaneos y consulta los anteriores**, eligiéndolos de una
  **lista**, no abriendo directamente el último.
- **Acceso por el Nginx Proxy Manager** (LXC) que ya tiene, solo dentro de casa.
- **SNMPv3** (SHA + AES, usuario de solo lectura que ya existe en el hAP), no
  v2c. Motivo: el nodo llega al hAP a través del NAT del UDM, así que el hAP ve
  a toda la red B con la misma IP. Con v2c el filtro por IP dejaría pasar a
  toda esa red y solo protegería la community, que además viaja en claro.

## Decisiones de diseño (propuestas por Claude; el mantenedor puede cambiarlas)

### App

**Rangos permitidos (web).**
- Variable de entorno `TOPOLOGY_ALLOWED_RANGES`: CIDRs separados por espacios
  (en inglés, como las `TOPOLOGY_SNMP_*` existentes).
- Sin la variable, todo como hoy. Con ella:
  - cada rango tiene que ser IP o CIDR (nada de sintaxis de nmap como
    `192.0.2.1-5`, que no se puede comprobar de forma fiable) y estar
    **contenido** en uno de los permitidos (`ipaddress.subnet_of`);
  - **las IPs de SNMP también** tienen que estar dentro de un rango permitido,
    para que la web no sirva para consultar equipos de fuera.
- Error claro en el formulario ("this range is outside the allowed ranges:
  ..."), antes de lanzar nmap. Va en `rangos.py` (validación pura, sin
  Streamlit); `webapp.py` solo la llama. Tests en `test_rangos.py` y un test de
  AppTest con el fixture `sin_escaneos_reales`.
- El CLI no se limita: quien lo ejecuta ya tiene la máquina.

**Ejecuciones en el historial.** Hoy cada rango se guarda como un escaneo
suelto y sin topología. Cambios en `history.py`:
- Tabla nueva `ejecuciones` (id, fecha, origen `cli`/`web`, topología SNMP en
  JSON o NULL) y columna `escaneos.ejecucion_id` (NULL en los antiguos).
- **Migración en sitio** al abrir la base (`ALTER TABLE` si falta la columna):
  el `historial.db` de quien ya usa la herramienta sigue valiendo.
- Funciones nuevas: listar ejecuciones (fecha, origen, rangos, nº de hosts,
  nº de alertas) y cargar una (resultados con el formato de
  `scanner.parsear_host`, topología, y diff contra la ejecución anterior de
  cada rango, combinado con `combinar_diffs`).
- `alertas` se recalcula con `puertos_sensibles_abiertos` al cargar, como hace
  ya `listar_escaneos_recientes`: no se guarda dos veces.
- Los escaneos antiguos (sin ejecución) salen en la lista uno por uno, como
  ejecuciones de un solo rango sin topología.
- La purga (`mantener_ultimos`, 50 por rango) sigue igual: con un nocturno al
  día, ~50 días de historia.

**Web: lista de escaneos.** El panel "historial reciente" del sidebar (hoy
solo informativo) pasa a ser una lista elegible de ejecuciones. Al elegir una,
se muestra con el mismo `_mostrar_resultado` que un escaneo recién hecho
(KPIs, cambios, inventario, topología), marcada con su fecha y origen. Los
escaneos lanzados desde la web también se guardan como ejecución.

**Base de datos compartida.** CronJob y web escriben en el mismo
`historial.db`. SQLite lo aguanta con un `timeout` de conexión de unos
segundos. La ruta de la web se configura por variable de entorno
(`TOPOLOGY_HISTORY_DB`, por defecto `historial.db` como hoy); el CLI ya tiene
`--history-db`.

### Clúster

**Chart de Helm** (`deploy/helm/topology-scanner/`), un solo release en el
namespace `topology-scanner`:

| Recurso | Detalle |
|---|---|
| `CronJob` escaneo | `schedule: "0 3 * * *"`, `timeZone: Europe/Madrid` (sin ella k3s usa UTC), `concurrencyPolicy: Forbid`, sin reintentos automáticos (`backoffLimit: 0`; un escaneo fallido se ve, no se repite a ciegas), `activeDeadlineSeconds` generoso (el `-O` alarga mucho), historial de 3 Jobs buenos y 3 fallidos |
| `Deployment` web | 1 réplica, estrategia `Recreate`: con `hostNetwork`, en una actualización `RollingUpdate` la web nueva y la vieja pelearían por el mismo puerto del nodo y la nueva no arrancaría nunca |
| `PersistentVolumeClaim` | `local-path` (el de k3s), `ReadWriteOnce`, 1 GiB; lo montan los dos en `/data` (RWO es por nodo, y solo hay uno) |
| `Secret` SNMP | **no lo crea el chart**: se crea a mano (`kubectl create secret`) y el chart solo lo referencia por nombre |

Los dos pods, con la misma imagen (`ghcr.io/danielsm107/topology-scanner`,
**tag fijo**, nunca `latest`):
- `hostNetwork: true` + `dnsPolicy: ClusterFirstWithHostNet`: en la red B con
  MAC directa, como en la prueba L2 de la fase 1.
- `securityContext`: `runAsNonRoot`, UID/GID 10001, `capabilities: drop [ALL],
  add [NET_RAW, NET_ADMIN]`. Sin `privileged` ni `allowPrivilegeEscalation:
  false`, que anula las capacidades de archivo de nmap (fase 1).
  `fsGroup: 10001` para que el volumen sea escribible.
- Variables `TOPOLOGY_SNMP_USER/_AUTH_KEY/_PRIV_KEY` desde el Secret.
- `requests`/`limits` de CPU y memoria modestos (nodo de 4 vCPU / 8 GiB).

**El CronJob** ejecuta el CLI con los rangos y la IP SNMP de los `values`,
`--os-detection`, `--history-db /data/historial.db` y las salidas HTML/CSV en
`/data` (se sobrescriben cada noche).

**Exposición de la web.** Con `hostNetwork`, Streamlit escucha directamente en
el nodo, en el puerto 8501 (configurable en `values`). **Ni Service ni
Ingress**: NPM hace de proxy a `<IP del nodo>:8501`, y meter Traefik en medio
serían dos proxies encadenados sin ganar nada. Esto cambia lo que proponía el
diseño general (Ingress de Traefik).
- En NPM hay que activar **"Websockets Support"**: Streamlit funciona por
  websockets y, sin eso, la página carga pero se queda colgada.
- **Access List de NPM** (IP o usuario/contraseña): opcional, documentada en el
  runbook. NPM no está publicado fuera y los rangos permitidos ya limitan qué
  se puede escanear.
- El puerto 8501 también queda accesible directamente desde la LAN. Se acepta:
  todo es dentro de casa.

**Configuración.** `values.yaml` con valores por defecto inventados
(`192.0.2.0/24`...), `values.example.yaml` comentado, y el real en
`deploy/helm/values.local.yaml`, ignorado por git. Ahí van los rangos, la IP
SNMP y los rangos permitidos (por defecto, los mismos rangos que el nocturno).
El diseño general guardaba también los `values` en un Secret del clúster
(`topology-scanner-values`) para Jenkins; **se deja para la fase 5**, que es
quien lo necesita.

**CI.** Job nuevo `helm` en `ci.yml`: `helm lint` y `helm template` con
`values.example.yaml`, con `azure/setup-helm` **fijado por SHA** (lo comprueba
`tests/test_workflows.py`). Un test de pytest renderiza el chart
(`helm template`, se salta si `helm` no está instalado) y comprueba lo que no
puede romperse: `hostNetwork`, capacidades exactas, `runAsNonRoot`, nada de
`privileged`/`allowPrivilegeEscalation: false`, `timeZone`, `Forbid` y el tag
fijo.

## Tareas a mano del mantenedor (con supervisión)

1. **RouterOS (hAP)**: permitir SNMP v3 del usuario de solo lectura desde la IP
   con la que el UDM saca a la red B hacia la red A. Hoy solo acepta el PC.
   Comprobar antes desde la VM que la red A es alcanzable (ping al hAP,
   `snmpwalk` de prueba).
2. **Secret SNMP**: `kubectl create secret generic` con las tres claves v3, sin
   que acaben en el historial de la shell (desde un archivo fuera del repo,
   como el `proxmox.env` de la fase 2).
3. **`helm install`** con su `values.local.yaml`.
4. **Primer escaneo a mano**: `kubectl create job --from=cronjob/... prueba`,
   seguir el log y verlo en la web.
5. **Proxy host en NPM**: `scanner.<dominio>` → `<IP del nodo>:8501`, con
   websockets.

## Resultado verificable (cierre de la fase)

- [ ] `pytest` y `ruff` en verde, con tests de rangos permitidos, ejecuciones y
      migración del historial, y del chart renderizado.
- [ ] v1.3.0 publicada (PyPI + GHCR).
- [ ] CI con el job `helm` en verde.
- [ ] El escaneo manual desde el CronJob termina, deja una ejecución con las
      dos redes y la topología SNMP, y la red A sale como árbol (no estrella).
- [ ] En `scanner.<dominio>`, la lista muestra esa ejecución y se abre
      completa.
- [ ] La web rechaza un rango fuera de los permitidos (y una IP SNMP de fuera).
- [ ] Un escaneo lanzado desde la web aparece en la lista.
- [ ] Tras la primera noche, hay una ejecución de las 3:00 con origen `cli`.
- [ ] Runbook `03-kubernetes.md`, `docs/decisiones.md` y `docs/devops/README.md`
      al día.

## Riesgos conocidos

- **La detección de SO a través del NAT** (red A vista desde la red B) es menos
  fiable que en el mismo segmento. Se acepta: los SO de la red A pueden salir
  genéricos o vacíos.
- **Duración del nocturno con `-O`**: no se sabe hasta la primera ejecución.
  El `activeDeadlineSeconds` se ajusta con el dato real.
- **El UDM podría filtrar algo** de la red B hacia la red A. La tarea a mano 1
  lo comprueba antes de instalar nada.

## Lo que queda para el plan

Orden de commits, nombres exactos de funciones y de claves de `values`,
recursos (CPU/RAM) concretos, el puerto si 8501 choca con algo en el nodo, y
el texto del runbook.
