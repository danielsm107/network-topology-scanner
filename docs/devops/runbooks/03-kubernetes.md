# Fase 3 — Despliegue en Kubernetes

**Objetivo:** que el escáner viva en el k3s de casa (la VM de la fase 2) en vez
de en el PC: un **escaneo nocturno** de las redes de casa que queda en el
historial, y una **web en la LAN** para ver cualquier escaneo guardado y lanzar
otros, solo contra esas redes. Diseño:
[`docs/superpowers/specs/2026-10-29-fase-3-kubernetes-design.md`](../../superpowers/specs/2026-10-29-fase-3-kubernetes-design.md).

**Resultado verificable:**

- [x] v1.3.0 publicada (PyPI + GHCR) con rangos permitidos y ejecuciones en el historial.
- [x] Chart de Helm con tests (`tests/test_helm.py`) y job `helm` en la CI.
- [x] `helm install` en el k3s: web `Running`, PVC `Bound`, CronJob programado (2026-11-03).
- [x] Escaneo a mano desde el CronJob: termina, con MAC en la red del nodo y árbol SNMP (98 s, 2026-11-03).
- [x] La web, detrás de NPM por HTTPS y websockets, lista la ejecución y la abre entera.
- [ ] A la mañana siguiente, la lista tiene una ejecución de las 3:00 con origen `cli`.

## Piezas

```
deploy/helm/
├── .gitignore                       # ignora values.local.yaml
├── values.local.yaml                # los valores reales (no está en git)
└── topology-scanner/
    ├── Chart.yaml
    ├── values.yaml                  # por defecto, con datos inventados
    ├── values.example.yaml          # → ../values.local.yaml
    └── templates/
        ├── _helpers.tpl             # pod y contenedor comunes: hostNetwork, UID 10001, capacidades, Secret
        ├── cronjob.yaml             # escaneo nocturno (CLI)
        ├── deployment.yaml          # web (Streamlit)
        ├── pvc.yaml                 # /data: historial.db y el último HTML
        └── NOTES.txt
```

Ni Service ni Ingress: los pods usan la red del nodo (`hostNetwork`) para ver
las MACs, y NPM hace de proxy directamente a `<IP del nodo>:8501`. Meter
Traefik en medio serían dos proxies encadenados sin ganar nada.

Nada real va al repo: redes, IP del router, dominio y credenciales viven en
`values.local.yaml`, en un archivo de entorno fuera del repo y en un Secret
creado a mano.

## Requisitos en el PC

- Helm y kubectl (`winget install Helm.Helm Kubernetes.kubectl`).
- El kubeconfig de la fase 2: `export KUBECONFIG=~/.kube/config-homelab`.
- Comandos de Helm **desde la raíz del repo**. Si la ruta del chart no existe
  desde donde estás, Helm la toma por `<repo>/<chart>` y responde
  `repo deploy not found`. Con `./deploy/...` el error es más claro.

## A mano en el router (SNMPv3)

El nodo está en la red B, detrás del UDM, y llega al router de la red A (el
hAP) **a través de su NAT**: el hAP ve a toda la red B con una sola IP, la del
UDM en la red A. Por eso:

- **SNMPv3 (SHA + AES), no v2c.** Con v2c, el filtro por IP dejaría pasar a
  cualquier equipo de la red B, y la community viaja en claro. Con v3 hacen
  falta el usuario y sus dos claves, y el tráfico va cifrado.
- El usuario de solo lectura acepta la IP del PC y la del UDM en la red A
  (`addresses`), nada más.

Claves aleatorias en hexadecimal (sin símbolos que haya que escapar en RouterOS
ni en el archivo de entorno), escritas **directamente en el archivo**, para que
no pasen por el portapapeles ni por el historial de la shell:

```bash
umask 077   # solo tu usuario puede leer el archivo
{
  echo "TOPOLOGY_SNMP_USER=<usuario>"
  echo "TOPOLOGY_SNMP_AUTH_KEY=$(openssl rand -hex 16)"
  echo "TOPOLOGY_SNMP_PRIV_KEY=$(openssl rand -hex 16)"
} > ~/.config/topology-scanner/snmp.env
```

En RouterOS (probado en v6), con los dos valores del archivo:

```
/snmp community set [find name=<usuario>] authentication-password=<auth> encryption-password=<priv>
/snmp community print detail where name=<usuario>
```

En el `print`: `security=private`, `authentication-protocol=SHA1`,
`encryption-protocol=AES` y las dos IPs en `addresses`. Para probarlo desde el
PC sin mostrar las claves:

```bash
set -a; . ~/.config/topology-scanner/snmp.env; set +a
python -c "import os; from topology_scanner import snmp; \
  print(snmp.consultar_equipo('<IP del router>', snmp.credenciales_desde_entorno(os.environ))['nombre'])"
```

## El Secret

El chart **no crea** el Secret: solo lo referencia por nombre (`snmpSecret`).
Si lo creara, las claves tendrían que pasar por los `values` y acabarían en
el historial de releases de Helm (que se guarda dentro del clúster).

```bash
kubectl create namespace topology-scanner
kubectl -n topology-scanner create secret generic topology-scanner-snmp \
  --from-env-file="$HOME/.config/topology-scanner/snmp.env"
```

Comprobar las claves sin ver los valores:

```bash
kubectl -n topology-scanner get secret topology-scanner-snmp \
  -o go-template='{{range $k, $v := .data}}{{$k}}: {{len (base64decode $v)}} caracteres{{"\n"}}{{end}}'
```

Las claves de `openssl rand -hex 16` tienen 32 caracteres, y el usuario los
suyos. Uno de más es un `\r`: el archivo tiene finales de línea de Windows y
el router rechaza la autenticación sin decir por qué. Arreglo: guardar el
archivo con finales LF y volver a crear el Secret. (Mirar la longitud en
base64 no basta: 32 y 33 caracteres ocupan lo mismo, 44.)

**Cambiar las claves** (después de cambiarlas en el router): regenerar el
Secret y reiniciar la web, que lee las variables al arrancar. El CronJob coge
el Secret nuevo en su siguiente ejecución.

```bash
kubectl -n topology-scanner create secret generic topology-scanner-snmp \
  --from-env-file="$HOME/.config/topology-scanner/snmp.env" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n topology-scanner rollout restart deployment/topology-scanner-web
```

## Los values

`cp deploy/helm/topology-scanner/values.example.yaml deploy/helm/values.local.yaml`
y poner los datos reales. Solo hace falta lo que cambia respecto a `values.yaml`:

```yaml
escaneo:
  rangos:
    - 192.0.2.0/24       # la red del nodo: MAC y fabricante directos
    - 198.51.100.0/24    # la otra red, detrás de un router: se completa con SNMP
  snmp:
    - 198.51.100.1       # router a consultar
web:
  dominio: scanner.example.com   # el Proxy Host de NPM (ver más abajo)
rangosPermitidos: []             # vacío = los mismos rangos del escaneo
```

Comprobar que git no lo ve (`git status` no debe listarlo) y revisar lo que se
va a aplicar sin tocar el clúster:

```bash
helm lint ./deploy/helm/topology-scanner -f deploy/helm/values.local.yaml
helm template topology-scanner ./deploy/helm/topology-scanner -f deploy/helm/values.local.yaml | less
```

## Instalar, actualizar, volver atrás

```bash
helm install topology-scanner ./deploy/helm/topology-scanner \
  -n topology-scanner -f deploy/helm/values.local.yaml
kubectl -n topology-scanner get pods,cronjob,pvc
```

La primera vez, la web tarda unos segundos en estar `1/1` (descarga la imagen
de GHCR). Un `Readiness probe failed ... connection refused` en los eventos al
arrancar es normal: la sonda llega antes que Streamlit.

Cualquier cambio de los values o del chart (rangos, horario, versión de la
imagen) se aplica igual, y cada `upgrade` es una revisión nueva:

```bash
helm upgrade topology-scanner ./deploy/helm/topology-scanner \
  -n topology-scanner -f deploy/helm/values.local.yaml --wait
helm -n topology-scanner history topology-scanner
helm -n topology-scanner rollback topology-scanner <revisión>   # si algo va mal
```

La web usa la estrategia `Recreate`: en cada upgrade se corta unos segundos.
Con `hostNetwork`, un `RollingUpdate` arrancaría la web nueva mientras la vieja
sigue ocupando el puerto del nodo, y la nueva no arrancaría nunca.

## Escaneo a mano

Para no esperar a las 3:00, un Job con la misma plantilla que el CronJob:

```bash
kubectl -n topology-scanner create job prueba-1 --from=cronjob/topology-scanner-escaneo
kubectl -n topology-scanner logs -f job/prueba-1     # Ctrl+C deja de mirar, el Job sigue
kubectl -n topology-scanner get job prueba-1         # COMPLETIONS 1/1 y su duración
```

Qué tiene que salir en el log: `live hosts`, cada host de la red del nodo con
su fabricante (los de la otra red salen como `unknown vendor`: detrás de un
router no hay MAC), `SNMP topology: N network devices` y el bloque de
`HISTORY` por rango. Los Jobs a mano no se borran solos:
`kubectl -n topology-scanner delete job prueba-1`.

`activeDeadlineSeconds` (4 h) mata el escaneo si se cuelga. El primero real,
con `-O` y dos /24 (25 hosts vivos), tardó 98 s: hay margen de sobra.

## La web en NPM

En Nginx Proxy Manager, un Proxy Host:

- Dominio: el de `web.dominio`. Destino: `http://<IP del nodo>:8501`.
- **Websockets Support activado.** Imprescindible: Streamlit funciona entero
  por websocket. Sin él, la página carga pero se queda colgada.
- Certificado SSL y, si se quiere, una **Access List** (por IP de la LAN o con
  usuario y contraseña). La web no tiene login: la protegen que NPM no esté
  publicado fuera y la lista de rangos permitidos.

`web.dominio` hace que Streamlit se anuncie con ese nombre en el 443. Sin él,
al arrancar en modo headless consulta `checkip.amazonaws.com` para mostrar la
IP pública en el log, y vuelve a usarla al validar el `Origin` del websocket.

Comprobación sin navegador:

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://scanner.example.com/_stcore/health   # 200
curl -s -i -N --max-time 4 -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  https://scanner.example.com/_stcore/stream | head -1                                 # 101
```

Y en el navegador: la ejecución del Job sale en "Saved scans" y se abre entera
(inventario, cambios, árbol SNMP); un rango de fuera de los permitidos se
rechaza; un escaneo lanzado desde la web aparece en la lista con origen `web`.

## Ver qué ha guardado

```bash
kubectl -n topology-scanner exec deploy/topology-scanner-web -- python -c "
from topology_scanner.history import listar_ejecuciones
for e in listar_ejecuciones('/data/historial.db'): print(e['fecha'], e['origen'], e['rangos'], e['total_hosts'])"
```

En Git Bash, las rutas que empiezan por `/` en un `kubectl exec` (`ls /data`)
se convierten en rutas de Windows: `MSYS_NO_PATHCONV=1 kubectl ...`.

## Desinstalar

```bash
helm -n topology-scanner uninstall topology-scanner
```

El PVC tiene `helm.sh/resource-policy: keep`: el historial sobrevive y un
`helm install` posterior lo vuelve a montar. Para borrarlo de verdad, a mano:
`kubectl -n topology-scanner delete pvc topology-scanner-datos`. El Secret
tampoco lo borra Helm (no lo creó él).

## Riesgos y limitaciones conocidas

- **Detección de SO a través del NAT**: en la red que no es la del nodo, `-O`
  acierta menos (el UDM está en medio). El nocturno lo hace igualmente, de
  noche no hay prisa.
- **El puerto 8501 también responde directamente** en la LAN, sin pasar por
  NPM. Aceptado: todo es dentro de casa.
- **Un solo nodo**: el PVC es `local-path` (disco de la VM). Si se recrea la VM
  con Terraform, el historial se pierde. Copia a S3 en la fase 4.
