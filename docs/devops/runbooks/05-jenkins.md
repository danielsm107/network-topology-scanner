# Fase 5 — Jenkins (despliegue continuo)

**Objetivo:** que un tag `vX.Y.Z` llegue solo al clúster, **se compruebe que
funciona y vuelva a la versión anterior si no funciona**, avisando por email.
Sin abrir nada a internet: GitHub Actions corre en la nube y no llega a la LAN,
así que Jenkins vive dentro y **mira hacia fuera** (sondea GitHub cada 5 min).
Diseño:
[`docs/superpowers/specs/2026-11-09-fase-5-jenkins-design.md`](../../superpowers/specs/2026-11-09-fase-5-jenkins-design.md).

**Resultado verificable:**

- [x] Jenkins en k3s (chart oficial 5.10.13), configurado entero como código (JCasC):
      sin anónimo, sin ejecutores en el controlador, plugins fijados (2026-11-09).
- [x] v1.4.1 (los hooks de `helm test`) desplegada por Jenkins sin intervención (2026-11-09).
- [x] Ensayo 1, la imagen no arranca: upgrade fallido, rollback, email `REHEARSAL` (2026-11-09).
- [x] Ensayo 2, arranca pero no pasa la prueba: rollback y email (2026-11-09).
- [x] Ensayo 3, versión que nunca se publica (`v1.4.99`): 60 min de espera, **un** email,
      marcada como fallida, los sondeos siguientes no hacen nada (2026-11-09/10).
- [x] Ensayo 4, reconstrucción: `helm uninstall` y reinstalar desde el repo deja el
      pipeline igual, sin tocar la interfaz (2026-11-10).
- [x] Camino feliz: v1.5.0 (filtro de avisos) desplegada sola tras el tag (2026-11-10).
- [x] El nocturno siguiente corre con la 1.5.0: Job completo, informes en S3 y sin
      email, porque no hubo hosts nunca vistos ni cambios de puertos (2026-11-11).

## Piezas

```
Jenkinsfile                       # job desplegar: solo prepara el agente y llama a desplegar.sh
deploy/jenkins/
├── values.yaml                   # chart oficial: JCasC (usuarios, jobs), plugins fijados, NodePort 30880
├── values.example.yaml           # → values.local.yaml (ignorado): jenkinsUrl con el dominio real
├── rbac.yaml                     # namespace, cuenta del agente, Roles, ConfigMap estado-despliegue
├── sondear.Jenkinsfile           # job sondear: cada 5 min, ¿hay versión nueva? → lanza desplegar
├── desplegar.sh                  # toda la lógica: elegir, esperar, upgrade, test, rollback, marcar, avisar
├── elegir_version.sh             # qué tag desplegar (mayor vX.Y.Z, nunca hacia atrás, nunca una fallida)
├── comprobar_publicada.sh        # ¿release de GitHub y tag en GHCR?
└── avisar.sh                     # aws sns publish al topic de los hallazgos
deploy/helm/topology-scanner/templates/test-pod.yaml   # Pod de helm test
tests/test_jenkins.py             # los scripts con helm/kubectl/curl/aws falsos: los caminos de fallo
```

Toda la lógica está en scripts `sh` con tests, no en Groovy: los caminos de
fallo son justo los que peor se ensayan en vivo. Los `Jenkinsfile` solo
preparan el Pod del agente (`alpine/k8s` por digest: helm, kubectl, git, curl, aws).

Objetos que se crean **a mano** y sobreviven a reinstalar Jenkins:

| Objeto | Namespace | Qué lleva |
|---|---|---|
| Secret `jenkins-admin` | `jenkins` | `jenkins-admin-user`, `jenkins-admin-password` |
| Secret `jenkins-avisos` | `jenkins` | `TOPIC_ARN`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` |
| Secret `topology-scanner-values` | `topology-scanner` | `values.yaml`: los values reales del escáner |
| ConfigMap `estado-despliegue` | `jenkins` | `fallidas`: versiones marcadas (lo escribe el pipeline) |

## Cómo funciona

```
git tag vX.Y.Z ─► release.yml: tests, PyPI, GHCR, release de GitHub (la última)
                                                     │
sondear (cada 5 min) ◄───────────────────────────────┘
   └─ ¿tag vX.Y.Z mayor que la desplegada y no marcado? no ─► "Nada que desplegar"
          └─ sí ─► desplegar (MODO=automatico)
                1. espera a la release de GitHub + el tag en GHCR (cada 60 s, máx. 60 min)
                2. clona el tag: chart de ESE tag; values del Secret; image.tag forzado
                3. helm upgrade --wait --timeout 5m
                4. helm test (versión, web, escaneo del propio nodo) + imagen correcta
                   ├─ OK ─► fin, sin email
                   └─ fallo ─► marca ─► helm rollback a la revisión anterior ─► helm test ─► email
                                            └─ falla la vuelta ─► email URGENT
```

- **La versión desplegada se lee del clúster** (etiqueta de la web), no de
  Jenkins: perder `JENKINS_HOME` no cambia lo que decide.
- **Una versión fallida no se reintenta sola**: si no, cada sondeo la volvería a
  desplegar, con su rollback y su email. Se reintenta con un tag nuevo o a mano.
- **La marca se guarda antes de avisar y antes del rollback**: si el pod muere a
  medias, no hay un segundo intento.
- El rollback va a una **revisión explícita** (la de antes del upgrade). Si el
  upgrade falla antes de crear revisión (values inválidos), no se hace rollback:
  bajaría una versión de más.
- `helm test` **sin "Succeeded"** cuenta como fallo: una revisión sin hooks daría
  código 0 sin haber probado nada.
- Los despliegues correctos no mandan email. Los fallidos sí, por el mismo topic
  SNS que los hallazgos, con asunto `topology-scanner deploy FAILED: X.Y.Z` (o
  `URGENT ... rollback FAILED`, o con `REHEARSAL` delante en un ensayo).

## Requisitos en el PC

- Helm, kubectl y el kubeconfig de la fase 2. En Git Bash, `KUBECONFIG` en formato
  Windows y `MSYS_NO_PATHCONV=1` para rutas de Linux (ver `04-aws.md`). **Sin
  `KUBECONFIG`**, Helm intenta `localhost:8080` y falla con
  `kubernetes cluster unreachable` (pasó en el ensayo 4).
- El perfil `personal` de AWS para la clave de Jenkins. Nunca el default.

## 1. Antes de instalar

```bash
# Disco y memoria de la VM: el PVC de Jenkins pide 8 GiB, el controlador hasta 2 GiB
ssh <usuario>@<IP del nodo> 'df -h / && free -h'
```

El 2026-11-09 había 1,4 GiB en uso de 7,75 GiB. Con Jenkins instalado, el
controlador ronda 0,9 GiB.

## 2. Secrets y RBAC

**Valores del escáner.** El Secret pasa a ser la fuente de verdad de los values
(ver `03-kubernetes.md`):

```bash
kubectl -n topology-scanner create secret generic topology-scanner-values \
  --from-file=values.yaml=deploy/helm/values.local.yaml
```

**Administrador de Jenkins.** Usuario y contraseña directos a archivos, sin
pasar por la pantalla ni por el historial de la shell:

```bash
umask 077
echo -n admin > ~/.config/topology-scanner/jenkins-admin-user
openssl rand -base64 24 | tr -d '\n' > ~/.config/topology-scanner/jenkins-admin-password
kubectl apply -f deploy/jenkins/rbac.yaml           # crea también el namespace jenkins
kubectl -n jenkins create secret generic jenkins-admin \
  --from-file=jenkins-admin-user="$HOME/.config/topology-scanner/jenkins-admin-user" \
  --from-file=jenkins-admin-password="$HOME/.config/topology-scanner/jenkins-admin-password"
```

Para recuperar la contraseña más tarde (en tu terminal, no en un chat ni en un log):

```bash
kubectl -n jenkins get secret jenkins-admin -o jsonpath='{.data.jenkins-admin-password}' | base64 -d; echo
```

**Clave de avisos.** Usuario IAM `topology-scanner-jenkins` (lo crea
`infra/aws/hallazgos/`, solo `sns:Publish` sobre el topic). La clave, a mano,
igual que la del homelab:

```bash
{
  aws iam create-access-key --user-name topology-scanner-jenkins --profile personal \
    --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text \
    | awk '{print "AWS_ACCESS_KEY_ID=" $1; print "AWS_SECRET_ACCESS_KEY=" $2}'
  echo "TOPIC_ARN=$(terraform -chdir=infra/aws/hallazgos output -raw topic_arn)"
} > ~/.config/topology-scanner/jenkins-avisos.env
sed -i 's/\r$//' ~/.config/topology-scanner/jenkins-avisos.env   # aws en Windows escribe \r\n
chmod 600 ~/.config/topology-scanner/jenkins-avisos.env

kubectl -n jenkins create secret generic jenkins-avisos \
  --from-env-file="$HOME/.config/topology-scanner/jenkins-avisos.env"
# Longitudes sin ver valores: 20, 40 y la del ARN
kubectl -n jenkins get secret jenkins-avisos \
  -o go-template='{{range $k, $v := .data}}{{$k}} {{len ($v | base64decode)}}{{"\n"}}{{end}}'
```

Rotarla: igual que la del homelab (`04-aws.md`), recreando el Secret con
`--dry-run=client -o yaml | kubectl apply -f -`. Los agentes leen el Secret al
arrancar: el siguiente despliegue ya usa la nueva. Probarla con un ensayo
(paso 6), que manda un email.

## 3. Instalar

```bash
cp deploy/jenkins/values.example.yaml deploy/jenkins/values.local.yaml   # poner el dominio real
helm repo add jenkins https://charts.jenkins.io && helm repo update jenkins
helm -n jenkins install jenkins jenkins/jenkins --version 5.10.13 \
  -f deploy/jenkins/values.yaml -f deploy/jenkins/values.local.yaml --wait --timeout 15m
```

Actualizar values (o JCasC): lo mismo con `upgrade`. Sin el sidecar de recarga,
un cambio de JCasC se aplica al reiniciar el controlador, que el `upgrade` ya hace.

**Comprobaciones** (las cuatro; un "verde" solo no demuestra nada):

```bash
# 1. Ningún plugin roto. Tiene que dar 0
kubectl -n jenkins logs jenkins-0 -c jenkins | grep -c 'Failed Loading'
kubectl -n jenkins logs jenkins-0 -c jenkins | grep 'fully up and running'

# 2. Los jobs los crea JCasC
MSYS_NO_PATHCONV=1 kubectl -n jenkins exec jenkins-0 -c jenkins -- ls /var/jenkins_home/jobs   # desplegar sondear

# 3. Sin login no se entra: 403
curl -s -o /dev/null -w '%{http_code}\n' http://<IP del nodo>:30880/api/json

# 4. El log del último sondeo (el primero llega a los 5 min) dice qué ha decidido
MSYS_NO_PATHCONV=1 kubectl -n jenkins exec jenkins-0 -c jenkins -- sh -c \
  'd=/var/jenkins_home/jobs/sondear/builds; n=$(ls $d | grep -E "^[0-9]+$" | sort -n | tail -1);
   grep -E "Nada que desplegar|Versión nueva" $d/$n/log'
```

Mirar el **log**, no solo el color: con plugins incompletos, `pipeline { }`
terminaba en verde **sin haber arrancado ningún agente**. Y mientras un build
corre, `build.xml` ya pone `<result>SUCCESS</result>`: para saber si acabó,
mirar `Finished:` al final del log (o la `duration`, que es 0 mientras corre).

## 4. NPM

Proxy Host con el dominio de `values.local.yaml` hacia `http://<IP del nodo>:30880`,
certificado SSL y una **Access List solo de la LAN**. Websockets no hacen falta.
Comprobar que desde fuera de la LAN (datos móviles) no responde. El router no
reenvía puertos: Jenkins nunca ha estado expuesto a internet.

## 5. Uso diario

**Sacar versión**: subir la versión, CHANGELOG, commit, PR, merge, y
`git tag vX.Y.Z origin/main && git push origin vX.Y.Z`. Nada más: en ~10-15 min
está desplegada. Se ve en `desplegar` → la ejecución con `Desplegada X.Y.Z: prueba correcta`.

**Cambiar los values** (rangos, horario, SNMP...): actualizar el Secret y lanzar
`desplegar` a mano con `VERSION` vacía, que vuelve a desplegar la versión actual
con los values nuevos (y la prueba, y el rollback si fallan):

```bash
kubectl -n topology-scanner create secret generic topology-scanner-values \
  --from-file=values.yaml=deploy/helm/values.local.yaml --dry-run=client -o yaml | kubectl apply -f -
```

Si falla un redespliegue de la versión que ya corría, **no** se marca: el
problema son los values, no la versión.

**Ejecución manual** (*desplegar → Build with Parameters*):

| `VERSION` | Qué hace |
|---|---|
| vacía | vuelve a desplegar la actual con los values del Secret |
| `X.Y.Z` mayor | despliega esa (aunque esté marcada; si sale bien, se desmarca) |
| `X.Y.Z` menor | **bajada**: marca las superiores, para que el sondeo no la deshaga |

**Ver las marcas y quitarlas** (tras arreglar lo que falló, o para retomar
después de una bajada; también vale desplegarla a mano):

```bash
kubectl -n jenkins get configmap estado-despliegue -o jsonpath='{.data.fallidas}'
kubectl -n jenkins patch configmap estado-despliegue --type merge -p '{"data":{"fallidas":""}}'
```

Si la versión marcada tiene un tag que no se va a publicar nunca (como el del
ensayo 3), **borrar antes el tag** (`git push origin :refs/tags/vX.Y.Z` y
`git tag -d vX.Y.Z`): con el tag vivo y sin marca, el siguiente sondeo lo vuelve
a intentar, con su hora de espera y su email.

**Versiones que cambian el esquema del historial**: Helm no devuelve los datos
atrás. Si una versión migra `historial.db` y luego hay rollback, la anterior
puede no entender la base. La prueba no monta el PVC, así que no lo ve: aparece
en el nocturno. Todo email de rollback lo advierte y enlaza la restauración de
`04-aws.md`. Para una versión así, vigilar el primer nocturno.

## 6. Ensayos

Lanzarlos a mano en *desplegar → Build with Parameters*, `ENSAYO`:

- `no-arranca`: despliega una imagen que no existe. Esperado: `helm upgrade`
  falla a los 5 min, rollback, `helm test` de la vuelta en verde y email
  `REHEARSAL topology-scanner deploy FAILED`. La versión no se marca.
- `falla-prueba`: despliega bien, pero la prueba espera otra versión. Esperado:
  upgrade correcto, `helm test` falla, rollback y email.

Resultados reales:

| Ensayo | Resultado |
|---|---|
| 1. No arranca | Rollback y email. **La web estuvo caída ~5 min** (ver Riesgos). |
| 2. Falla la prueba | Rollback y email. |
| 3. Nunca publicada (`v1.4.99`, no coincide con `pyproject.toml`: `release.yml` lo corta) | Espera de 61 min, marcada, **un** email, sondeos siguientes en "Nada que desplegar"; un `desplegar` duplicado en la cola terminó sin hacer nada. Después: tag borrado y marca quitada. |
| 4. Reconstrucción | `uninstall` + `install`: 47 s, 0 *Failed Loading*, jobs de vuelta, anónimo 403, sondeo "Nada que desplegar", `desplegar` manual con `helm test` en verde. |

**Reconstruir Jenkins** (ensayo 4, o si se rompe):

```bash
helm -n jenkins uninstall jenkins --wait     # borra también el PVC (ver abajo)
helm -n jenkins install jenkins jenkins/jenkins --version 5.10.13 \
  -f deploy/jenkins/values.yaml -f deploy/jenkins/values.local.yaml --wait --timeout 15m
```

Y las comprobaciones del paso 3, más un `desplegar` manual con `VERSION` vacía.
**El PVC de Jenkins lo borra `helm uninstall`**: el chart oficial no lo marca con
`resource-policy: keep` (al revés que el del escáner). Se pierde el historial
de builds, y nada más: lo que decide el pipeline está en el repo, en el clúster
y en el ConfigMap, y los Secrets no los creó Helm. Si alguna vez importa ese
historial, no hacer `uninstall`.

## 7. Actualizar la lista de plugins

Con `installLatestPlugins: false`, una dependencia que no esté en la lista se
instala en **su versión mínima**. Así, en la instalación real, *Pipeline:
Declarative* no cargaba y `pipeline { }` terminaba en verde sin ejecutar nada.
Por eso `values.yaml` lleva la lista **completa**, dependencias incluidas
(`test_plugins_con_todas_sus_dependencias_bloqueadas`). Para regenerarla:

1. En `values.local.yaml`, temporalmente: `installPlugins` con solo los de primer
   nivel (`kubernetes`, `workflow-aggregator`, `git`, `configuration-as-code`,
   `job-dsl`) en la versión nueva, y `installLatestPlugins: true`. `helm upgrade`.
2. Volcar lo instalado, autenticado:

   ```bash
   curl -s -u "admin:$(cat ~/.config/topology-scanner/jenkins-admin-password)" \
     "https://<dominio>/pluginManager/api/json?tree=plugins[shortName,version]" \
     | python -c "import json,sys; [print(f'    - {p[\"shortName\"]}:{p[\"version\"]}') for p in sorted(json.load(sys.stdin)['plugins'], key=lambda p: p['shortName'])]"
   ```
3. Pegarlo en `values.yaml`, quitar lo temporal de `values.local.yaml`,
   `helm upgrade` y las comprobaciones del paso 3 (0 *Failed Loading*).

## Riesgos y limitaciones conocidas

- **Jenkins puede casi todo en el clúster.** El `Role` es solo del namespace
  `topology-scanner`, nunca `cluster-admin`, pero incluye `secrets` (Helm guarda
  ahí sus revisiones: también puede leer los de SNMP y AWS) y crear Pods, que sin
  Pod Security es root en el nodo y, con un solo nodo, el clúster. El chart
  necesita `hostNetwork` y capacidades, que el perfil `baseline` prohíbe: no hay
  parche sencillo. Por eso Jenkins va con contraseña y solo en la LAN
  (`docs/decisiones.md`).
- **El NodePort 30880 responde en HTTP en la LAN**, sin pasar por NPM. Mismo
  criterio que el 8501 de la web: todo es dentro de casa, y sin anónimo.
- **Un despliegue que no arranca tira la web hasta 5 min**: la web usa `Recreate`
  (por `hostNetwork`, ver `03-kubernetes.md`), así que la vieja ya está parada
  cuando la nueva no llega a arrancar, y `--wait --timeout 5m` espera entero antes
  del rollback. El nocturno no se ve afectado salvo que coincida.
- **Fallos fuera del script no mandan email**, solo dejan el build en rojo: el
  Pod del agente muerto, el Secret `jenkins-avisos` ausente o un estado que no se
  puede leer (código 4, que el siguiente sondeo reintenta). Los cubrirá la fase 6.
- **La prueba no cubre SNMP ni la subida a AWS** (necesitarían credenciales
  reales y tienen efectos): un fallo ahí aparece en el nocturno.
- **Límite de la API de GitHub** (60 peticiones/h sin token): la espera pregunta
  una vez por minuto, dentro del límite.
- **El sondeo usa la misma cuenta que despliega**: no necesita escribir, pero una
  segunda cuenta de solo lectura sería un Role más para casi nada.
