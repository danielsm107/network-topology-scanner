# Fase 4 — AWS como código + avisos de cambios

**Objetivo:** que un cambio en la red de casa llegue por **email** a la mañana
siguiente, sin abrir la web, con enlaces al mapa y al CSV de esa noche; que el
historial **sobreviva** a la pérdida del clúster (copia en S3, restauración
probada); y que la infraestructura de AWS se cambie **por PR**, con GitHub
Actions entrando en AWS por OIDC, sin claves. Diseño:
[`docs/superpowers/specs/2026-11-06-fase-4-aws-design.md`](../../superpowers/specs/2026-11-06-fase-4-aws-design.md).

**Resultado verificable:**

- [x] v1.4.0 publicada (PyPI + GHCR) con `--changes-dir` y `--history-backup`.
- [x] `infra/aws/hallazgos/` aplicado (14 recursos) y probado con `terraform test` en la CI.
- [x] El plan de un PR sale como comentario (`No changes`) y el apply de main espera aprobación (2026-11-06).
- [x] Job de prueba en el clúster: informes en `informes/<fecha>/`, copia en `historial/historial.db`
      y email con enlaces que abren el mapa y el CSV (2026-11-06).
- [x] Ensayo de restauración: PVC borrado de verdad, restaurado desde S3, la web lista las
      ejecuciones de antes y el siguiente escaneo no avisa de todos los hosts como nuevos (2026-11-06).
- [x] El nocturno de las 3:00 sube sus informes (y avisa, si hubo cambios) sin intervención
      (2026-11-07, 08 y 09).

## Piezas

```
infra/aws/hallazgos/            # Terraform: estado en el bucket del bootstrap, clave hallazgos/
├── main.tf                     # bucket de informes (+ retenciones) y SNS con suscripción email
├── iam.tf                      # usuario del homelab, OIDC de GitHub, roles de plan y apply
├── variables.tf                # email_avisos (sensitive), bucket_estado, repo_github (sub inmutable)
├── tests/hallazgos.tftest.hcl  # provider simulado: corre en la CI sin credenciales
├── backend.hcl.example         # → backend.hcl (ignorado)
└── terraform.tfvars.example    # → terraform.tfvars (ignorado, lleva el email)
.github/workflows/terraform-aws.yml   # plan en PR (comentario), apply en main (environment aws)
deploy/helm/topology-scanner/
├── files/subir.sh              # sube informes y copia, firma enlaces y publica en SNS
└── templates/configmap-subida.yaml
```

Flujo de una noche con `aws.enabled`:

1. `initContainer` **escaneo** (la imagen de siempre): escanea, guarda en el
   historial del PVC y deja en un `emptyDir` (`/salida`) el HTML, el CSV, una
   copia consistente del historial y, **solo si merece aviso**, `cambios/`
   (`cambios.json`, `asunto.txt`, `cuerpo.txt`). Ver "Cuándo avisa".
2. Contenedor **subida** (`amazon/aws-cli` por digest, sin capacidades, raíz de
   solo lectura): sube todo a S3 y, si existe `cambios.json`, firma enlaces de
   7 días y publica el aviso en SNS. Si falla la copia del historial, el aviso
   sale igual y el Job termina fallido.

### Cuándo avisa (desde v1.5.0)

Las primeras noches avisó a diario por equipos de casa que entran y salen de la
red, y un aviso diario se acaba ignorando. Desde la 1.5.0 (`history.merece_aviso`),
el email sale solo si en algún rango hay:

- un host **nunca visto** en ese rango (en ningún escaneo guardado, los últimos 50)
  con al menos un puerto abierto, o
- un **cambio de puertos** en un host que ya estaba.

Ya no avisan los hosts que caen, los que no tienen puertos ni los conocidos que
vuelven. Cuando el email sale, lleva **todos** los cambios, como antes. La web y
el historial lo siguen mostrando todo. Límites: se identifica por IP (un equipo
conocido con una IP nueva sí avisa) y un equipo que vuelve con puertos distintos
no avisa (no hay escaneo anterior con el que comparar).

Retenciones del bucket: `informes/` 90 días; versiones antiguas de
`historial/historial.db`, 30 días (la actual no caduca).

## Requisitos en el PC

- Terraform 1.16.6, kubectl, Helm y `gh` (los de las fases anteriores).
- `aws sso login --profile personal`. **Nunca el perfil default** (es la cuenta
  del trabajo).
- Para `kubectl` con rutas de Linux en Git Bash: `MSYS_NO_PATHCONV=1` y
  `KUBECONFIG` en formato Windows (`C:/Users/<usuario>/.kube/config-homelab`).
  Con `~/.kube/...` o `/c/Users/...`, `MSYS_NO_PATHCONV` tampoco convierte el
  `KUBECONFIG` y kubectl acaba intentando `localhost:8080`.

## 1. Primer apply desde el PC (una sola vez)

GitHub no puede crear el rol con el que él mismo entra en AWS: el primer apply
es desde el PC, como el bootstrap de la fase 2.

```bash
cd infra/aws/hallazgos
cp backend.hcl.example backend.hcl
cp terraform.tfvars.example terraform.tfvars
terraform -chdir=../bootstrap output bucket_estado   # → en los dos archivos
# terraform.tfvars: email_avisos = el email real (el archivo está ignorado)

# Solo puede haber un OIDC de GitHub por cuenta: si ya existe, importarlo
aws iam list-open-id-connect-providers --profile personal

terraform init -backend-config=backend.hcl
terraform plan -out="$HOME/hallazgos.tfplan"   # fuera del repo: el plan lleva datos de la cuenta
terraform apply "$HOME/hallazgos.tfplan"
rm "$HOME/hallazgos.tfplan"
terraform output
```

Después, **confirmar la suscripción**: AWS manda un email "AWS Notification -
Subscription Confirmation" (mirar en spam). Hasta pulsar el enlace, SNS no
entrega nada.

## 2. GitHub: environment, variables y secret

En *Settings → Environments*, environment **`aws`**:

- **Required reviewers**: el mantenedor. Sin esto, el apply se ejecuta solo al
  mergear. Comprobar que está:
  `gh api repos/{owner}/{repo}/environments/aws -q '.protection_rules[].type'`
  tiene que listar `required_reviewers` y `branch_policy`.
- **Deployment branches**: solo `main`.

Variables y secret (con los outputs del paso 1):

```bash
gh variable set AWS_ROLE_PLAN_ARN  --body "arn:aws:iam::123456789012:role/topology-scanner-github-plan"
gh variable set AWS_ROLE_APPLY_ARN --body "arn:aws:iam::123456789012:role/topology-scanner-github-apply"
gh variable set TF_STATE_BUCKET    --body "topology-scanner-tfstate-123456789012"
gh secret set ALERT_EMAIL          # lo pide por teclado; el mismo que en terraform.tfvars
```

Comprobación: un PR que toque `infra/aws/hallazgos/` tiene un comentario con el
plan (`No changes`), y al mergearlo el job `apply` se queda en *Waiting* hasta
aprobarlo en *Actions → Review deployments*.

### Si el plan falla con `Not authorized to perform sts:AssumeRoleWithWebIdentity`

El `sub` del token de GitHub no coincide con el del trust del rol. GitHub está
activando el **formato inmutable**, con los IDs del usuario y del repo:

```bash
gh api repos/{owner}/{repo}/actions/oidc/customization/sub
# {"use_immutable_subject":true,"sub_claim_prefix":"repo:<usuario>@<id>/<repo>@<id>"}
```

`repo_github` (en `variables.tf`) tiene que ser lo de después de `repo:`. El
formato inmutable es mejor que el antiguo (un repo renombrado o recreado por
otra persona con el mismo nombre no entra), así que se adapta el rol, no se
desactiva. El cambio se aplica **desde el PC** (paso 1), porque el rol de apply
tiene el mismo problema y GitHub no puede arreglarlo él solo. Pasó en la
instalación real.

## 3. La clave del homelab y el Secret

Terraform no crea la clave: quedaría en el estado, y el rol de plan de los PRs
lo lee. Se crea a mano y va directa a un archivo, sin pasar por la pantalla:

```bash
mkdir -p ~/.config/topology-scanner
aws iam create-access-key --user-name topology-scanner-homelab --profile personal \
  --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text \
  | awk '{print "AWS_ACCESS_KEY_ID=" $1; print "AWS_SECRET_ACCESS_KEY=" $2}' \
  > ~/.config/topology-scanner/aws.env
sed -i 's/\r$//' ~/.config/topology-scanner/aws.env   # aws en Windows termina las líneas en \r\n
chmod 600 ~/.config/topology-scanner/aws.env
cut -d= -f1 ~/.config/topology-scanner/aws.env        # solo los nombres

kubectl -n topology-scanner create secret generic topology-scanner-aws \
  --from-env-file="$HOME/.config/topology-scanner/aws.env"
# Longitudes sin ver los valores: tienen que ser 20 y 40
kubectl -n topology-scanner get secret topology-scanner-aws \
  -o go-template='{{range $k, $v := .data}}{{$k}} {{len ($v | base64decode)}}{{"\n"}}{{end}}'
```

**Si falta el Secret**, el contenedor de subida se queda en
`CreateContainerConfigError` hasta el `activeDeadlineSeconds` del Job (4 h). El
escaneo ya está guardado para entonces; solo se pierde la subida y el aviso.

### Rotar la clave

1. `aws iam create-access-key ...` como arriba (un usuario admite dos claves a la vez).
2. Volver a crear el Secret:
   `kubectl ... create secret generic topology-scanner-aws --from-env-file=... --dry-run=client -o yaml | kubectl apply -f -`.
3. Lanzar un Job de prueba (paso 5). Si sube, desactivar y borrar la vieja:
   `aws iam list-access-keys --user-name topology-scanner-homelab --profile personal`,
   `aws iam update-access-key --status Inactive ...` y `aws iam delete-access-key ...`.

## 4. Activar la subida en el chart

En `deploy/helm/values.local.yaml` (ignorado), con los outputs del paso 1:

```yaml
aws:
  enabled: true
  bucket: topology-scanner-informes-123456789012
  topicArn: arn:aws:sns:eu-south-2:123456789012:topology-scanner-hallazgos
```

```bash
helm upgrade topology-scanner ./deploy/helm/topology-scanner \
  -n topology-scanner -f deploy/helm/values.local.yaml --wait
kubectl -n topology-scanner get configmap topology-scanner-subida
```

## 5. Job de prueba y aviso

```bash
kubectl -n topology-scanner create job --from=cronjob/topology-scanner-escaneo prueba
kubectl -n topology-scanner wait --for=condition=complete job/prueba --timeout=900s
kubectl -n topology-scanner logs job/prueba -c escaneo | sed -n '/HISTORY/,$p'
kubectl -n topology-scanner logs job/prueba -c subida
kubectl -n topology-scanner delete job prueba
```

`kubectl wait` con **una** condición: con `--for=condition=complete
--for=condition=failed` espera a que se cumplan las dos, y se queda colgado.

La subida termina en `Aviso publicado en SNS.` si mereció aviso, o en `Sin
cambios ...: no se avisa.` si no (el texto es anterior a la 1.5.0: también sale
cuando hubo cambios que no merecen aviso). Para forzar un aviso desde la 1.5.0,
apagar o encender un equipo ya no basta: hace falta abrir o cerrar un puerto
**de los que mira el escaneo** (`PUERTOS_POR_DEFECTO`, el chart no pasa
`--ports`) en un host que ya esté en el historial. Por ejemplo,
`python -m http.server 8080` en un PC de la red que no tenga el 8080 abierto (el
8000 por defecto no se escanea). Pararlo después: si no, la noche siguiente
vuelve a avisar, al cerrarse. El asunto es ASCII (límite de SNS) y lo sensible
va primero.

Ver lo subido: `aws s3 ls s3://<bucket> --recursive --profile personal`.

## 6. Restaurar el historial

La copia está en `historial/historial.db`, con versiones de 30 días. El usuario
del homelab **no puede leerla**: se restaura desde el PC con el perfil
`personal`. Este procedimiento se ensayó de verdad, borrando el PVC.

```bash
export KUBECONFIG="C:/Users/<usuario>/.kube/config-homelab"   # formato Windows (ver Requisitos)

# 1. Parar a quien escribe, y borrar los Jobs terminados: sus Pods (aunque
#    estén Completed) mantienen el PVC en Terminating y el borrado no acaba
kubectl -n topology-scanner patch cronjob topology-scanner-escaneo -p '{"spec":{"suspend":true}}'
kubectl -n topology-scanner scale deploy topology-scanner-web --replicas=0
kubectl -n topology-scanner delete jobs --all

# 2. Solo si el volumen está mal o se ha perdido (el ensayo lo borró a propósito)
kubectl -n topology-scanner delete pvc topology-scanner-datos
kubectl -n topology-scanner get pvc        # tiene que no salir nada antes de seguir

# 3. Elegir versión y bajarla
aws s3api list-object-versions --bucket <bucket> --prefix historial/ --profile personal \
  --query 'Versions[].[VersionId,LastModified,IsLatest]' --output table
aws s3api get-object --bucket <bucket> --key historial/historial.db \
  --version-id <VersionId> --profile personal "$HOME/historial-restaurado.db"

# 4. PVC nuevo (helm lo recrea, pero también arranca la web: pararla otra vez;
#    la pausa del CronJob la respeta, el chart no define suspend)
helm upgrade topology-scanner ./deploy/helm/topology-scanner -n topology-scanner -f deploy/helm/values.local.yaml
kubectl -n topology-scanner scale deploy topology-scanner-web --replicas=0

# 5. Pod temporal con el volumen, mismo usuario que la app
kubectl -n topology-scanner apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: restaurar
spec:
  securityContext: {runAsUser: 10001, runAsGroup: 10001, fsGroup: 10001}
  containers:
    - name: restaurar
      image: ghcr.io/danielsm107/topology-scanner:1.4.0
      command: [sleep, "3600"]
      volumeMounts: [{name: datos, mountPath: /data}]
  volumes:
    - name: datos
      persistentVolumeClaim: {claimName: topology-scanner-datos}
EOF
kubectl -n topology-scanner wait --for=condition=Ready pod/restaurar --timeout=120s

# 6. Copiar (ruta relativa: con C:\..., kubectl cp toma "C" por un Pod) y comprobar
cd ~
MSYS_NO_PATHCONV=1 kubectl cp historial-restaurado.db topology-scanner/restaurar:/data/historial.db
MSYS_NO_PATHCONV=1 kubectl -n topology-scanner exec restaurar -- python -c "
import sqlite3; from topology_scanner.history import listar_ejecuciones
print(sqlite3.connect('/data/historial.db').execute('PRAGMA integrity_check').fetchone()[0])
print(len(listar_ejecuciones('/data/historial.db', limite=1000)), 'ejecuciones')"

# 7. Volver a arrancar
kubectl -n topology-scanner delete pod restaurar
kubectl -n topology-scanner scale deploy topology-scanner-web --replicas=1
kubectl -n topology-scanner patch cronjob topology-scanner-escaneo -p '{"spec":{"suspend":false}}'
rm ~/historial-restaurado.db
```

Comprobación: la web lista las ejecuciones de antes, y un Job de prueba (paso 5)
compara contra la última restaurada (pocos cambios, no todos los hosts nuevos).

## Usuario de Jenkins (fase 5)

`infra/aws/hallazgos/` crea también `topology-scanner-jenkins`, con **solo
`sns:Publish` sobre el topic**: Jenkins avisa de un despliegue fallido por el
mismo email. No reutiliza el usuario del homelab porque ese escribe en S3, y
Jenkins no lo necesita. Su clave, también a mano y fuera del estado: ver
`05-jenkins.md`, paso 2.

## Cambiar la infraestructura de AWS

Por PR: editar `infra/aws/hallazgos/`, revisar el plan del comentario, mergear y
aprobar el apply en *Actions*. Desde el PC solo para lo que GitHub no puede
hacer (el primer apply, o un cambio en los propios roles de OIDC).

## Riesgos y limitaciones conocidas

- **Claves de larga duración en el homelab** (usuario IAM): sin PKI no hay forma
  de evitarlas. Mínimo privilegio, fuera del estado de Terraform, y rotación
  documentada arriba. Mejora futura: IAM Roles Anywhere.
- **El rol de apply puede ampliarse a sí mismo** (`iam:*` sobre
  `topology-scanner-*`). Lo frena el environment con aprobación obligatoria. El
  `Deny` de crear claves de su política es una protección contra errores, no una
  barrera: el rol puede quitárselo. Para que lo fuera, haría falta un
  *permissions boundary* que no pueda editar.
- **Los enlaces del email valen 7 días** para cualquiera que tenga el email.
- **El plan de los PRs es público** (repo público): muestra el ID de la cuenta en
  los ARN. AWS no lo trata como secreto; el email va como `sensitive`.
- **Si la subida falla, el aviso de esa noche se pierde**: el Job no se reintenta
  (el diff ya está en el historial). aws-cli reintenta los errores pasajeros
  (`AWS_RETRY_MODE=standard`); un fallo que persista lo avisará la fase 6.
