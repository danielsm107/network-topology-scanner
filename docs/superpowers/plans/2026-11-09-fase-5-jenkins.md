# Fase 5: Jenkins (CD), plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** un tag `vX.Y.Z` publicado acaba desplegado en k3s por Jenkins, se prueba con `helm test`, vuelve atrás solo si falla y avisa por email.

**Architecture:** la lógica va en scripts POSIX con tests (`deploy/jenkins/*.sh`, probados con `helm`/`kubectl`/`aws` falsos en el `PATH`, igual que `files/subir.sh`). Los pipelines solo los llaman. Dos jobs: `sondear` (cron, historial corto) lanza `desplegar` (historial largo) cuando hay algo que hacer.

**Tech Stack:** Jenkins (chart oficial + JCasC + job-dsl + plugin de Kubernetes), Helm 4, k3s, AWS SNS, Terraform, POSIX sh, pytest.

**Spec:** `docs/superpowers/specs/2026-11-09-fase-5-jenkins-design.md`

## Global Constraints

- Solo tags con la forma exacta `vX.Y.Z`. Nunca hacia atrás de forma automática.
- Una versión fallida no se reintenta sola.
- Espera máxima a la release y la imagen: 60 minutos.
- Ningún ensayo publica una versión rota en PyPI ni en `latest`.
- La prueba no toca el historial, no monta el PVC, no sube nada, no manda el email de cambios y solo escanea la IP del propio nodo.
- Jenkins: `Role` por namespace, nunca `cluster-admin`; sin acceso anónimo; solo LAN por NPM con HTTPS.
- Límite inicial de memoria del controlador: 2 GiB.
- Terceros (imágenes, chart, plugins) con versión fija; imágenes por digest; versiones publicadas hace unos días.
- Ningún `.tf` crea `aws_iam_access_key`. Claude nunca ve valores secretos.
- Datos inventados en repo y tests (`192.0.2.0/24`, `02:00:00:…`, `jenkins.example.com`). Dominio y redes reales solo en archivos ignorados.
- `ruff check src/ tests/ scripts/` y `pytest tests/ -v` en verde antes de cada commit. Scripts con finales LF (`.gitattributes` ya cubre `*.sh`).
- Comandos de los pasos en Git Bash, con `.venv/Scripts/` delante de `pytest`/`ruff`.

## Review Focus

- `kubectl` falla al leer la versión desplegada o las fallidas: se aborta sin desplegar. Tratarlo como "vacío" reabriría el bucle de reintentos. Test en Tarea 2.
- GitHub o GHCR dan error o límite de peticiones durante la espera: cuenta como "todavía no", no como fallo inmediato. Test en Tarea 2.
- El rollback también falla: email urgente distinto y código de salida de error. Test en Tarea 3.
- SNS caído mientras se avisa de un fallo: el rollback ya se ha hecho, el error del aviso se registra y la ejecución termina en error sin ocultar el motivo original. Test en Tarea 3.
- Orden semántico (`v1.10.0` mayor que `v1.9.0`) y tags raros (`v1.5.0-rc1`, `v1.5`, `release-1`): test en Tarea 2.

---

### Tarea 1: Prueba del chart con `helm test`, y coherencia de versiones

**Files:**
- Create: `deploy/helm/topology-scanner/templates/test-pod.yaml`
- Modify: `deploy/helm/topology-scanner/values.yaml`, `src/topology_scanner/cli.py`
- Test: `tests/test_helm.py`, `tests/test_cli.py`

**Interfaces:**
- Produces: Pod `<fullname>-prueba` con hook `test`; valor `pruebas.versionEsperada` (vacío = `image.tag`), que usa el ensayo 2; `topology-scanner --version` imprime `topology-scanner X.Y.Z`.

- [ ] **Paso 1: Tests que fallan**

En `tests/test_cli.py`, `test_version_imprime_la_del_paquete`: `--version` termina con código 0 e imprime `topology_scanner.__version__`. En `tests/test_helm.py`:

```python
def test_prueba_es_hook_de_helm_y_no_toca_datos():
    pod = _renderizar()["Pod"]
    assert pod["metadata"]["annotations"]["helm.sh/hook"] == "test"
    assert pod["spec"]["restartPolicy"] == "Never"
    assert pod["spec"]["hostNetwork"] is True
    assert "volumes" not in pod["spec"]
    (c,) = pod["spec"]["containers"]
    assert "volumeMounts" not in c and "envFrom" not in c
    assert c["securityContext"]["capabilities"]["add"] == ["NET_RAW", "NET_ADMIN", "NET_BIND_SERVICE"]
    guion = c["command"][-1]
    assert "--no-history" in guion and "--history-db" not in guion and "--changes-dir" not in guion

def test_prueba_solo_escanea_el_nodo():
    (c,) = _renderizar()["Pod"]["spec"]["containers"]
    assert _env(c)["IP_NODO"]["valueFrom"]["fieldRef"]["fieldPath"] == "status.hostIP"

def test_version_esperada_por_defecto_es_la_imagen():
    (c,) = _renderizar("--set", "image.tag=9.9.9")["Pod"]["spec"]["containers"]
    assert _env(c)["VERSION_ESPERADA"]["value"] == "9.9.9"

def test_chart_e_imagen_coinciden_con_pyproject():
    version = tomllib.loads((RAIZ / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    chart = yaml.safe_load((CHART / "Chart.yaml").read_text(encoding="utf-8"))
    valores = yaml.safe_load((CHART / "values.yaml").read_text(encoding="utf-8"))
    assert chart["appVersion"] == version
    assert valores["image"]["tag"] == version
```

`tomllib` no existe en 3.10: `pytest.importorskip("tomllib")` dentro del test (en 3.12 se ejecuta).

- [ ] **Paso 2: Comprobar que fallan.** `.venv/Scripts/pytest tests/test_helm.py tests/test_cli.py -v`. Esperado: fallan los nuevos, con `KeyError: 'Pod'`.

- [ ] **Paso 3: Implementar**

- `cli.py`: `parser.add_argument("--version", action="version", version=f"topology-scanner {__version__}")`.
- `values.yaml`: `pruebas: {versionEsperada: ""}`, con comentario de que solo lo cambia el ensayo.
- `test-pod.yaml`: Pod con `topology-scanner.podComun` y `contenedorComun`, `helm.sh/hook: test`, `helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded`, `resources` de `resources.escaneo`, `command: [sh, -ec, <guion>]` y env `TZ`, `IP_NODO`, `VERSION_ESPERADA` (`default .Values.image.tag .Values.pruebas.versionEsperada`), `PUERTO_WEB`. El guion:
  1. `topology-scanner --version` tiene que ser `topology-scanner $VERSION_ESPERADA`.
  2. `python -c` con `urllib` contra `http://$IP_NODO:$PUERTO_WEB/_stcore/health`, con tres reintentos.
  3. `topology-scanner "$IP_NODO" --fast --no-history --output /tmp/p.html --csv /tmp/p.csv`, y el CSV tiene al menos una fila de datos. El Pod corre con `workingDir: /tmp`.

- [ ] **Paso 4: Comprobar.** `.venv/Scripts/pytest tests/ -q` y `.venv/Scripts/ruff check src/ tests/ scripts/`. Esperado: todo verde, sin romper los tests que indexan por `kind`.

- [ ] **Paso 5: Commit** `feat(deploy): prueba del despliegue con helm test`.

### Tarea 2: Elegir versión y esperar la publicación

**Files:**
- Create: `deploy/jenkins/elegir_version.sh`, `deploy/jenkins/comprobar_publicada.sh`
- Test: `tests/test_jenkins.py`

**Interfaces:**
- Produces:
  - `elegir_version.sh <desplegada> <archivo_fallidas>`: lee tags por stdin; imprime `X.Y.Z` o nada; sale 0. Sale 2 si `<desplegada>` está vacía o el archivo no existe.
  - `comprobar_publicada.sh <X.Y.Z>`: sale 0 si existen la release de GitHub y el tag en GHCR; 1 si no o ante cualquier error de red. Repo e imagen en variables `REPO_GITHUB` e `IMAGEN_GHCR`, con los valores reales por defecto.

- [ ] **Paso 1: Tests que fallan**

Patrón de `_ejecutar_subir` en `test_helm.py`: `sh` real, `curl` falso en `PATH`, se saltan sin `sh`.

```python
@pytest.mark.parametrize("tags, desplegada, fallidas, esperada", [
    ("v1.4.0\nv1.5.0\n", "1.4.0", "", "1.5.0"),
    ("v1.9.0\nv1.10.0\n", "1.9.0", "", "1.10.0"),
    ("v1.4.0\n", "1.4.0", "", ""),
    ("v1.3.0\n", "1.4.0", "", ""),
    ("v1.5.0\n", "1.4.0", "1.5.0\n", ""),
    ("v1.5.0\nv1.6.0\n", "1.4.0", "1.6.0\n", "1.5.0"),
    ("v1.5.0-rc1\nv1.5\nrelease-1\n", "1.4.0", "", ""),
    ("", "1.4.0", "", ""),
])
def test_elegir_version(tags, desplegada, fallidas, esperada, tmp_path): ...

def test_elegir_version_sin_desplegada_es_error(tmp_path): ...       # código 2
def test_elegir_version_sin_archivo_de_fallidas_es_error(tmp_path): ...  # código 2

@pytest.mark.parametrize("release, ghcr, codigo", [
    (200, 200, 0), (404, 200, 1), (200, 404, 1), (500, 200, 1), (403, 200, 1), (200, 503, 1),
])
def test_comprobar_publicada(release, ghcr, codigo, tmp_path): ...
```

- [ ] **Paso 2: Comprobar que fallan.** `.venv/Scripts/pytest tests/test_jenkins.py -v`.

- [ ] **Paso 3: Implementar**

`elegir_version.sh`: filtro `grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$'`, quita las fallidas, ordena con `sort -V`, y devuelve la mayor si, ordenada con la desplegada, queda por encima. `comprobar_publicada.sh`: `curl -s -o /dev/null -w '%{http_code}'` a `https://api.github.com/repos/$REPO_GITHUB/releases/tags/vX.Y.Z`; token anónimo de `https://ghcr.io/token?scope=repository:$IMAGEN_GHCR:pull`; `HEAD /v2/$IMAGEN_GHCR/manifests/X.Y.Z` con `Accept` de índice OCI y de manifest list.

- [ ] **Paso 4: Comprobar.** `.venv/Scripts/pytest tests/test_jenkins.py -v`. Esperado: PASS.

- [ ] **Paso 5: Commit** `feat(deploy): elegir versión a desplegar y comprobar que está publicada`.

### Tarea 3: Desplegar, probar, volver atrás y avisar

**Files:**
- Create: `deploy/jenkins/desplegar.sh`, `deploy/jenkins/avisar.sh`
- Test: `tests/test_jenkins.py`

**Interfaces:**
- Consumes: los scripts de la Tarea 2; Secret `topology-scanner-values` (clave `values.yaml`); Pod de la Tarea 1; valor `pruebas.versionEsperada`.
- Produces:
  - `avisar.sh <asunto> <cuerpo>`: `aws sns publish` a `$TOPIC_ARN`. Sale con el código de `aws`.
  - `desplegar.sh`, por entorno: `MODO` (`automatico`|`manual`), `VERSION` (manual; vacía = la desplegada), `ENSAYO` (`ninguno`|`no-arranca`|`falla-prueba`), `URL_EJECUCION`, `ESPERA_SEGUNDOS` (por defecto 3600). Códigos: 0 OK o nada que hacer; 1 fallo con rollback correcto; 3 fallo con rollback fallido.
  - ConfigMap `estado-despliegue` en el namespace `jenkins`, clave `fallidas`, una versión por línea.

- [ ] **Paso 1: Tests que fallan**

`helm`, `kubectl`, `git`, `aws` y `comprobar_publicada.sh` falsos: registran sus argumentos en un archivo y responden según variables del test.

- `test_automatico_sin_version_nueva_no_despliega`: ninguna llamada a `helm upgrade`, sin email.
- `test_automatico_camino_feliz`: orden `upgrade` → `test`; `--set image.tag=X.Y.Z` después de `-f`; chart del `git clone --branch vX.Y.Z`; sin email.
- `test_falla_upgrade_vuelve_atras_marca_y_avisa`: `rollback` y `test`, patch del ConfigMap con la versión, un email, código 1.
- `test_falla_helm_test_vuelve_atras_marca_y_avisa`: igual.
- `test_helm_test_sin_pruebas_es_fallo`: `helm test` sale 0 sin ninguna fase `Succeeded` en su salida; se trata como fallo.
- `test_imagen_distinta_de_la_version_es_fallo`: tras `helm test`, la imagen de la web o del escaneo (en el CronJob va en `containers` o en `initContainers`, según `aws.enabled`) no termina en `:X.Y.Z`; rollback, marca y email.
- `test_email_de_rollback_lleva_advertencia_de_historial`: el cuerpo enlaza `04-aws.md` e incluye versión, paso y `URL_EJECUCION`, sin IPs.
- `test_rollback_fallido_email_urgente`: asunto con `URGENT`, código 3.
- `test_sns_caido_no_oculta_el_fallo`: `aws` falla; el rollback ya está hecho, el motivo sale por stderr y el código es 1.
- `test_lectura_de_estado_fallida_no_despliega`: `kubectl` falla; sin `upgrade`, sin marca, código distinto de 0.
- `test_sin_publicar_tras_la_espera_marca_y_avisa`: `ESPERA_SEGUNDOS=0`; sin `upgrade`, marca, un email.
- `test_manual_sin_version_redespliega_la_actual`: chart del tag de la desplegada; no compara si es mayor; sin esperar a la publicación.
- `test_manual_redespliegue_fallido_no_marca`: rollback y email, sin marca.
- `test_manual_con_version_fallida_la_despliega_y_quita_la_marca`.
- `test_ensayos_solo_en_manual`: `MODO=automatico ENSAYO=no-arranca` termina con error sin desplegar.
- `test_ensayo_no_arranca`: `--set image.tag=0.0.0-ensayo-no-existe`; no marca ninguna versión.
- `test_ensayo_falla_prueba`: versión actual y `--set pruebas.versionEsperada=0.0.0-ensayo`; no marca ninguna versión.

- [ ] **Paso 2: Comprobar que fallan.** `.venv/Scripts/pytest tests/test_jenkins.py -v`.

- [ ] **Paso 3: Implementar**

La versión desplegada sale de `kubectl -n topology-scanner get deploy topology-scanner-web -o jsonpath='{.metadata.labels.app\.kubernetes\.io/version}'`. Los values, de `kubectl get secret topology-scanner-values` a un archivo de `mktemp` que se borra con `trap`. `helm upgrade --wait --timeout 5m`; `helm test --timeout 10m --logs`; `helm rollback topology-scanner 0 --wait --timeout 5m`. Comprobar la frase real de una prueba correcta contra `helm test` de Helm 4 en la Tarea 7, y ajustar el falso si difiere. Espera: bucle de `comprobar_publicada.sh` cada 60 s hasta `ESPERA_SEGUNDOS` (por defecto 3600). Textos de email en inglés, como los de hallazgos, con asunto `topology-scanner deploy FAILED: X.Y.Z` o `URGENT topology-scanner rollback FAILED: X.Y.Z`. La marca se guarda antes de avisar: un SNS caído no puede provocar otro intento.

- [ ] **Paso 4: Comprobar.** `.venv/Scripts/pytest tests/test_jenkins.py -v`. Esperado: PASS.

- [ ] **Paso 5: Commit** `feat(deploy): despliegue con prueba, marcha atrás y aviso`.

### Tarea 4: Jenkins como código

**Files:**
- Create: `Jenkinsfile`, `deploy/jenkins/sondear.Jenkinsfile`, `deploy/jenkins/values.yaml`, `deploy/jenkins/values.example.yaml`, `deploy/jenkins/rbac.yaml`, `deploy/jenkins/.gitignore`
- Modify: `.github/workflows/ci.yml` (job `helm`)
- Test: `tests/test_jenkins.py`, `tests/test_workflows.py`

**Interfaces:**
- Consumes: `deploy/jenkins/desplegar.sh`. Secrets a mano en el namespace `jenkins`: `jenkins-admin` (usuario y contraseña) y `jenkins-avisos` (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `TOPIC_ARN`).
- Produces: jobs `desplegar` (parámetros `MODO`, `VERSION`, `ENSAYO`; `disableConcurrentBuilds`; conserva 100 ejecuciones) y `sondear` (`H/5 * * * *`; conserva 20). `ServiceAccount` `jenkins-agente` en `jenkins`.

- [ ] **Paso 1: Elegir versiones fijas y comprobar la imagen del agente**

Con versiones publicadas hace unos días: chart `jenkins/jenkins`, plugins (kubernetes, workflow-aggregator, git, job-dsl, configuration-as-code) e imagen del agente. Candidata: `alpine/k8s`. Por digest, comprobar en `docker-lab` que trae `helm` **de la versión mayor 4** (la que creó el release), `kubectl`, `git`, `curl`, `aws` y `sort -V`, y que corre como no root. Si no cumple, se elige otra y se anota el motivo.

- [ ] **Paso 2: Tests que fallan**

Leyendo `deploy/jenkins/values.yaml` y `rbac.yaml` con `yaml.safe_load`, sin red ni repo de Helm:

- `test_jenkins_sin_acceso_anonimo`: `allowAnonymousRead: false` y sin `unsecured`.
- `test_controlador_sin_ejecutores`: `numExecutors: 0`.
- `test_limite_de_memoria_del_controlador`: `2Gi`.
- `test_imagenes_de_jenkins_por_digest`, `test_plugins_con_version_fija`.
- `test_rbac_sin_cluster_admin`: `rbac.yaml` no contiene `ClusterRole` ni `ClusterRoleBinding`; un `Role` por namespace; en `jenkins` solo `get` y `patch` de ConfigMaps con `resourceNames: [estado-despliegue]`; el ConfigMap va en el mismo archivo, sin `data`, para que un `apply` no borre las marcas.
- `test_jenkinsfile_llama_al_script`: `Jenkinsfile` contiene `desplegar.sh`, sin `helm upgrade`.
- `test_sondear_solo_lanza_en_automatico`: `MODO=automatico`, `wait: false`.
- `test_la_ci_valida_los_valores_de_jenkins` en `test_workflows.py`.

- [ ] **Paso 3: Comprobar que fallan.** `.venv/Scripts/pytest tests/test_jenkins.py tests/test_workflows.py -v`.

- [ ] **Paso 4: Implementar**

- `sondear`: `git ls-remote --tags`, `elegir_version.sh` y, si hay versión, `build job: 'desplegar', parameters: MODO=automatico, wait: false`. `desplegar` vuelve a elegir: así una ejecución duplicada de la cola termina sin hacer nada. Agente con límite de 128 MiB.
- `Jenkinsfile`: agente con imagen por digest y `jenkins-agente`; `withEnv` con los valores de `jenkins-avisos`; `sh 'deploy/jenkins/desplegar.sh'`. Límite del agente: 256 MiB.
- JCasC: seguridad local con `jenkins-admin`, sin anónimos, 0 ejecutores, cloud de Kubernetes, y los dos jobs con job-dsl, `Pipeline from SCM` contra `main` (`lightweight`).
- `rbac.yaml`: `Role` en `topology-scanner` con los recursos del chart (`deployments`, `cronjobs`, `configmaps`, `persistentvolumeclaims`, `pods`, `pods/log`, `secrets`, `events`) y `Role` en `jenkins` para el ConfigMap.
- Exposición: `NodePort` fijo en `values.yaml`, para que NPM apunte a la IP del nodo. El dominio, en `values.local.yaml`, ignorado por `deploy/jenkins/.gitignore`.
- `ci.yml`: `helm repo add`/`helm template` con `deploy/jenkins/values.example.yaml`.

- [ ] **Paso 5: Comprobar.** `.venv/Scripts/pytest tests/ -q` y ruff. Esperado: todo verde.

- [ ] **Paso 6: Commit** `feat(deploy): Jenkins como código (JCasC, pipelines y permisos)`.

### Tarea 5: Usuario IAM de Jenkins

**Files:**
- Modify: `infra/aws/hallazgos/iam.tf`, `infra/aws/hallazgos/outputs.tf`
- Test: `infra/aws/hallazgos/tests/hallazgos.tftest.hcl`

**Interfaces:**
- Produces: usuario IAM `topology-scanner-jenkins` y output con su nombre. La clave se crea a mano en la Tarea 7.

- [ ] **Paso 1: Test que falla.** Bloque `run` en el `tftest`: el usuario existe y su política tiene una sola sentencia, `sns:Publish` sobre el ARN del topic.
- [ ] **Paso 2: Comprobar que falla.** `cd infra/aws/hallazgos && terraform init -backend=false && terraform test`.
- [ ] **Paso 3: Implementar.** `aws_iam_user.jenkins` y `aws_iam_user_policy.jenkins`, con `local.politica_jenkins`, junto a los del homelab.
- [ ] **Paso 4: Comprobar.** `terraform fmt -check -recursive infra/`, `terraform validate`, `terraform test`, y `.venv/Scripts/pytest tests/test_workflows.py -q` (ninguna clave en `.tf`).
- [ ] **Paso 5: Commit** `feat(infra): usuario IAM de Jenkins, solo para avisar por SNS`.

### Tarea 6: PR de las tareas 1-5, sin tag todavía

Solo con la aprobación del mantenedor para hacer push.

- [ ] **Paso 1:** Preparar v1.4.1: `pyproject.toml`, `CHANGELOG.md`, `image.tag`, `appVersion` y `version` del chart (0.3.0). `test_chart_e_imagen_coinciden_con_pyproject` en verde. Commit `release: v1.4.1`.
- [ ] **Paso 2:** Push de `fase-5-jenkins` y PR. Esperado: CI verde y comentario de plan con **solo** el usuario y la política nuevos.
- [ ] **Paso 3 (mantenedor):** Mergear y aprobar el apply en el environment `aws`. **No crear el tag**: tiene que llegar con Jenkins ya funcionando (Tarea 7).

### Tarea 7: Instalación y primer despliegue real

En una rama nueva, `fase-5-instalacion`, para lo que salga.

- [ ] **Paso 1:** Medir disco y memoria de la VM. Esperado: espacio para el PVC de Jenkins (8 GiB) y margen. Si no lo hay, parar y consultar.
- [ ] **Paso 2 (mantenedor):** Crear en AWS la clave de `topology-scanner-jenkins` (archivo con LF, fuera del repo) y los Secrets `jenkins-admin` y `jenkins-avisos`. Claude comprueba longitudes sin ver valores, como en `04-aws.md`.
- [ ] **Paso 3 (mantenedor):** `kubectl -n topology-scanner create secret generic topology-scanner-values --from-file=values.yaml=deploy/helm/values.local.yaml`.
- [ ] **Paso 4 (mantenedor):** `kubectl apply -f deploy/jenkins/rbac.yaml` y `helm install` de Jenkins. Esperado: controlador `Ready`, los dos jobs creados por JCasC y login sin anónimo. Medir la memoria y ajustar el límite si hace falta.
- [ ] **Paso 5 (mantenedor):** Entrada en NPM con HTTPS y solo LAN. Comprobar que desde fuera de la LAN no responde.
- [ ] **Paso 6:** Con `sondear` activo y sin tags nuevos: tres sondeos sin ninguna ejecución de `desplegar`.
- [ ] **Paso 7 (mantenedor):** `git tag v1.4.1 && git push origin v1.4.1`. Esperado: espera hasta que la release se publica, despliega y `helm test` en verde, sin intervención.
- [ ] **Paso 8:** Ejecutar `helm test` a mano sobre la revisión y comprobar en el historial que no se ha añadido ninguna ejecución y que no ha llegado ningún email.

### Tarea 8: Ensayos

Partiendo de v1.4.1 desplegada. Lo lanza el mantenedor; Claude revisa.

- [ ] **Paso 1 (ensayo 1):** `desplegar` manual con `ENSAYO=no-arranca`. Esperado: falla el upgrade, rollback, email con advertencia, web funcionando en 1.4.1.
- [ ] **Paso 2 (ensayo 2):** `ENSAYO=falla-prueba`. Esperado: upgrade correcto, falla `helm test`, rollback, email.
- [ ] **Paso 3 (ensayo 3):** `git tag v1.4.99 && git push origin v1.4.99`. `release.yml` tiene que cortarlo sin publicar: comprobar PyPI y GHCR. Tras 60 minutos, **un** email; los sondeos siguientes no hacen nada. Borrar el tag local y remoto, y quitar `1.4.99` del ConfigMap.
- [ ] **Paso 4 (reconstrucción):** `helm uninstall jenkins`, borrar el PVC de Jenkins y reinstalar desde el repo. Esperado: jobs de vuelta sin tocar la interfaz y un despliegue manual correcto.
- [ ] **Paso 5:** Anotar los resultados para el runbook.

### Tarea 9: Filtro de ruido y v1.5.0 (el camino feliz)

**Files:**
- Modify: `src/topology_scanner/history.py`, `src/topology_scanner/cli.py`, `pyproject.toml`, `CHANGELOG.md`, chart (`image.tag`, `appVersion`, `version`)
- Test: `tests/test_history.py`, `tests/test_cli.py`

**Interfaces:**
- Produces: clave `hosts_nunca_vistos: list[str]` en cada diff de `registrar_ejecucion`; `history.merece_aviso(diff: dict, resultados: dict) -> bool`.

- [ ] **Paso 1: Tests que fallan**

Con datos inventados de `192.0.2.0/24`:

- `test_nunca_visto_al_aparecer_por_primera_vez`.
- `test_host_que_vuelve_no_es_nunca_visto`: A, B, A → en el tercero `hosts_nuevos` sí lo trae, `hosts_nunca_vistos` no.
- `test_nunca_visto_es_por_rango`: la IP vista en otro rango cuenta como nunca vista en este.
- `test_nunca_visto_antes_de_purgar`: con `mantener_ultimos=2`, escaneos {A}, {B}, {A}: en el tercero se purga el primero, y A no cuenta como nunca visto.
- `test_primera_vez_sin_nunca_vistos`.
- `@pytest.mark.parametrize` de `merece_aviso`: nunca visto con puertos → True; sin puertos → False; que vuelve con puertos → False; solo caídos → False; `puertos_cambiados` → True; diff sin la clave → False si no hay cambios de puertos.
- `test_hay_cambios_no_cambia`: un diff con solo un host caído sigue dando True.
- `test_changes_dir_no_escribe_sin_motivo` y `test_changes_dir_incluye_todos_los_cambios_si_avisa` (en `test_cli.py`).

- [ ] **Paso 2: Comprobar que fallan.** `.venv/Scripts/pytest tests/test_history.py tests/test_cli.py -v`.

- [ ] **Paso 3: Implementar.** `_comparar` y `hay_cambios` no se tocan. En `registrar_ejecucion`, antes de `_guardar_escaneo`: consulta sobre `hosts` + `escaneos` del rango, y la clave nueva en el diff (vacía si `primera_vez`). `merece_aviso` es una función pura. `_escribir_cambios` sale sin escribir si ningún diff lo merece.

- [ ] **Paso 4: Comprobar.** `.venv/Scripts/pytest tests/ -q` y ruff. Esperado: todo verde. Una búsqueda de `diff ==` no encontró tests que comparen el diff completo; si alguno falla por la clave nueva, se ajusta ese test.

- [ ] **Paso 5: Commits** `feat(history): avisar solo de hosts nunca vistos con puertos o de cambios de puertos` y `release: v1.5.0`.

- [ ] **Paso 6 (mantenedor):** PR, merge, `git tag v1.5.0 && git push origin v1.5.0`. Esperado: Jenkins lo despliega sin intervención, y el nocturno siguiente corre con 1.5.0 (`kubectl logs`) y solo avisa si se cumple la regla.

### Tarea 10: Documentación

**Files:**
- Create: `docs/devops/runbooks/05-jenkins.md`
- Modify: `docs/devops/runbooks/03-kubernetes.md`, `docs/devops/runbooks/04-aws.md`, `docs/devops/README.md`, `docs/decisiones.md`, `CLAUDE.md`, `README.md`

- [ ] **Paso 1:** `05-jenkins.md`: instalación, Secrets, NPM, rotar la clave, reintentar una versión, quitar una marca, ensayos con sus resultados y tropiezos reales. Avisar de las versiones que cambian el esquema.
- [ ] **Paso 2:** `03-kubernetes.md`: cambiar valores = actualizar el Secret y relanzar `desplegar`; `helm upgrade` desde el PC solo como emergencia. `04-aws.md`: usuario de Jenkins y nueva regla de avisos.
- [ ] **Paso 3:** `decisiones.md`: las de esta fase, con el acceso de Jenkins a los Secrets dejado por escrito. `docs/devops/README.md`: fase 5 Hecha. `CLAUDE.md`: estructura, comandos, `history.merece_aviso` como fuente única. `README.md`: mención breve en inglés.
- [ ] **Paso 4:** `.venv/Scripts/pytest tests/ -q` y ruff, y comprobar con `git grep` que no se ha colado ninguna IP real ni el dominio. Commit `docs: runbook de la fase 5 y decisiones`.
- [ ] **Paso 5 (mantenedor):** PR y merge. Fase 5 cerrada.
