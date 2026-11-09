# Fase 5: Jenkins (CD), diseño

Continúa [`2026-10-22-fase-devops-design.md`](2026-10-22-fase-devops-design.md).
Aquí se concreta lo que aquel documento dejaba abierto y se corrige lo que la
instalación real ha cambiado desde entonces.

## Intención

Hoy, sacar una versión termina con el mantenedor lanzando `helm upgrade` desde
su PC. Esta fase hace que un tag nuevo llegue solo al clúster, **se compruebe que
funciona y vuelva a la versión anterior si no funciona**, avisando por email.

Es pieza de portfolio para un rol DevOps. Tiene que poder responder en una
entrevista a "¿y qué pasa si el despliegue sale mal?" enseñándolo en directo, y
justificar por qué hay dos herramientas: GitHub Actions corre en la nube y no
llega a la LAN; Jenkins vive dentro y mira hacia fuera, sin abrir ningún puerto.

## Objetivos

1. Jenkins en k3s, instalado con Helm y configurado como código (JCasC y
   `Jenkinsfile`): si se rompe la VM, se reconstruye desde el repo.
2. Un tag `vX.Y.Z` con su release completa acaba desplegado sin intervención.
3. Tras cada despliegue, una prueba real. Si falla, marcha atrás automática.
4. Si un despliegue falla, vuelve atrás o se queda a medias, llega un email.
5. Demostrable: los dos caminos de fallo se ensayan de verdad.
6. Primer cambio real por el pipeline: el filtro de ruido de los avisos (v1.5.0).
7. Documentación: runbook `05-jenkins.md`, `decisiones.md`, README de DevOps y `CLAUDE.md`.

## No-objetivos

- **Entorno de staging.** Descartado por el mantenedor: con un solo nodo y
  `hostNetwork` demostraría poco y es lo que más memoria gasta. Se puede añadir
  después sin rehacer nada.
- **Aprobación manual antes de producción.** Decisión del mantenedor: despliegue
  automático, con la marcha atrás como red de seguridad.
- Jenkins no construye imágenes ni ejecuta tests: eso sigue en GitHub Actions.
- Jenkins no despliega su propio chart ni el de la infraestructura: se actualizan
  a mano desde el PC.
- Sin webhooks ni nada expuesto a internet.
- Telegram y métricas del pipeline: fase 6.

## Anti-objetivos (fallaría aunque técnicamente funcione)

- Un despliegue fallido que se reintenta en bucle y llena el buzón.
- Una prueba que modifica el historial, sube informes o manda el email de cambios.
- Publicar una versión rota a propósito en PyPI o en `latest` para hacer la demo.
- Jenkins con permisos de `cluster-admin`, o sin contraseña en la LAN.
- Que el pipeline escanee algo más que el propio nodo.

## Decisiones del mantenedor

- Alcance: despliegue con verificación y marcha atrás (la opción "B" de las
  tres que se le plantearon).
- Despliegue automático, sin aprobación.
- Aviso de fallo por el **mismo email** de los hallazgos (SNS).
- Primer cambio real: el filtro de ruido, después de que funcione el pipeline.
- Jenkins en el clúster: lo decía el diseño de octubre y se ha confirmado que
  cabe (2026-11-09: 1,4 GiB en uso de 7,75 GiB; disco libre sin medir todavía).

## Flujo

```
git tag vX.Y.Z ─► release.yml (GitHub Actions): tests, PyPI, GHCR, release
                                                     │
                 Jenkins sondea GitHub cada 5 min ◄──┘ (sale de la LAN, nada entra)
                     │
   1. ¿Hay versión nueva y no marcada como fallida?  no ─► fin (sin email)
   2. ¿Está la release de GitHub y la imagen en GHCR? no, tras 60 min ─► email + marca
   3. helm upgrade --wait con el chart del tag y los values del Secret
   4. helm test (prueba real)
        ├─ OK ─► fin
        └─ fallo en 3 o 4 ─► helm rollback ─► marca como fallida ─► email
                                 └─ el rollback también falla ─► email urgente
```

### Paso 1: qué versión desplegar

- Solo tags con la forma exacta `vX.Y.Z`. Se desplegaría la mayor por versión
  semántica, y solo si es mayor que la desplegada (`helm list`/`helm get`). Nunca
  hacia atrás de forma automática.
- **Una versión fallida no se reintenta sola.** Si no, cada sondeo la desplegaría
  otra vez, con su rollback y su email. Se reintenta con un tag nuevo o lanzando
  el job a mano.
- El registro de versiones fallidas puede vivir en `JENKINS_HOME`. Si se pierde al
  reconstruir, el coste es un intento y un email más: aceptable.
- Un sondeo sin nada que hacer no deja ruido ni consume un agente caro.
- La lógica de elegir versión va en un script con tests (mayor, fallida, prerrelease,
  sin tags), como `files/subir.sh`: es la parte que peor se ensaya en vivo.

**Ejecución manual** (decisión del constructor). Un único parámetro `VERSION`:

- Vacío: vuelve a desplegar **la versión ya desplegada**, con el chart de su tag y los
  values actuales del Secret. Es lo que hace efectivo cambiar un rango.
- Con valor: despliega esa versión, aunque sea menor o esté marcada como fallida. Si
  sale bien, se le quita la marca.
- Mismo camino que el automático, con prueba, rollback y email. Si falla un redespliegue
  de la versión que ya corría, **no** se marca como fallida: el problema son los values.

### Paso 2: por qué no basta con el tag

El tag aparece en GitHub **antes** que la imagen, y si los tests fallan la imagen
nunca llega. La señal de "publicada" es la release de GitHub, que `release.yml`
crea la última, solo con PyPI y la imagen ya publicadas. Se comprueba además que
el tag `X.Y.Z` exista en GHCR. Se espera hasta 60 minutos (la imagen multiarquitectura
tarda). Si se agota: email, y la versión queda marcada como fallida.

### Paso 3: despliegue

- Chart: el del commit del tag, no el de `main`.
- `Jenkinsfile`: el de `main`, para poder arreglar el pipeline sin sacar versión.
- Values: del Secret `topology-scanner-values` (ver "Valores reales").
- La imagen la fija `image.tag` del chart del tag. **Los values reales no pueden
  sobrescribir `image.tag`**, y hoy nada garantiza que `image.tag` coincida con
  `pyproject.toml`: hay que añadir un test de coherencia, que en CI impida sacar
  una versión cuyo chart despliegue otra imagen.
- Un upgrade no mata un escaneo en curso: el Job nocturno que ya esté corriendo
  sigue con la imagen anterior. No hace falta evitar las 3:00.

### Paso 4: la prueba real

Con `helm test` (pods con el hook `test` en el chart, la forma estándar de Helm).
No se usa `kubectl create job --from=cronjob` porque tiene efectos: escribiría
una ejecución en el historial, movería la base de comparación, subiría a S3 y
podría mandar el email de cambios. La prueba comprueba:

1. **Versión:** `topology-scanner --version` es la esperada, y la imagen de la web
   y del CronJob es la del tag.
2. **Web:** `/_stcore/health` responde a través del puerto del nodo.
3. **Escaneo:** nmap con las mismas capacidades y usuario que el CronJob, contra
   **la IP del propio nodo únicamente**, con `--fast --no-history`, y sin montar el
   PVC. Tiene que terminar bien y encontrar al menos un host: así se detecta una
   imagen que arranca pero no sabe escanear (por ejemplo, sin `setcap`).

No prueba SNMP ni la subida a AWS: requerirían credenciales reales y tienen efectos.
Un fallo ahí no aparece hasta el nocturno, y lo cubrirá la fase 6. Limitación aceptada.

### Marcha atrás y sus límites

- `helm rollback` a la revisión anterior, con `--wait`. Se comprueba con `helm test`
  de nuevo. Si la vuelta también falla, el email lo deja claro: hace falta intervenir.
- **`helm test` sin ninguna prueba cuenta como fallo.** Si no, una revisión sin hooks
  daría un verde que no comprueba nada. Por eso los hooks llegan en una versión propia
  antes de los ensayos (ver "Ensayos").
- **Helm no devuelve los datos atrás.** `history.py` migra el esquema al abrir la
  base, así que una versión con esquema nuevo deja el historial en un formato que
  la anterior puede no entender. La prueba no monta el PVC, así que no lo detectaría:
  aparecería en el nocturno. Limitación aceptada (decisión del constructor): el rollback
  sigue siendo automático y **todo email de rollback lleva una advertencia fija** que lo
  explica y enlaza la restauración de `04-aws.md`, con su copia nocturna en S3. No se
  añade copia previa ni detección de esquema: las migraciones son raras y añadirían
  permisos sobre el PVC y estados nuevos al pipeline.

## Valores reales

Hoy están en `deploy/helm/values.local.yaml`, en el PC. El diseño de octubre
preveía un Secret `topology-scanner-values` que no se llegó a crear. Se crea ahora,
a mano, desde ese archivo, y **pasa a ser la fuente de verdad**: cambiar un rango
es actualizar el Secret y relanzar el pipeline. Así se evita que el PC y el clúster
diverjan. El runbook de la fase 3 se actualiza en consecuencia.

Siguen fuera del chart los Secrets de SNMP y AWS: no pasan por los values.

## Jenkins

- Namespace `jenkins`, chart oficial con versión fijada. Configuración en
  `deploy/jenkins/` y `Jenkinsfile` en la raíz.
- Valores reales (dominio) en un archivo ignorado por git, como en el chart principal.
- Agentes como pods efímeros (plugin de Kubernetes), con imagen fijada por digest que
  traiga Helm y kubectl. Sin ejecutores en el controlador.
- Plugins con versión fijada. Imágenes de terceros por digest (misma regla que aws-cli).
- Límite de memoria inicial del controlador: 2 GiB, para ajustar con lo que se mida.
  Comprobar que sobra sitio para el escaneo (hasta 1 GiB) y la fase 6.
- Disco: PVC `local-path`. Medir antes el disco libre de la VM.
- Acceso: **solo LAN**, HTTPS por NPM, igual que la web.
- Sin acceso anónimo: usuario administrador con contraseña en un Secret creado a mano.

### Permisos

Cuenta de servicio del agente con un `Role` **solo en el namespace
`topology-scanner`**, con lo mínimo que necesite Helm: el recurso de cada plantilla,
pods y logs, y `secrets`, porque Helm guarda ahí sus revisiones. Eso permite leer los
Secrets de SNMP y AWS de ese namespace: es inevitable con Helm y por eso Jenkins va
con contraseña y solo en la LAN. Hay que dejarlo escrito en `decisiones.md`, no ocultarlo.

### Aviso por email

Mismo topic SNS, por lo tanto mismo email. **Usuario IAM nuevo**
(`topology-scanner-jenkins`) con solo `sns:Publish` sobre ese topic. No se reutiliza el
del homelab porque puede escribir en S3, y Jenkins no lo necesita. Se añade en
`infra/aws/hallazgos/` y entra por `terraform-aws.yml` (plan en el PR, apply con
aprobación). La clave se crea a mano, nunca en Terraform (ya lo comprueba un test).

El asunto distingue el aviso de los de hallazgos. El cuerpo lleva versión, paso que
falló, estado final y enlace a la ejecución. Sin IPs ni rangos. Los despliegues
correctos no mandan email.

## Filtro de ruido en los avisos

Motivo: las tres primeras noches avisaron por equipos domésticos que entran y salen
de la red. Un aviso diario se acaba ignorando.

Regla (el mantenedor eligió "nunca visto" frente a comparar solo con la noche anterior):
el email sale solo si hay **un host nunca visto con algún puerto abierto** o **un cambio
de puertos**. Dejan de avisar los hosts que caen, los que no tienen puertos y los que ya
se conocían y vuelven tras faltar alguna noche.

- "Nunca visto" = la IP no aparece en ningún escaneo guardado **de ese rango**, sin
  contar el de esta pasada. Hay que comprobarlo antes de que la purga borre lo antiguo.
- `history.hay_cambios` y `_comparar` no cambian: el diff sigue siendo contra el escaneo
  anterior, y la web y el historial siguen mostrándolo todo. La regla es una función
  nueva en `history.py` para decidir el aviso, y es la que usa `--changes-dir`.
- `files/subir.sh` no cambia: sigue avisando si existe `cambios.json`.
- Si el email sale, muestra todos los cambios (también caídos y hosts sin puertos), como
  hoy: es el contexto para entender el aviso.
- Se pierde a sabiendas: un equipo nuevo sin puertos no avisa, ni un equipo importante
  que cae. Siguen en el inventario y el historial. Una lista de equipos críticos queda
  como idea para después.
- Límites aceptados: el historial identifica por IP, así que un equipo conocido con una
  IP nunca vista sí avisa; y `mantener_ultimos` (50) marca la memoria, así que quien lleve
  más de 50 escaneos sin aparecer cuenta como nunca visto. Un equipo conocido que vuelve
  con puertos distintos no avisa, porque no hay escaneo anterior con el que comparar.
- Filtrar por MAC no sirve: en los rangos detrás de un router nmap no ve la MAC.

## Ensayos (criterio de éxito de la fase)

**Nunca con una versión rota publicada**: PyPI no permite volver a subir una versión y
la imagen pasaría a `latest`.

**Punto de partida: v1.4.1** (decisión del constructor). Ningún tag trae hoy los hooks
de `helm test`, así que hace falta una versión que solo añada los hooks y el test de
coherencia del chart. Es el primer despliegue real por el pipeline, y deja una revisión
con pruebas a la que volver. Solo en este primer paso la revisión anterior (1.4.0) no
tiene hooks; si fallara, se trata a mano. v1.5.0 sigue siendo el primer cambio funcional.

Los ensayos 1 y 2 usan una ejecución manual con un parámetro de ensayo que sustituye la
imagen, **con el chart del tag desplegado**: es la misma ruta que un despliegue real.
No existe en los sondeos automáticos. Se tiene que ver:

1. **Falla el despliegue:** una imagen que no arranca. `helm upgrade --wait` falla,
   rollback, email, y la web sigue funcionando con la versión anterior.
2. **Falla la prueba:** una imagen que arranca pero no escanea (o valores equivalentes).
   Upgrade correcto, `helm test` falla, rollback, email.
3. **Una versión fallida no se reintenta:** un tag de ensayo (`v1.4.99`) que no coincide
   con `pyproject.toml`, así que `release.yml` lo corta antes de publicar nada. Se agota
   la espera del paso 2, llega **un** email, y los sondeos siguientes no hacen nada. Luego
   se borra el tag. Es el único tag de ensayo permitido, y no publica nada.
4. **Camino feliz:** v1.5.0 con el filtro de ruido, un tag real, desplegado sin
   intervención. El nocturno siguiente corre con esa versión.
5. **Reconstrucción:** borrar el Jenkins instalado y volver a instalarlo desde el repo
   deja el pipeline funcionando igual.

## Reparto del trabajo

Claude hace la mayor parte y explica. A mano, supervisado, el mantenedor: la instalación
de Jenkins con Helm, los Secrets (Claude nunca ve valores secretos), la clave IAM, la
entrada en NPM, y lanzar los ensayos.

## Lo que se deja al constructor

- Tipo de job y mecanismo de sondeo (mientras cumpla las reglas del paso 1).
- Cómo inyecta la ejecución manual los parámetros de ensayo, y qué imagen se usa.
- Versiones exactas de chart, plugins e imágenes (publicadas hace unos días, no recién salidas).
- Cómo se expone Jenkins a NPM (`NodePort`, ServiceLB…).
- Cómo validar en CI el `Jenkinsfile` y los valores de Jenkins, y dónde encaja en el job
  `helm`. Tiene que seguir la regla de versiones fijadas de `tests/test_workflows.py`.
- Orden de las tareas, con el filtro de ruido al final por exigencia del objetivo 6.
