# Fase 4 — AWS como código + hallazgos (diseño)

Concreta la fila "4 | AWS como código + hallazgos" del diseño general
([`2026-10-22-fase-devops-design.md`](2026-10-22-fase-devops-design.md)), sobre
lo que dejó la fase 3: el CronJob nocturno en el k3s de casa, con historial en
un PVC.

## Para qué

Hoy los cambios de la red solo se ven si alguien abre la web. Con esta fase:

- **Un email por la mañana cuando algo ha cambiado** en la red (hosts nuevos
  o desaparecidos, puertos que se abren o cierran), con lo sensible primero y
  enlaces para abrir el mapa y el CSV de esa noche desde el móvil.
- **El historial no se pierde si muere el MiniPC**: copia en S3 después de
  cada escaneo, y una restauración probada de verdad siguiendo un runbook.
- **La infraestructura de AWS se cambia por PR**: `plan` en el PR, `apply` en
  GitHub Actions al mergear, con aprobación del mantenedor y sin claves de AWS
  en GitHub.

Éxito: el mantenedor enciende un dispositivo nuevo en casa, y a la mañana
siguiente tiene un email que lo dice y desde el que abre el mapa. Borra el
volumen del historial, lo restaura siguiendo el runbook, y la web vuelve a
mostrar las ejecuciones de antes.

## Objetivos

1. **Cambios en la app** (genéricos, sin nada de AWS):
   - Un flag del CLI que escribe los cambios de la ejecución **solo si los
     hay** (`history.hay_cambios`): un JSON con los diffs y un texto listo
     para el email (asunto y cuerpo).
   - Un flag del CLI que deja una **copia consistente** del historial en una
     ruta dada.
2. **Release v1.4.0** con esos cambios, porque el clúster usa la imagen
   publicada.
3. **Terraform de AWS** en una raíz nueva de `infra/aws/`: bucket de informes,
   topic SNS con suscripción email, usuario IAM del homelab, proveedor OIDC de
   GitHub y dos roles (plan y apply).
4. **Workflow de GitHub Actions** para ese Terraform: `plan` en PRs, `apply` en
   main con aprobación.
5. **Chart de Helm**: el Job nocturno sube informes y copia del historial, y
   publica el aviso si hay cambios.
6. **Instalación real**, ensayo de restauración, y runbook
   `docs/devops/runbooks/04-aws.md`.

## Fuera de alcance

- Lista de hosts "conocidos" para no volver a avisar de ellos (ruido de
  móviles de visitas). Se apunta como idea.
- Avisos de salud del sistema (el escaneo falló o no se ejecutó): fase 6, por
  Telegram.
- Email en HTML: SNS por email solo manda texto plano.
- IAM Roles Anywhere en vez de claves del usuario del homelab (ver decisiones
  del diseño general): mejora futura.
- Despliegue automático del chart al sacar tag: fase 5 (Jenkins). Aquí el
  `helm upgrade` lo lanza el mantenedor desde el PC.
- El Terraform de Proxmox sigue aplicándose desde el PC (GitHub no llega a la
  LAN).

## Anti-objetivos (fracaso aunque funcione)

- **Coste** por encima de céntimos al mes. Los créditos de AWS caducan el
  2026-11-06: todo se cobra. Nada encendido (EC2, Lambda, NAT), nada de KMS
  propio (~1 $/mes por clave), nada de clases de almacenamiento con mínimos
  (Glacier).
- **Un email cada noche** aunque no haya cambios.
- **Secretos en git o en algo público**: las claves del usuario del homelab
  no van al repo, ni a GitHub, ni al estado de Terraform. El email del
  mantenedor no aparece en comentarios de PR ni en logs públicos del CI.
- **Que un PR pueda cambiar AWS**: el rol de los PRs solo lee.
- **Que la app aprenda AWS**: ni `boto3` ni nombres de buckets en `src/`.
- Datos reales de la red en el repo (reglas de siempre del `CLAUDE.md`).
- Romper el uso local: sin los flags nuevos, el CLI hace lo de hoy.

## Decidido con el mantenedor

- **Email = resumen corto + enlaces** (opciones A y C de la conversación):
  - Solo si hay cambios. **Uno por noche**, con todos los rangos juntos.
  - Asunto con cuántos cambios hay y en qué rangos.
  - En el cuerpo, **los puertos sensibles nuevos primero**; luego hosts
    nuevos, desaparecidos y puertos cambiados, un host por línea con IP,
    fabricante y categoría.
  - Al final, **enlaces temporales** (prefirmados) al mapa HTML y al CSV de
    esa noche en S3.
- **Terraform de AWS aplicado por GitHub Actions** (plan en PR, apply en main
  con aprobación), entrando por OIDC.
- **Copia del historial con versiones y ensayo de restauración** (opción C):
  copia tras cada escaneo correcto, versiones de 30 días, y en esta fase se
  restaura de verdad siguiendo el runbook.
- **Informes en S3 durante 90 días**, luego se borran solos.

## Propuestas del diseño (decisiones de Claude; el mantenedor puede cambiarlas)

### App

- **`--changes-dir DIR`** (nombre a afinar en el plan, en inglés como el resto
  del CLI): si alguna ejecución tiene cambios, escribe en `DIR`
  `cambios.json` (los diffs por rango, combinados) y `asunto.txt` /
  `cuerpo.txt` (el texto del email). Si no hay cambios, no escribe nada: la
  ausencia del archivo es la señal para no avisar. Un primer escaneo de un
  rango (`primera_vez`) no cuenta como cambio.
- El texto del email lo genera la app, en una función pura nueva de
  `export.py` (junto a `exportar_diff_texto`), reutilizando
  `history.combinar_diffs`, `hay_cambios` y `PUERTOS_SENSIBLES`. Motivo: el
  contenedor de subida es `aws-cli` y no tiene Python ni nada para formatear
  JSON con gusto; y es testeable con pytest como todo lo demás. El diseño
  general decía "el resumen se genera a partir del JSON": se cumple, lo genera
  la app a partir de los mismos diffs.
- **Asunto en ASCII y menos de 100 caracteres**: es límite de SNS. Nada de
  `⚠` en el asunto; el aviso de sensibles va como `[!]`. En el cuerpo sí
  vale Unicode.
- **`--history-backup FILE`**: tras registrar la ejecución, copia el
  historial con la API de backup de SQLite (`sqlite3.Connection.backup`), no
  con un `cp`: la web puede estar escribiendo a la vez. Vive en `history.py`.
- Idioma de asunto y cuerpo: inglés, como la salida del CLI.
- Solo avisa el escaneo nocturno (el CronJob pasa los flags). Los escaneos
  lanzados a mano desde la web no mandan email.

### AWS (Terraform)

- **Raíz nueva** `infra/aws/hallazgos/`, estado en el bucket de la fase 2
  (clave propia, junto a la de Proxmox) con `use_lockfile`. Región `eu-south-2`,
  como el bucket del estado. Hay que añadirla al job `terraform` de CI (el
  test de `test_workflows.py` lo exige).
- **Bucket de informes** `topology-scanner-informes-<id de cuenta>`, privado
  (bloqueo de acceso público), SSE-S3, versionado activado. Prefijos:
  - `informes/<fecha-hora>/`: HTML, CSV y `cambios.json` (si hay). Expiran a
    los 90 días.
  - `historial/historial.db`: la copia. Versiones no actuales expiran a los
    30 días.
  - Limpieza de marcadores de borrado expirados (efecto del versionado).
- **SNS**: un topic y una suscripción email. La dirección es una variable
  `sensitive` que llega al workflow por una variable/secret de GitHub (y por
  `terraform.tfvars` ignorado en el PC), así no sale en el `plan` público.
  La suscripción hay que confirmarla a mano pulsando el enlace del email.
- **Usuario IAM del homelab** con mínimo privilegio: `s3:PutObject` en
  `informes/*` y `historial/*`, `s3:GetObject` en `informes/*` (lo necesitan
  los enlaces prefirmados: se firman con estas claves), `sns:Publish` en el
  topic. **La clave de acceso no la crea Terraform**: quedaría en el estado,
  y el rol de plan lo lee. Se crea a mano desde el PC (runbook) y va a un
  Secret de Kubernetes.
- **OIDC de GitHub**: proveedor + dos roles.
  - `plan`: solo lectura de lo que gestiona esta raíz y del estado; confía en
    `pull_request` de este repo. El `plan` corre con `-lock=false` para no
    necesitar escribir el lockfile.
  - `apply`: escritura limitada a los recursos de esta raíz (nombres con
    prefijo `topology-scanner`); confía solo en el environment `aws` de este
    repo. Es el rol sensible (puede tocar IAM): por eso el environment exige
    la aprobación del mantenedor y solo admite la rama main.
- El environment `aws` (revisor obligatorio, solo main) y las variables del
  workflow se crean a mano en la configuración del repo: tarea del mantenedor,
  en el runbook.
- El `plan` publicado en los PRs muestra el ID de la cuenta en los ARN. Se
  acepta: AWS no lo trata como secreto, y no da acceso por sí solo.
- **Huevo y gallina**: el primer `apply` (que crea el proveedor OIDC y los
  roles) se hace desde el PC con el perfil `personal`, como el bootstrap de
  la fase 2. Después, todo por PR.

### GitHub Actions

- Workflow nuevo (p. ej. `terraform-aws.yml`), solo cuando cambia
  `infra/aws/hallazgos/` o el propio workflow:
  - En PR: `plan`, publicado como comentario del PR. PRs desde forks no
    reciben token OIDC: el job se salta para ellos.
  - En push a main: `plan` + `apply` en el environment `aws` (aprobación
    manual), con `concurrency` para que no se pisen dos apply.
- Actions de terceros fijadas por SHA (`aws-actions/configure-aws-credentials`,
  `hashicorp/setup-terraform`), runner `ubuntu-26.04`, Terraform 1.16.6: las
  reglas de siempre, y las comprueba `test_workflows.py`.

### Kubernetes (chart)

- El Pod del Job nocturno pasa a tener **dos pasos**: el escaneo como
  `initContainer` y la subida como contenedor principal (imagen oficial
  `amazon/aws-cli`, fijada por digest). Si el escaneo falla, la subida no
  arranca y el Job sale fallido, como hoy.
- Comparten un `emptyDir` para los archivos de esa noche (HTML, CSV,
  `cambios.json`, `asunto.txt`, `cuerpo.txt`, copia del historial). El
  historial vivo sigue en el PVC.
- El script de subida va en un ConfigMap: sube los informes, sube la copia
  del historial y, si existe `cambios.json`, firma enlaces de 7 días (máximo
  con claves de usuario IAM) al HTML y al CSV, los añade al final del cuerpo
  y publica en SNS.
- Todo bajo `aws.enabled` (desactivado por defecto): sin él, el chart hace lo
  de la fase 3. Valores: región, bucket, ARN del topic, nombre del Secret con
  las claves (`topology-scanner-aws`, creado a mano). El contenedor de subida
  con el mismo endurecimiento que el resto (no root, `drop: [ALL]`, sistema
  de archivos de solo lectura salvo el `emptyDir`).
- Si falla la subida o el aviso, el Job sale fallido (se verá en el clúster
  y, en la fase 6, por Telegram). El escaneo y el historial local ya están
  guardados para entonces.

### Restauración

- Se restaura desde el PC con las credenciales del mantenedor (perfil
  `personal`), no con el usuario del homelab (que no puede leer `historial/`).
- El runbook cubre: parar CronJob y web, recuperar la versión elegida del
  objeto, meterla en el PVC (nuevo o vaciado), volver a arrancar.
- **Ensayo en esta fase**: borrar el PVC de verdad, restaurar, y comprobar
  que la web lista las ejecuciones de antes y que el siguiente escaneo no
  avisa de todos los hosts como nuevos.

## Lo que se deja al constructor

- Nombres exactos de flags, archivos y prefijos (respetando lo de arriba).
- Formato exacto del asunto y el cuerpo, dentro de lo decidido.
- Las políticas IAM concretas de los roles de plan y apply, con mínimo
  privilegio razonable.
- Cómo se obtiene el digest de `amazon/aws-cli` y cómo se mantiene.
- Orden de tareas y commits del plan.

## Documentación (entregable)

- `docs/devops/runbooks/04-aws.md`: primer apply desde el PC, confirmar la
  suscripción, crear y rotar la clave del usuario del homelab, el Secret,
  `helm upgrade`, cómo forzar un aviso de prueba, y la restauración.
- `docs/decisiones.md`: cada decisión nueva con su porqué (en particular:
  claves estáticas del homelab y por qué no en el estado; texto del email
  generado por la app; dos roles OIDC).
- `docs/devops/README.md`: fase 4 hecha y piezas nuevas.
- `CLAUDE.md`: estructura y comandos nuevos. README (inglés): flags nuevos.
