# Fase DevOps — diseño

Fecha: 2026-10-22 · Estado: aprobado por el mantenedor (2026-10-22)

## Por qué

El mantenedor quiere orientar su perfil a **DevOps** (no solo sysadmin/redes).
La herramienta ya está cerrada como software (v1.0.0 en PyPI, publicada por
GitHub Actions). Esta fase la convierte en un **sistema desplegado y operado**:
contenedor, infraestructura como código, Kubernetes, CI/CD, alertas y
observabilidad, usando AWS, Kubernetes, Jenkins y GitHub Actions.

Es pieza de portfolio para entrevistas, así que importa tanto que funcione
como poder explicar **por qué** está montado así. Y tiene que quedar **todo
documentado** en el repo (petición explícita del mantenedor).

## La restricción que define el diseño

Un escáner de red solo ve la red en la que está. Desplegado en AWS vería la
VPC, no la LAN de casa. Por eso el sistema es **híbrido**:

- **Homelab (dentro de la LAN):** todo lo que escanea o necesita llegar al
  clúster: k3s, el CronJob de escaneo, la web, Jenkins, Prometheus.
- **AWS (fuera):** lo que no necesita estar en la LAN: informes, avisos,
  estado de Terraform.

Ningún puerto del homelab se abre a internet: toda comunicación sale del
homelab hacia fuera (subir a S3, publicar en SNS, consultar GitHub, Telegram).

## Objetivos

1. Escaneo **programado** de la LAN sin intervención (por defecto, cada noche).
2. **Hallazgos de seguridad por email**: solo cuando el escaneo encuentra
   cambios (`history.hay_cambios`), con el resumen del diff.
3. **Salud del sistema por Telegram**: el escaneo ha fallado, o lleva más de
   ~26 h sin ejecutarse con éxito.
4. Informes de cada escaneo (mapa HTML, CSV, diff) guardados en S3.
5. **Toda la infraestructura como código**: la VM de Proxmox y la de AWS con
   Terraform, el despliegue en Kubernetes con Helm. "Si se rompe el MiniPC,
   se reconstruye desde el repo".
6. **CI/CD completo**: GitHub Actions para CI (tests, imagen, plan de
   Terraform); Jenkins para CD dentro de la LAN.
7. Documentación: arquitectura, un runbook por fase, decisiones con su porqué.

## No-objetivos

- **EKS** ni ningún cómputo encendido en AWS (EC2, NAT Gateway, Fargate): el
  cómputo es el homelab.
- Alta disponibilidad: es un nodo único en un MiniPC, y se acepta.
- Multiusuario, autenticación propia en la web, multi-sitio.
- Métricas de negocio del escaneo en Prometheus (nº de hosts, puertos…): fuera
  del alcance inicial. Se movieron a la fase 6 el 2026-10-29 (ver su fila).
- Usar a la vez otra nube (Azure se descartó: curiosidad, no requisito).

## Anti-objetivos (fracaso aunque "funcione")

- **Coste**: si AWS pasa de unos pocos $/mes, el diseño está mal. Los créditos
  (100 $) caducan el 2026-11-06; después todo se cobra a la tarjeta.
- **Secretos en git** (claves de AWS, community/claves SNMP, token de Telegram,
  token de la API de Proxmox): nunca, ni en el historial.
- **La web o cualquier servicio del homelab expuestos a internet.**
- **Datos reales de la red en el repo** (IPs, MACs, nombres): las reglas del
  `CLAUDE.md` siguen valiendo. La configuración real (rangos, IPs SNMP) vive en
  archivos no versionados o en Secrets, y en el repo van ejemplos inventados.
- Alerta por email en cada escaneo aunque no haya cambios (se dejan de leer).
- Fallo silencioso: que el escaneo deje de ejecutarse y nadie se entere (por
  eso existe la alerta de salud).
- Que la herramienta pueda usarse para escanear redes ajenas (aviso legal del
  proyecto): los rangos son configuración del despliegue, nunca entrada pública.

## Restricciones conocidas

**Hardware del homelab:** MiniPC con Proxmox VE 9, Intel N100 (4 núcleos),
15,4 GiB de RAM. La ARC de ZFS ocupa hoy 7-10 GiB sin límite.
- VM nueva `k3s`: 4 vCPU, 8 GiB RAM, ~40 GB disco, red en el bridge de la LAN
  (para que nmap vea la LAN en L2: MAC y fabricante).
- Limitar la ARC de ZFS a ~4 GiB (`zfs_arc_max`), documentado en el runbook.
- VM y no contenedor LXC (k3s en LXC da problemas de privilegios y módulos).
- Todo ligero: Jenkins no construye imágenes; Prometheus con retención corta.

**AWS:** cuenta existente con 100 $ de créditos que caducan el 2026-11-06,
probablemente ya en el plan de pago (confirmar en Account). Sin EKS.

**La app:** `webapp.py` y el CLI ejecutan nmap, que para MAC/OS necesita
privilegios de red (`NET_RAW`, `NET_ADMIN`). El historial es SQLite.

## Arquitectura

```
                          GitHub (repo público)
   ┌──────────────────────────────────────────────────────────────┐
   │ GitHub Actions                                               │
   │  - CI: ruff, pytest, docker build + escaneo de la imagen,    │
   │        helm lint, terraform fmt/validate/plan                │
   │  - Release (tag vX.Y.Z): PyPI + imagen a GHCR + release      │
   │  - Terraform AWS: plan en PR, apply en main (con aprobación) │
   └───────────────┬──────────────────────────────────┬───────────┘
          OIDC (sin claves)                     imagen ghcr.io/…
                   ▼                                  │ (pull)
   ┌───────────────────────────────┐                  │
   │ AWS                           │                  │
   │  S3 informes (privado)        │◄── sube ──┐      │
   │  SNS hallazgos ──► email      │◄── publica┤      │
   │  S3 estado de Terraform       │           │      │
   │  Budget 5 $ ──► email         │           │      │
   └───────────────────────────────┘           │      │
                                               │      ▼
   ┌───────────────────── Homelab (LAN) ───────┴──────────────────┐
   │ Proxmox ─► VM k3s (creada con Terraform + cloud-init)        │
   │   ns topology-scanner:                                       │
   │     CronJob escaneo (hostNetwork) ─► historial (PVC)         │
   │     Deployment web (Streamlit, solo LAN)                     │
   │   ns jenkins: Jenkins (sondea tags en GitHub ─► helm upgrade)│
   │   ns monitoring: Prometheus + Alertmanager ─► Telegram       │
   │                  Grafana, kube-state-metrics                 │
   └──────────────────────────────────────────────────────────────┘
```

## Decisiones tomadas

### Con el mantenedor

- Sistema híbrido: homelab (Proxmox) + AWS. AWS y no Azure.
- VM dedicada en Proxmox para k3s.
- **Hallazgos → email (vía SNS). Salud del sistema → Telegram (vía Alertmanager).**
- Herramientas: AWS, Kubernetes, Jenkins, GitHub Actions, con todo documentado.
- Higiene de la cuenta AWS antes de crear nada (fase 0).
- **La web del clúster solo escanea rangos permitidos.** Sin autenticación y
  con acceso de red completo, cualquiera en la LAN podría escanear cualquier
  cosa (aviso legal del proyecto). La web acepta una lista de rangos
  permitidos por configuración (p. ej. una variable de entorno) y rechaza
  todo rango que no esté contenido en alguno de ellos. Sin la variable, el
  comportamiento es el de hoy (uso local en el PC). Se descartaron "web solo
  visor" (pierde el escaneo y el log en vivo) y "dejarlo como riesgo aceptado".
  Va en la fase 3, antes de desplegar la web.

### Propuestas por el diseño (no discutidas una a una; el mantenedor puede cambiarlas)

- **Reparto CI/CD**: GitHub Actions = CI y artefactos (corre en la nube, no
  llega a la LAN). Jenkins = CD dentro de la LAN, **por sondeo** (pull): mira
  los tags del repo cada pocos minutos y despliega con Helm. Así no hace falta
  abrir el homelab a internet para recibir webhooks. Esto es lo que justifica
  tener dos herramientas de CI/CD en vez de una redundante.
- **Registro de imágenes: GHCR (`ghcr.io`), no ECR.** El repo es público, así
  que la imagen también: k3s la descarga sin credenciales. Con ECR privado, el
  token de descarga caduca cada 12 h y habría que montar un refresco de
  credenciales dentro del clúster: complejidad sin valor para el objetivo.
  (Cambia lo que se habló en el chat, donde se mencionó ECR.)
- **Entrada a AWS desde GitHub por OIDC** (rol IAM con trust a este repo), igual
  que PyPI: sin claves en los secrets.
- **Entrada a AWS desde el homelab con un usuario IAM de mínimo privilegio**
  (solo `s3:PutObject` en el bucket de informes y `sns:Publish` en el topic),
  con sus claves en un Secret de Kubernetes creado a mano (nunca en git).
  Compromiso aceptado y documentado: IAM Roles Anywhere evitaría claves de
  larga duración, pero exige montar una PKI. El runbook documenta cómo rotarlas,
  y `docs/decisiones.md` deja escrita la respuesta a "¿por qué claves
  estáticas?" (pregunta probable en una entrevista), con Roles Anywhere como
  mejora futura.
- **Estado de Terraform en S3** con bloqueo nativo de S3 (`use_lockfile`, sin
  DynamoDB). El bucket del estado se crea en un paso de *bootstrap* aparte con
  estado local, porque Terraform no puede guardar su estado en un bucket que
  aún no existe.
- **La app no aprende nada de AWS.** El principio del proyecto ("cada módulo no
  sabe nada de los demás") se extiende al despliegue: el escaneo escribe
  archivos, y otro contenedor del mismo Pod (imagen oficial de `aws-cli`) los
  sube a S3 y publica en SNS. Cambios en la app, los dos genéricos y útiles
  por sí mismos: un flag del CLI para escribir el diff en JSON solo si
  `hay_cambios(diff)` (el resumen legible del email se genera a partir de ese
  JSON), y la lista de rangos permitidos de la web (ver arriba).
- **El escaneo como CronJob** con `hostNetwork: true` y solo las capacidades
  `NET_RAW` y `NET_ADMIN` (no `privileged`), con un usuario no root si nmap lo
  permite (capabilities en el binario + `--privileged` de nmap); si no, root
  dentro del contenedor y se documenta el porqué.
- **La web también en el clúster**, misma imagen, mismo tratamiento de red, y
  expuesta solo en la LAN (Ingress de Traefik, el que trae k3s).
- **Historial SQLite en un PVC** (`local-path`, el de k3s), compartido por el
  CronJob y la web: un solo nodo, así que `ReadWriteOnce` basta.
- **Configuración real fuera del repo**: rangos, IPs SNMP y credenciales van en
  un `values` local no versionado y en Secrets. En el repo, un
  `values.example.yaml` con datos inventados.
- **Alertas de salud sin tocar la app**: kube-state-metrics ya expone si un
  Job ha fallado y cuándo fue el último éxito de un CronJob; las reglas de
  Prometheus salen de ahí.
- **Seguridad en el pipeline**: la imagen se escanea en CI (p. ej. Trivy) y el
  build falla con vulnerabilidades críticas que tengan arreglo.
- **Budget de AWS manual en la fase 0**, antes de que exista Terraform: la red
  de seguridad tiene que estar antes que cualquier recurso.
- **Terraform de Proxmox: `apply` manual desde el PC del mantenedor**, que es
  el único que llega a la API de Proxmox (está en la LAN y no se abre nada).
  Su estado va al mismo bucket S3 de estado, con otra clave
  (`proxmox/terraform.tfstate`), usando las credenciales de `aws sso login`
  de la fase 0. En CI, el código de Proxmox solo pasa `terraform fmt` y
  `validate`; el `plan` de CI es solo para AWS. Un runner dentro de la LAN
  queda fuera de alcance.
- **Copia de seguridad del historial a S3**: un CronJob diario copia
  `historial.db` a un prefijo `backups/` del bucket de informes (con
  versionado y caducidad). Sin el historial, tras reconstruir la VM, el
  primer escaneo lo vería todo como nuevo y los emails de hallazgos
  perderían su base de comparación. El usuario IAM del homelab tiene por eso
  `s3:GetObject`/`PutObject` también en `backups/`, y el runbook documenta la
  restauración. Jenkins y Grafana no necesitan copia: su configuración es
  código (JCasC, dashboards versionados).
- **Los `values` reales del despliegue viven en el clúster**: un Secret
  (`topology-scanner-values`) que se crea a mano la primera vez desde el
  archivo local no versionado. La instalación inicial (fase 3) y Jenkins
  (fase 5) usan ese Secret; cambiar un rango es actualizar el Secret y
  relanzar el pipeline, sin necesidad de un tag nuevo.
- **Orden de fases independiente de la caducidad de los créditos**
  (2026-11-06): lo previsto en AWS cuesta céntimos al mes, así que no se
  adelanta la fase 4. La fase 0 (budget) sí conviene hacerla cuanto antes.

## Fases

Cada fase es un plan de implementación propio (`superpowers:writing-plans`),
con commits pequeños, y no se empieza la siguiente sin la anterior funcionando
y documentada.

| # | Fase | Resultado verificable |
|---|------|----------------------|
| 0 | Higiene de la cuenta AWS (manual) | MFA en root, acceso con `aws sso login`, budget de 5 $ con avisos al 50/100 %, plan de la cuenta confirmado |
| 1 | Contenedor | `Dockerfile` + `.dockerignore`; la imagen escanea con MAC/fabricante en la LAN; CI construye y escanea la imagen; la release publica `ghcr.io/danielsm107/topology-scanner:X.Y.Z` |
| 2 | VM de Proxmox como código | `terraform apply` crea la VM con cloud-init y k3s instalado; `kubectl get nodes` responde desde el PC del mantenedor |
| 3 | Despliegue en Kubernetes | Rangos permitidos en la web (con test); chart de Helm: CronJob de escaneo, web en la LAN, PVC del historial, Secrets SNMP y de `values`; un escaneo manual (`kubectl create job --from=cronjob/...`) deja historial y la web rechaza un rango no permitido |
| 4 | AWS como código + hallazgos | Terraform: bucket de informes, SNS + suscripción email, usuario IAM del homelab, rol OIDC de GitHub; flag de diff JSON en el CLI; un cambio en la red llega por email, los informes aparecen en S3 y la copia del historial se restaura siguiendo el runbook |
| 5 | Jenkins (CD) | Jenkins en el clúster (Helm, configuración como código); un tag nuevo acaba desplegado sin intervención |
| 6 | Observabilidad | Prometheus, Alertmanager, Grafana, kube-state-metrics; un Job que falla a propósito llega a Telegram; métricas del escaneo (hosts vivos, puertos sensibles, hosts nuevos) con su panel en Grafana (el CronJob vive minutos: Pushgateway o servidas por la web desde el historial, a decidir en la fase) |

## Documentación (entregable de cada fase)

- `docs/devops/README.md`: arquitectura (el diagrama de arriba), cómo encajan
  las piezas, índice de runbooks.
- `docs/devops/runbooks/NN-<fase>.md`: pasos reproducibles de cada fase, con
  qué se hace a mano y por qué, y cómo comprobar que funciona.
- `docs/decisiones.md`: cada decisión nueva con su porqué (como hasta ahora).
- `README.md` (inglés): sección corta de despliegue que enlaza a `docs/devops/`.
- `CLAUDE.md`: estructura y comandos nuevos.
- Idioma: castellano en `docs/` (como el resto), inglés en el README.

## Lo que se deja al constructor

- Distribución de carpetas (orientativa: `deploy/helm/`, `infra/aws/{bootstrap,main}`,
  `infra/proxmox/`, `Jenkinsfile`, `deploy/monitoring/`).
- Imagen base, versiones exactas de charts y proveedores, nombre exacto del flag
  del diff y formato del email.
- Horario del CronJob (por defecto, de noche) y retención de Prometheus.
- Cómo instala k3s cloud-init y cómo se obtiene el kubeconfig.
- Herramienta concreta de escaneo de imágenes.

## Ideas para después (fuera de esta fase)

- Hallazgos también a Telegram (una Lambda suscrita a SNS).
- GitOps con Argo CD como alternativa a Jenkins, para comparar.
- Publicar el último mapa HTML en una URL privada (S3 + CloudFront con acceso
  restringido).
