# README de portfolio + arquitectura en inglés — diseño

## Por qué

El mantenedor busca un puesto DevOps y el repo va en su CV. Hoy el README
(inglés, 290 líneas) presenta la herramienta; las 8 fases DevOps caben en un
párrafo de 9 líneas que enlaza a `docs/devops/`, en español. Quien llegue desde
el CV debe ver en 30 segundos que hay un **sistema que se despliega, se vigila
y se recupera solo**, no solo un script.

## Objetivos

- Primera pantalla del README: frase de doble propuesta (escáner + plataforma
  que lo ejecuta), insignias, diagrama de arquitectura, capturas.
- Sección nueva **"How it runs"** (~30 líneas) en el README: qué hace cada pieza
  y 4-5 decisiones que más venden.
- `docs/architecture.md` nuevo, en inglés: las 8 fases (0-7) con qué se hizo y
  por qué, y enlaces a los runbooks en español. Sirve también de guion para el
  simulacro de entrevista.

## No objetivos

- Traducir runbooks ni `docs/decisiones.md` (siguen en español).
- Cambiar código, chart ni infraestructura.
- Reescribir las secciones de uso (instalación, SNMP, tests): solo se mueven
  debajo y se ajustan enlaces.

## Antiobjetivos (fracaso aunque "funcione")

- Que el README se vuelva un muro: el `pip install` / `docker run` tiene que
  seguir a un vistazo.
- Exageraciones ("production-grade", "enterprise"): es un homelab y se dice.
- Cualquier dato real: IPs, dominios, ID de cuenta AWS, nombres de bucket con
  la cuenta, MACs. Solo nombres genéricos (regla de CLAUDE.md, el repo es público).

## Enfoques considerados

- **A (elegido)**: README con dos partes + `docs/architecture.md`. Vende arriba,
  detalle para quien lo quiera, uso intacto.
- B: todo en el README. Descartado: >500 líneas, el usuario de la herramienta
  atraviesa Kubernetes para instalarla.
- C: solo añadir el diagrama al párrafo actual. Descartado: las decisiones, lo
  que más vale en entrevista, siguen escondidas y en español.

## Decidido

- Diagrama en **Mermaid** (GitHub lo pinta, es texto, se actualiza en el mismo
  PR que la infra). Uno solo en el README (visión general); en
  `architecture.md` puede haber uno más de detalle (flujo del release:
  tag → CI → PyPI/GHCR → Jenkins → helm upgrade/test/rollback).
- Contenido del diagrama general: PC del mantenedor (Terraform/Helm), GitHub
  (CI, release, terraform-aws por OIDC), GHCR/PyPI, Proxmox → VM k3s con
  CronJob + web + Jenkins + Prometheus/Grafana/Loki/Alloy/Pushgateway, AWS
  (S3 informes/historial, SNS email), Telegram, healthchecks.io, LAN escaneada.

## Llamadas mías (corregibles)

- Decisiones a destacar en "How it runs": OIDC sin claves de larga duración;
  despliegue por tag con `helm test` y rollback automático; actions fijadas por
  SHA e imagen escaneada con Trivy; contenedor sin root (setcap); vigilancia de
  la propia monitorización (Watchdog → healthchecks.io); probado con ensayos de
  fallo reales (restauración desde S3, reinstalación de la monitorización).
- La sección "Deployment (homelab + AWS)" actual se sustituye por "How it runs".
- Roadmap: se añaden las líneas de la fase DevOps que faltan (Jenkins CD,
  observabilidad, logs).
- Un solo commit de docs en rama `readme-portfolio` + PR.

## Para quien lo construya

Redacción concreta, orden fino de secciones y nivel de detalle de cada fase en
`architecture.md`, sacándolo de `docs/devops/`, los runbooks y
`docs/decisiones.md`. Comprobar que el Mermaid se ve en GitHub (vista previa
del PR).
