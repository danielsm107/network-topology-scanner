# Fase DevOps

Llevar el escáner de "herramienta en el PC" a un sistema que se despliega,
escanea solo y avisa: homelab (Proxmox + k3s) para todo lo que tiene que ver la
LAN, AWS para lo que no. Diseño completo, con el porqué de cada decisión:
[`docs/superpowers/specs/2026-10-22-fase-devops-design.md`](../superpowers/specs/2026-10-22-fase-devops-design.md).

## Estado

| # | Fase | Estado | Runbook |
|---|------|--------|---------|
| 0 | Higiene de la cuenta AWS | Hecha | [00-cuenta-aws.md](runbooks/00-cuenta-aws.md) |
| 1 | Contenedor | Hecha | [01-contenedor.md](runbooks/01-contenedor.md) |
| 2 | VM de Proxmox como código | Hecha | [02-proxmox-vm.md](runbooks/02-proxmox-vm.md) |
| 3 | Despliegue en Kubernetes | Hecha | [03-kubernetes.md](runbooks/03-kubernetes.md) |
| 4 | AWS como código + hallazgos | Hecha | [04-aws.md](runbooks/04-aws.md) |
| 5 | Jenkins (CD) | Pendiente | |
| 6 | Observabilidad | Pendiente | |

## Piezas que ya existen

- `Dockerfile` / `.dockerignore`: la imagen (nmap sin root, `/data`, web por `STREAMLIT_*`).
- `compose.yaml`: uso local con Docker Compose (web + escaneo por CLI).
- `.github/workflows/ci.yml`, job `imagen`: construye, prueba y escanea (Trivy) la imagen.
- `.github/workflows/release.yml`, job `imagen`: publica `ghcr.io/danielsm107/topology-scanner:X.Y.Z` y `latest`.
- `infra/aws/bootstrap/`: bucket S3 del estado de Terraform (versionado, cifrado, sin acceso público).
- `infra/proxmox/`: la VM k3s (Ubuntu 26.04 + cloud-init + k3s fijado); estado en S3, `apply` desde el PC.
- `.github/workflows/ci.yml`, job `terraform`: `fmt`, `validate` y `terraform test` (provider simulado).
- `deploy/helm/topology-scanner/`: chart de Helm (escaneo nocturno como CronJob, web, PVC del historial);
  `helm install`/`upgrade` desde el PC, valores reales en `deploy/helm/values.local.yaml` (ignorado).
- `.github/workflows/ci.yml`, job `helm`: `helm lint` y `helm template`; `tests/test_helm.py` renderiza el chart.
- `infra/aws/hallazgos/`: bucket de informes (y copia del historial), SNS con suscripción email, usuario IAM
  del homelab, OIDC de GitHub con rol de plan (PRs) y de apply (environment `aws`, con aprobación).
- `.github/workflows/terraform-aws.yml`: plan de `infra/aws/hallazgos/` como comentario en los PRs, apply en main.
- Chart con `aws.enabled`: el Job nocturno sube informes y copia del historial a S3 y avisa por SNS si hubo
  cambios (`files/subir.sh`, contenedor `amazon/aws-cli`).
