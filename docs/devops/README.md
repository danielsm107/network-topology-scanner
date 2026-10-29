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
| 3 | Despliegue en Kubernetes | Pendiente | |
| 4 | AWS como código + hallazgos | Pendiente | |
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
