# Fase 2 (VM de Proxmox como código) — plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `terraform apply` desde el PC del mantenedor crea en Proxmox la VM `k3s`
(cloud-init, IP fija, k3s instalado) y `kubectl get nodes` responde desde el PC.

**Architecture:** Dos raíces de Terraform. `infra/aws/bootstrap/` (estado local)
crea el bucket S3 del estado; se adelanta de la fase 4 porque el diseño ya
manda el estado de Proxmox a ese bucket. `infra/proxmox/` (estado en S3, clave
`proxmox/terraform.tfstate`, `use_lockfile`) usa el provider `bpg/proxmox`:
descarga la imagen cloud de Ubuntu por la API, sube el snippet de cloud-init por
SSH (la API de Proxmox no admite subir snippets) y crea la VM. El cloud-init
instala k3s con versión fijada y la IP en `--tls-san`. La CI solo hace `fmt`,
`validate` y `terraform test` (con provider simulado): no llega a la LAN.

**Tech Stack:** Terraform ≥ 1.10, `bpg/proxmox`, `hashicorp/aws` ~> 6, cloud-init,
k3s, GitHub Actions (`hashicorp/setup-terraform`).

**Spec:** `docs/superpowers/specs/2026-10-22-fase-devops-design.md` (fila "2 | VM
de Proxmox como código"; "Terraform de Proxmox: `apply` manual desde el PC";
"Estado de Terraform en S3"; "Restricciones conocidas").

## Decisiones de esta fase (2026-10-27, con el mantenedor)

- **Bootstrap del bucket de estado ahora**, no en la fase 4.
- **IP fija por cloud-init** (variable en `terraform.tfvars`, no versionado).
- **8 GiB de RAM** (lo del diseño): el mantenedor apaga la VM 202 (~8 GiB), que no
  cabría a la vez. Si se vuelve a encender, bajar la variable `memoria_mib` a 6144.
- **SSH al nodo como root con `~/.ssh/homelab_ed25519`**, solo para subir el
  snippet; el resto va por API token de mínimo privilegio.
- **La ARC de ZFS ya está limitada** (~1,5 GiB) y los discos de VM van en
  `local-lvm`: la tarea del diseño sobra; solo se anota en el runbook.

## Global Constraints

- Estado de Proxmox en S3, clave `proxmox/terraform.tfstate`, bloqueo con `use_lockfile` (sin DynamoDB).
- AWS: perfil `personal` (SSO), región `eu-south-2`. Nunca el perfil `default` (cuenta del trabajo).
- VM: 4 vCPU, 8192 MiB, 40 GB en `local-lvm`, bridge `vmbr0`, VMID 210, nombre `k3s`, arranque con el host.
- Nada real en el repo: IPs, dominio del host, token, ID de cuenta y nombre del bucket van en
  `terraform.tfvars` / `backend.hcl` (ignorados). Ejemplos con `192.0.2.0/24` y `pve.example.internal`.
- Versiones fijadas: provider con `~>` + `.terraform.lock.hcl` versionado; k3s con `k3s_version` exacta
  (canal `stable` el día de la ejecución); imagen de Ubuntu 26.04 LTS por URL de release con checksum.
- Actions de terceros fijadas por SHA (lo comprueba `tests/test_workflows.py`).
- Docs en castellano en `docs/`; `pytest tests/` y `ruff check src/ tests/ scripts/` en verde; un commit por tarea.
- Reparto de trabajo: lo marcado **[A MANO]** lo hace el mantenedor con supervisión.

## Review Focus

1. **Segundo `terraform plan` tras crear la VM** → tiene que decir "No changes" (ni recrear la VM por el
   snippet o la imagen; cloud-init solo corre en el primer arranque) → verificación en la Tarea 4.
2. **kubectl desde el PC con la IP de la VM** → sin error x509: la IP tiene que estar en `--tls-san` →
   `terraform test` de la Tarea 2.
3. **Variable de IP mal escrita** (sin `/24`, o gateway fuera de la red) → error de `validation` en el
   `plan`, no una VM inalcanzable → `terraform test` de la Tarea 2.
4. **Sesión SSO caducada** al hacer `init`/`plan` → el runbook dice `aws sso login --profile personal`
   (Tarea 5).
5. **IP dentro del pool DHCP del MikroTik** → conflicto de IP silencioso; el runbook obliga a comprobarlo
   antes del `apply` (Tarea 5).

---

### Task 1: Bootstrap del bucket de estado (`infra/aws/bootstrap/`)

**Files:**
- Create: `infra/aws/bootstrap/{versions.tf,main.tf,outputs.tf}`, `infra/.gitignore`
- Modify: `docs/devops/README.md` (fase 1 → "Hecha"; fase 2 → "En curso")

**Interfaces:**
- Produces: output `bucket_estado` (nombre del bucket); la Tarea 2 lo usa en `backend.hcl`.

- [ ] **Step 1:** rama `fase-2-proxmox-vm` desde `main`; instalar en el PC `Hashicorp.Terraform` y
  `Kubernetes.kubectl` con winget; `terraform version` ≥ 1.10.
- [ ] **Step 2:** `infra/.gitignore`: `.terraform/`, `*.tfstate`, `*.tfstate.*`, `*.tfvars` (salvo
  `!*.tfvars.example`), `backend.hcl`, `kubeconfig*`. **No** ignorar `.terraform.lock.hcl`.
- [ ] **Step 3:** código. Provider `aws` con `profile = "personal"`, `region = "eu-south-2"` y
  `default_tags` (`Project = "topology-scanner"`, `ManagedBy = "terraform"`). Bucket
  `topology-scanner-tfstate-<account_id>` (de `data.aws_caller_identity`), con versionado, cifrado SSE-S3
  (AES256: KMS costaría ~1 $/mes), bloqueo de acceso público completo, política que deniega
  `aws:SecureTransport = false`, y lifecycle que borra versiones no actuales a los 90 días.
  `prevent_destroy` en el bucket.
- [ ] **Step 4:** `terraform fmt -check -recursive infra/` y `terraform -chdir=infra/aws/bootstrap init -backend=false && terraform validate` → OK.
- [ ] **Step 5:** **[A MANO]** `aws sso login --profile personal`; `terraform -chdir=infra/aws/bootstrap init && plan`
  (revisar juntos: 6-7 recursos, nada que borrar) `&& apply`. Comprobar con
  `aws s3api get-bucket-versioning --bucket <bucket> --profile personal` → `Enabled`.
- [ ] **Step 6:** commit `feat(infra): bucket S3 para el estado de Terraform (bootstrap)` (con el lock file).

### Task 2: VM `k3s` en Proxmox (`infra/proxmox/`)

**Files:**
- Create: `infra/proxmox/{versions.tf,providers.tf,variables.tf,main.tf,outputs.tf}`,
  `infra/proxmox/cloud-init.yaml.tftpl`, `infra/proxmox/terraform.tfvars.example`,
  `infra/proxmox/backend.hcl.example`, `infra/proxmox/tests/vm.tftest.hcl`

**Interfaces:**
- Consumes: bucket de la Tarea 1 (vía `backend.hcl`, configuración parcial del backend `s3`).
- Produces: outputs `ip` (sin máscara), `ssh` (`"ssh -i ~/.ssh/homelab_ed25519 ubuntu@<ip>"`) y
  `kubeconfig` (comando que trae el kubeconfig con la IP en lugar de `127.0.0.1`). Variable
  `memoria_mib` (default 8192).

- [ ] **Step 1: test que falla** — `tests/vm.tftest.hcl` con `mock_provider "proxmox" {}` y `command = plan`,
  variables de ejemplo (`ip_cidr = "192.0.2.50/24"`, `gateway = "192.0.2.1"`, `k3s_version = "v1.99.0+k3s1"`):
  - `cloud_init_contiene_k3s_fijado`: `strcontains(local.cloud_init, "INSTALL_K3S_VERSION=v1.99.0+k3s1")`
    y `strcontains(local.cloud_init, "--tls-san 192.0.2.50")`.
  - `vm_con_los_recursos_del_diseno`: `memory[0].dedicated == 8192`, `cpu[0].cores == 4`,
    `disk[0].size == 40`, `network_device[0].bridge == "vmbr0"`, `vm_id == 210`, `on_boot == true`.
  - `ip_sin_mascara_falla`: `ip_cidr = "192.0.2.50"` → `expect_failures = [var.ip_cidr]`.
  - `gateway_fuera_de_la_red_falla`: `gateway = "198.51.100.1"` → `expect_failures = [var.gateway]`.
- [ ] **Step 2:** `terraform -chdir=infra/proxmox init -backend=false && terraform test` → FAIL.
- [ ] **Step 3: código.**
  - `versions.tf`: `required_version = ">= 1.10"`, `bpg/proxmox` con `~>` a la última minor, backend
    `s3 {}` vacío (bucket, `key = "proxmox/terraform.tfstate"`, región, `profile`, `use_lockfile = true`
    van en `backend.hcl`; `backend.hcl.example` con `bucket = "topology-scanner-tfstate-123456789012"`).
  - `providers.tf`: endpoint y token por entorno (`PROXMOX_VE_ENDPOINT`, `PROXMOX_VE_API_TOKEN`, nunca en
    variables), `insecure = var.proxmox_insecure` (default `true`, certificado autofirmado del host),
    bloque `ssh { username = "root"; private_key = file(pathexpand(var.ssh_clave_privada)) }`.
  - `variables.tf`: `nodo` (default `"pve"`), `ip_cidr` (validación: `can(cidrhost(var.ip_cidr, 0))` y
    contiene `/`), `gateway` (validación entre variables, TF ≥ 1.9:
    `cidrsubnet("${var.gateway}/${split("/", var.ip_cidr)[1]}", 0, 0) == cidrsubnet(var.ip_cidr, 0, 0)`), `dns` (lista, default `[gateway]`), `k3s_version`,
    `memoria_mib` = 8192, `ssh_clave_publica` = `"~/.ssh/homelab_ed25519.pub"`,
    `ssh_clave_privada` = `"~/.ssh/homelab_ed25519"`, `proxmox_insecure`.
  - `main.tf`: `proxmox_virtual_environment_download_file` (`content_type = "import"`, `local`, URL de
    la imagen `ubuntu-26.04-server-cloudimg-amd64.img` de `cloud-images.ubuntu.com/releases` con
    `checksum`/`checksum_algorithm = "sha256"`); `proxmox_virtual_environment_file` (`snippets` en
    `local`, `source_raw` con `local.cloud_init = templatefile(...)`); `proxmox_virtual_environment_vm`
    `k3s`: `agent.enabled`, `cpu.type = "host"`, disco `scsi0` en `local-lvm` importado de la imagen,
    `initialization` con `ip_config.ipv4`, `dns` y `user_data_file_id`; `on_boot = true`;
    `operating_system.type = "l26"`.
  - `cloud-init.yaml.tftpl`: usuario `ubuntu` con la clave pública, `package_update`,
    `qemu-guest-agent` (instalado y arrancado), y `runcmd`:
    `curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION=${k3s_version} sh -s - --tls-san ${ip}
    --write-kubeconfig-mode 0600`.
  - `terraform.tfvars.example`: valores de `192.0.2.0/24`.
- [ ] **Step 4:** `terraform test` → PASS; `terraform fmt -check -recursive infra/` → OK.
- [ ] **Step 5:** commit `feat(infra): VM k3s en Proxmox con Terraform y cloud-init` (con el lock file).

### Task 3: Terraform en la CI

**Files:**
- Modify: `.github/workflows/ci.yml` (job nuevo `terraform`)

- [ ] **Step 1:** job `terraform` (ubuntu-latest): checkout, `hashicorp/setup-terraform` **fijado por SHA**
  (resolverlo con `gh api repos/hashicorp/setup-terraform/git/ref/tags/<tag>`, con `# vX.Y.Z` al lado),
  `terraform fmt -check -recursive infra/`, y para `infra/aws/bootstrap` e `infra/proxmox`:
  `init -backend=false` + `validate`; en `infra/proxmox` además `terraform test`.
- [ ] **Step 2:** `pytest tests/test_workflows.py -v` → PASS; suite completa y ruff en verde.
- [ ] **Step 3:** commit `ci: fmt, validate y test de Terraform`.

### Task 4: Crear la VM y conectar kubectl (operación, sin commit)

- [ ] **Step 1: [A MANO] en el host Proxmox**:
  - Rol `TerraformProv` con los privilegios mínimos que pide la documentación de `bpg/proxmox` para
    VMs, almacenamiento y descarga de archivos (lista exacta en el runbook) → usuario `terraform@pve`
    → token `terraform@pve!fase2` con `--privsep 0` → ACL en `/` con ese rol.
  - `local`: añadir `snippets,import` a su `content`, manteniendo lo que ya tiene (mirar antes
    `/etc/pve/storage.cfg`).
  - Clave `homelab_ed25519.pub` en `/root/.ssh/authorized_keys`; probar `ssh -i ~/.ssh/homelab_ed25519 root@<host>`.
- [ ] **Step 2: [A MANO]** comprobar en el MikroTik que la IP elegida está fuera del pool de DHCP y libre
  (`ping` sin respuesta).
- [ ] **Step 3:** `terraform.tfvars` y `backend.hcl` reales; `PROXMOX_VE_ENDPOINT` / `PROXMOX_VE_API_TOKEN`
  en la sesión; `k3s_version` = canal `stable` de `https://update.k3s.io/v1-release/channels`.
- [ ] **Step 4: [A MANO]** `terraform init -backend-config=backend.hcl`, `plan` (revisar juntos), `apply`.
- [ ] **Step 5:** comando del output `kubeconfig` → `~/.kube/config-homelab`;
  `kubectl --kubeconfig ~/.kube/config-homelab get nodes` → `k3s   Ready`.
- [ ] **Step 6:** `terraform plan` otra vez → **No changes** (Review Focus 1). Si no, corregir
  (p. ej. `lifecycle { ignore_changes = [...] }` justificado) y volver a la Tarea 2 para el commit.
- [ ] **Step 7:** `aws s3 ls s3://<bucket>/proxmox/ --profile personal` → `terraform.tfstate`.

### Task 5: Documentación

**Files:**
- Create: `docs/devops/runbooks/02-proxmox-vm.md`
- Modify: `docs/devops/README.md` (fase 2 → "Hecha", piezas nuevas), `docs/decisiones.md`, `CLAUDE.md`
  (estructura `infra/`, comandos de Terraform, CI con job `terraform`)

- [ ] **Step 1:** runbook (mismo formato que `01-contenedor.md`): requisitos, lo que se hace a mano y por
  qué (token, snippets, clave root, IP fuera del DHCP), bootstrap, `init/plan/apply`, kubeconfig,
  comprobaciones, SSO caducado, cómo cambiar la RAM, cómo destruir y recrear la VM, nota sobre la ARC.
- [ ] **Step 2:** `docs/decisiones.md`: las cinco decisiones de arriba, con su porqué (y por qué SSH como
  root solo para snippets; por qué SSE-S3 y no KMS).
- [ ] **Step 3:** suite + ruff en verde; commit `docs: runbook de la fase 2 (VM de Proxmox como código)`.
- [ ] **Step 4:** push y PR a `main`.
