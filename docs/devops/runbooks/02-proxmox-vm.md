# Fase 2 — VM de Proxmox como código

**Objetivo:** que la VM donde corre k3s no sea una VM "hecha a mano" sino
código: `terraform apply` la crea en Proxmox con cloud-init, instala k3s en una
versión fijada, y `kubectl` funciona desde el PC. Si se rompe, se tira y se
vuelve a crear igual. Es la base de la fase 3 (despliegue en Kubernetes).

**Resultado verificable:**

- [x] Bucket S3 para el estado de Terraform (`infra/aws/bootstrap/`).
- [x] VM k3s en Proxmox con Terraform y cloud-init (`infra/proxmox/`).
- [x] La CI pasa `fmt`, `validate` y `terraform test` (job `terraform` de `ci.yml`).
- [x] `kubectl get nodes` responde `Ready` desde el PC (2026-10-29).
- [x] Un segundo `terraform plan` dice **No changes** y el estado está en S3.

## Piezas

```
infra/aws/bootstrap/   # bucket del estado (estado local, ignorado por git)
infra/proxmox/
├── main.tf                    # imagen de Ubuntu, snippets de cloud-init y la VM
├── cloud-init.yaml.tftpl      # user-data: usuario ubuntu, guest agent, k3s
├── network-config.yaml.tftpl  # red con IP fija (ver "La IP fija y dracut")
├── variables.tf               # con validación de IP/máscara y gateway
├── providers.tf               # bpg/proxmox: token por entorno, SSH solo para snippets
├── outputs.tf                 # ip, ssh, kubeconfig
├── tests/vm.tftest.hcl        # terraform test con el provider simulado
├── terraform.tfvars.example   # → terraform.tfvars (ignorado)
└── backend.hcl.example        # → backend.hcl (ignorado)
```

Nada real va al repo: IP, gateway, dominio del host, token, ID de cuenta y
nombre del bucket viven en `terraform.tfvars`, `backend.hcl` y el entorno.

## Requisitos en el PC

- Terraform y kubectl (`winget install Hashicorp.Terraform Kubernetes.kubectl`).
- AWS CLI con el perfil `personal` (SSO, fase 0). **Nunca el perfil `default`**:
  en este PC es otra cuenta. `backend.hcl` ya lleva `profile = "personal"`.
- La clave SSH del homelab (`~/.ssh/homelab_ed25519`).

## A mano en Proxmox (una vez)

Lo que Terraform no puede hacer por sí mismo, porque es justo lo que le da acceso.

### Token de API con privilegios mínimos

En la shell del host:

```bash
pveum role add TerraformProv -privs "Datastore.Allocate Datastore.AllocateSpace \
  Datastore.AllocateTemplate Datastore.Audit SDN.Audit SDN.Use Sys.AccessNetwork \
  Sys.Audit VM.Allocate VM.Audit VM.Config.CDROM VM.Config.Cloudinit VM.Config.CPU \
  VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network \
  VM.Config.Options VM.GuestAgent.Audit VM.PowerMgmt"
pveum user add terraform@pve --comment "Terraform (topology-scanner)"
pveum aclmod / -user terraform@pve -role TerraformProv
pveum user token add terraform@pve fase2 --privsep 0
```

- Solo lo que usan los recursos de `main.tf`: descargar la imagen
  (`Datastore.AllocateTemplate`, `Sys.AccessNetwork`), crear y configurar la VM
  (`VM.*`), conectarla al bridge (`SDN.Use`) y leer su IP por el guest agent
  (`VM.GuestAgent.Audit`). La documentación de `bpg/proxmox` propone una lista
  más amplia (consola, migración, pools, `Sys.Modify`...) para cubrir todos sus
  recursos; aquí no hace falta.
- `--privsep 0`: el token hereda los permisos del usuario, que solo tiene ese rol.
- El secreto del token **solo se ve al crearlo**. Va a un archivo fuera del repo
  y se carga en la sesión; nunca en `terraform.tfvars`, que acaba en el plan y
  en el estado:

  ```bash
  # ~/.config/topology-scanner/proxmox.env
  PROXMOX_VE_ENDPOINT=https://<host>:8006/
  PROXMOX_VE_API_TOKEN=terraform@pve!fase2=<secreto>
  ```

### `snippets` e `import` en el storage `local`

cloud-init lee el user-data y la red de archivos *snippet*, y la imagen de
Ubuntu se descarga como contenido `import`. Ninguno viene activado. Mirar
antes lo que ya tiene (`/etc/pve/storage.cfg`) y **añadir** sin quitar nada:

```bash
pvesm set local --content iso,vztmpl,backup,snippets,import   # lo que tenía + los dos nuevos
pvesm status --content import                                 # tiene que salir local
```

### SSH como root, solo para los snippets

La API de Proxmox no deja subir snippets: el provider entra por SSH al nodo
(`providers.tf`). Todo lo demás va por el token.

- La clave pública en `/root/.ssh/authorized_keys` del host.
- **Verificar la huella del host** antes de aceptarla, comparándola con la de
  la consola de Proxmox (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`).
  Un "yes" sin mirar en la primera conexión es justo lo que aprovecha un
  ataque de intermediario.

### IP fuera del pool DHCP

La VM lleva IP fija. Si cae dentro del pool del servidor DHCP, tarde o
temprano se la dará a otro equipo: **conflicto de IP silencioso**, que se
manifiesta como cortes intermitentes. Antes del `apply`:

1. Mirar el pool en el router que da DHCP en **esa** red (que no tiene por qué
   ser el router principal: en este homelab es otro equipo).
2. Elegir una IP fuera del pool y comprobar que está libre (`ping` sin respuesta).
3. Ponerla en `terraform.tfvars` (`ip_cidr`, con máscara, y `gateway`).

Otra opción sería una reserva DHCP, pero exige fijar la MAC de la VM y usar
DHCP en cloud-init. La IP fuera del pool no depende del router.

## Bootstrap del estado (una vez)

El estado de `infra/proxmox` va a S3, pero el bucket no puede guardarse en sí
mismo: `infra/aws/bootstrap/` lo crea con estado local (ignorado por git), con
versionado, cifrado SSE-S3, sin acceso público y `prevent_destroy`.

```bash
aws sso login --profile personal
cd infra/aws/bootstrap
terraform init && terraform apply
terraform output bucket_estado     # → bucket en infra/proxmox/backend.hcl
```

## Crear la VM

```bash
cd infra/proxmox
cp terraform.tfvars.example terraform.tfvars   # IP, gateway, k3s_version
cp backend.hcl.example backend.hcl             # bucket real
set -a; source ~/.config/topology-scanner/proxmox.env; set +a

terraform init -backend-config=backend.hcl
terraform plan -out=vm.tfplan      # revisar: 3 a crear
terraform apply vm.tfplan          # 5-10 min la primera vez (descarga la imagen)
```

- `k3s_version`: la del canal stable **del día**
  (<https://update.k3s.io/v1-release/channels/stable>), exacta. Así un
  `apply` dentro de seis meses instala lo mismo que hoy.
- `apply` de un plan guardado ejecuta exactamente lo revisado, sin preguntar.
  Si algo cambió desde el `plan`, se niega.
- Al terminar, cloud-init sigue trabajando dentro de la VM (paquetes, k3s) un
  par de minutos más.

**Si `init` o `plan` falla con `Token has expired and refresh failed`**: la
sesión de SSO caducó. `aws sso login --profile personal` y repetir.

## kubectl desde el PC

```bash
ssh -i ~/.ssh/homelab_ed25519 ubuntu@<ip> 'cloud-init status --wait'
mkdir -p ~/.kube
ssh -i ~/.ssh/homelab_ed25519 ubuntu@<ip> sudo cat /etc/rancher/k3s/k3s.yaml \
  | sed 's/127.0.0.1/<ip>/' > ~/.kube/config-homelab    # es el output `kubeconfig`
KUBECONFIG=~/.kube/config-homelab kubectl get nodes
```

El kubeconfig de k3s apunta a `127.0.0.1`; el `sed` lo cambia por la IP. Eso
solo funciona porque cloud-init instala k3s con `--tls-san <ip>`: sin ella,
kubectl falla con un error x509 (el certificado no incluye esa IP). Lo
comprueba `terraform test`. El archivo da acceso de administrador al clúster:
fuera del repo, y no en `~/.kube/config` para no mezclarlo con otros clústeres.

## Comprobaciones

1. `kubectl get nodes` → `k3s   Ready   control-plane`, con la versión fijada.
2. `kubectl get pods -A` → coredns, traefik, metrics-server y local-path en `Running`.
3. `cloud-init status --long` en la VM → `done`, **no `degraded done`**.
4. `terraform plan` otra vez → **No changes**. Si quisiera recrear algo,
   la configuración no describe lo que hay.
5. `aws s3 ls s3://<bucket>/proxmox/ --profile personal` → `terraform.tfstate`.

## La IP fija y dracut

El primer `apply` creó la VM con una IP del pool DHCP en vez de la fija.
`cloud-init status` decía `degraded done` con
`Error renaming mac=... from ens18 to eth0: [busy]`.

Cadena del fallo:

1. Con `ip_config` (el `ipconfig0` de Proxmox), Proxmox genera una red para una
   interfaz llamada **`eth0`**, siempre. netplan la traduce en un `.link` que
   renombra la tarjeta a `eth0` y un `.network` con la IP fija que solo aplica
   a una interfaz llamada `eth0`.
2. Las imágenes de Ubuntu 26.04 arrancan con un initramfs **dracut**, que ya ha
   levantado la tarjeta (`ens18`) por DHCP y deja
   `/run/systemd/network/zzzz-dracut-default.network` (DHCP para todo).
3. Una interfaz levantada no se puede renombrar → sigue siendo `ens18` → el
   `.network` de la IP fija no aplica → gana el de dracut → DHCP.

Arreglo: la red va en un snippet propio (`network-config.yaml.tftpl`,
`network_data_file_id`) en formato netplan, que busca la tarjeta por su nombre
real (`match: name: "en*"`) y **no la renombra**. Su `.network` se llama
`10-netplan-lan.network`, y networkd usa el primero en orden alfabético que
coincida: gana a `zzzz-dracut-default`. Lo cubre `terraform test`
(`red_fija_sin_renombrar_la_interfaz`).

Cómo se diagnosticó, por si vuelve a pasar algo parecido: el guest agent dice
la IP real aunque no sea la esperada (Proxmox → VM → *Summary*, o
`/agent/network-get-interfaces` por la API); se entra por esa IP y
`networkctl status <interfaz>` dice qué `.network` la gestiona.

## Operar la VM

**Cambiar la RAM:** `memoria_mib` en `terraform.tfvars` (6144 si se vuelve a
encender la VM 202, que no cabe a la vez con 8 GiB). `plan` → actualización
*in-place* (el provider reinicia la VM), no la recrea.

**Cambiar cloud-init (paquetes, versión de k3s, red):** cloud-init solo corre
en el **primer arranque** de una instancia. Cambiar el snippet recrea la VM
(`forces replacement` en el plan); es lo esperado, no un fallo.

**Destruir y recrear:**

```bash
terraform apply -replace=proxmox_virtual_environment_vm.k3s   # recrear solo la VM
terraform destroy                                             # todo (imagen y snippets incluidos)
```

Después de recrearla:

- La VM tiene **otra clave de host SSH**: `ssh-keygen -R <ip>` antes de entrar.
- k3s genera **otros certificados**: volver a traer el kubeconfig.
- Lo que hubiera en el clúster se pierde. En la fase 3 todo lo desplegado
  estará también como código, así que se vuelve a aplicar.

**ZFS y RAM:** el host usa ZFS, cuya caché (ARC) puede quedarse con mucha RAM
(hasta la mitad en instalaciones antiguas de Proxmox) y compite con las VMs. En este homelab ya está limitada
(~1,5 GiB) y los discos de VM van en `local-lvm`, así que no hay nada que
hacer; en otro host con ZFS, comprobar `/sys/module/zfs/parameters/zfs_arc_max`.

## CI

Job `terraform` de `.github/workflows/ci.yml`: `terraform fmt -check`,
`init -backend=false` + `validate` en cada raíz de `infra/`, y `terraform test`
en `infra/proxmox` (con `mock_provider`: ni token ni Proxmox, por eso corre en
GitHub). `tests/test_workflows.py` comprueba que ninguna raíz de `infra/` se
queda sin validar. **El `apply` nunca corre en la CI**: la API de Proxmox solo
es accesible desde la LAN, y no se abre nada hacia fuera.
