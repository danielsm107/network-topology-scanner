# Fase 1 — Contenedor

**Objetivo:** que la herramienta corra en una imagen Docker que escanee la LAN
igual que instalada en el equipo (con MAC y fabricante), como usuario sin
privilegios, y que cada release la publique en GHCR. Es la base de la fase 3
(Kubernetes): el CronJob de escaneo y la web usan esta misma imagen.

**Resultado verificable:**

- [x] `Dockerfile` + `.dockerignore`.
- [x] La imagen escanea la LAN con MAC y fabricante (prueba L2 del 2026-10-23).
- [x] La CI construye la imagen, la prueba y la escanea con Trivy (job `imagen` de `ci.yml`).
- [ ] La release publica `ghcr.io/danielsm107/topology-scanner:X.Y.Z` (job `imagen` de `release.yml`; se comprueba con la v1.2.1).

## La imagen

`Dockerfile` en dos etapas:

1. **build**: construye el wheel desde el código del repo (no desde PyPI), así
   la imagen es exactamente el commit que se construye.
2. **final**: `python:3.12-slim-trixie` + nmap + el wheel con los extras
   `[web,snmp]`. Ni el código fuente ni setuptools llegan a esta etapa.

`.dockerignore` deja fuera todo salvo `pyproject.toml`, `README.md`, `LICENSE`
y `src/`. Sobre todo, que ninguna salida de un escaneo local (`*.html`, `*.db`,
`*.csv`, con IPs y MACs reales) acabe dentro de una imagen pública.

```bash
docker build -t topology-scanner:dev .
docker run --rm topology-scanner:dev --help
```

## nmap sin root

Por qué: un contenedor que corre como root es root en el host si hay un fallo
de aislamiento, y en Kubernetes conviene poder exigir `runAsNonRoot`.

nmap necesita sockets raw (ARP para descubrir hosts en la LAN, SYN para los
puertos). En vez de ejecutarlo como root, el binario lleva **capacidades de
archivo** (`setcap cap_net_raw,cap_net_admin+eip`, solo esas dos) y la
imagen corre como el usuario `scanner`, **UID 10001** (fijo, porque los
volúmenes de Kubernetes se preparan por UID). `NMAP_PRIVILEGED=1` le dice a
nmap que use esos privilegios aunque no sea root: sin ella, al ver un usuario
normal, se limita a un escaneo TCP connect.

Las capacidades de archivo solo funcionan si el contenedor las tiene:

- `--cap-add NET_RAW --cap-add NET_ADMIN` (o `securityContext.capabilities.add`
  en Kubernetes). Sin ellas el kernel se niega a ejecutar nmap, y la app lo dice:
  *"nmap is installed (/usr/bin/nmap) but the system refused to run it..."*
  (`scanner.error_de_nmap`; python-nmap decía "not found", que despistaba).
- Sin `no-new-privileges` (Docker) ni `allowPrivilegeEscalation: false`
  (Kubernetes): anulan las capacidades de archivo y vuelve el caso anterior.

## Red: `--network host`

Con la red puente de Docker, nmap solo ve la red interna del contenedor: sin
MACs ni fabricantes de la LAN, y por tanto sin categorías. Con `--network host`
el contenedor usa la interfaz del host y está en el mismo segmento L2.

- Solo vale en **Linux**. Docker Desktop (Windows/macOS) corre los contenedores
  en una VM: ni con host network llegan a la LAN en capa 2.
- La MAC y el fabricante solo se ven en el **mismo segmento** que el host (igual
  que sin Docker). Lo que hay detrás de un router sale sin MAC; para eso está
  `--snmp`.

## El volumen `/data`

`/data` es el directorio de trabajo: ahí van `historial.db`, el HTML y el CSV.
Tiene que poder escribirlo el UID 10001:

- **Volumen con nombre** (`-v ts-datos:/data`, el del `compose.yaml`): Docker lo
  crea con el propietario del directorio de la imagen. Funciona sin más.
- **Carpeta del host** (`-v "$PWD/datos:/data"`): tiene que ser del UID 10001
  (`sudo chown 10001 datos`). Si no, el historial avisa y se salta, y el HTML
  falla con *"Could not write network_topology.html: Permission denied"*.

## Prueba L2

Lo que demuestra que la imagen sirve: escanear el segmento en el que está el
host y ver MAC y fabricante.

```bash
docker run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN \
    -v ts-datos:/data topology-scanner:dev <rango del segmento> --fast
```

Se comprueba:

1. Los hosts salen con `MAC` y `Vendor` (y la categoría que se deduce de él).
2. Ningún aviso de privilegios ni de escaneo TCP connect.
3. El propio host sale sin MAC: nmap nunca da la MAC del equipo desde el que
   escanea. Es normal.

Resultado (2026-10-23, VM `docker-lab` en Proxmox, Ubuntu 26.04, Docker 29):
8 hosts en 4 s, todos con MAC y fabricante salvo la propia VM. El router salió
como `Ubiquiti (router)` y las VMs/LXC de Proxmox como `Proxmox Server
Solutions GmbH (vm)`. Un host con tarjeta Realtek salió como `unknown`: el
fabricante de la tarjeta no dice qué es el equipo (límite conocido de la
clasificación por fabricante). Ejemplo de salida, con datos inventados:

```
[192.0.2.1] router.lan
  MAC         : 02:00:00:00:00:01
  Vendor      : Ubiquiti (router)
  - 22/tcp  ssh
  - 443/tcp  https
```

## CI: construir, probar, escanear

Job `imagen` de `.github/workflows/ci.yml`, en cada PR y push a `main`:

1. Construye la imagen (con caché de GitHub Actions).
2. Pruebas por fuera, como la usaría alguien: corre como UID 10001; nmap arranca
   con `NET_RAW`/`NET_ADMIN`; **sin ellas falla con el mensaje que dice qué
   hacer**; la web (extra `[web]`) está instalada.
3. **Trivy**: falla con vulnerabilidades críticas que ya tengan arreglo
   (`--severity CRITICAL --ignore-unfixed`). Las que no lo tienen no se pueden
   resolver actualizando.

Si Trivy encuentra una crítica con arreglo: actualizar la base o el paquete.
Silenciarla solo con una entrada en `docs/decisiones.md` que diga por qué.

**Toda action que no sea de GitHub (`actions/...`) va fijada por SHA, y Trivy
por digest**, no por tag (lo comprueba `tests/test_workflows.py`): en marzo de
2026 robaron credenciales de Aqua y reescribieron casi todas las tags de
`aquasecurity/trivy-action` y `setup-trivy` para robar los secretos de los
pipelines que las usaban. Trivy se ejecuta como imagen oficial
(`aquasec/trivy@sha256:...`, la 0.75.0), sin su action. Para actualizar un
digest o un SHA:

```bash
docker buildx imagetools inspect aquasec/trivy:<versión>       # Digest: sha256:...
gh api repos/docker/build-push-action/commits/<tag> --jq .sha  # igual para cada action
```

## Release: imagen en GHCR

Job `imagen` de `.github/workflows/release.yml`, con cada tag `vX.Y.Z` (después
de la comprobación tag = versión de `pyproject.toml`):

- Publica `ghcr.io/danielsm107/topology-scanner:X.Y.Z` y `:latest`, para
  `linux/amd64` y `linux/arm64` (Raspberry Pi; emulado con QEMU, por eso la
  release tarda unos minutos más).
- Se autentica con el `GITHUB_TOKEN` del workflow (`packages: write`): sin
  tokens personales ni secretos.
- La release de GitHub espera a PyPI y a la imagen.

**Paso manual (una vez, tras la primera publicación):** GHCR crea los paquetes
**privados**. En GitHub → perfil → *Packages* → `topology-scanner` → *Package
settings* → *Change visibility* → **Public**. Sin esto, ni k3s ni nadie la
puede descargar sin credenciales. Comprobación, sin `docker login`:

```bash
docker pull ghcr.io/danielsm107/topology-scanner:<versión>
```

## Docker Compose

`compose.yaml` (en la raíz, en inglés porque es para copiarlo): un servicio
`web` y un servicio `scan` (perfil `scan`, se lanza con `docker compose run`)
que comparten el volumen. **La web escucha solo en `127.0.0.1`**: no tiene
autenticación y escanea lo que le pidan, así que abrirla a la LAN
(`STREAMLIT_SERVER_ADDRESS: 0.0.0.0`) tiene que ser una decisión consciente.
En el clúster (fase 3) esto lo resuelve la lista de rangos permitidos.

```bash
docker compose up -d                                   # web en http://127.0.0.1:8501
docker compose run --rm scan <rango> --fast            # escaneo por CLI
```

## Mejoras apuntadas

- La imagen pesa ~990 MB: Streamlit arrastra pyarrow/pandas/numpy, y pyvis
  arrastra IPython. Dos targets (`cli` sin `[web]`, `web`) la reducirían para
  el CronJob de escaneo.
