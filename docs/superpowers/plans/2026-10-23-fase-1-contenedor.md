# Fase 1 (contenedor): lo que falta — plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cerrar la fase 1: la CI construye y escanea la imagen, cada release publica
`ghcr.io/danielsm107/topology-scanner:X.Y.Z`, y quien llegue de fuera (Reddit,
r/selfhosted) puede usar la imagen con un `compose.yaml` y errores comprensibles.

**Architecture:** El `Dockerfile` y el `.dockerignore` ya existen (sin commit) y la
prueba L2 ya pasó (2026-10-23: MAC y fabricante visibles desde el contenedor en la
LAN B, nmap como UID 10001 con `setcap`). Se añaden dos arreglos en la app que la
prueba destapó, un job de imagen en `ci.yml`, otro en `release.yml`, y la
documentación. La v1.2.1 es la primera release que publica imagen.

**Tech Stack:** Docker (buildx), GitHub Actions, GHCR, Trivy, pytest.

**Spec:** `docs/superpowers/specs/2026-10-22-fase-devops-design.md` (fila "1 |
Contenedor" de la tabla de fases; "Registro de imágenes: GHCR"; "Seguridad en el
pipeline").

## Global Constraints

- Imagen publicada: `ghcr.io/danielsm107/topology-scanner:X.Y.Z` (y `latest`).
- "la imagen se escanea en CI (p. ej. Trivy) y el build falla con vulnerabilidades críticas que tengan arreglo".
- Solo `NET_RAW` y `NET_ADMIN`, nunca `privileged`; usuario no root (UID 10001, ya en el `Dockerfile`).
- GHCR y no ECR: imagen pública, descargable sin credenciales.
- Docs en castellano en `docs/`, inglés en el `README.md`; mensajes de la app en inglés.
- Datos inventados en tests y docs (IPs de documentación, MACs `02:00:00:…`): nada de la red real del mantenedor.
- `pytest tests/` y `ruff check src/ tests/ scripts/` en verde antes de cada commit; un commit por tarea.

## Review Focus

1. Contenedor lanzado **sin `--cap-add`**: hoy dice "nmap program was not found in path" aunque nmap está. Esperado: mensaje que diga que no se pudo ejecutar y cómo arreglarlo → Tarea 1 (test unitario) y Tarea 3 (smoke test de la imagen en CI).
2. **`/data` sin permisos de escritura** para el UID 10001 (carpeta del host de root): hoy traceback de `PermissionError` al escribir el HTML. Esperado: mensaje claro y salida con error → Tarea 2.
3. **Sin `--network host`** (red puente): escanea, pero sin MACs ni fabricantes. Esperado: documentado donde se copia el comando → Tarea 5 (`compose.yaml`, README).
4. **Docker Desktop (Windows/macOS)**: `--network host` no llega a la LAN en capa 2. Esperado: documentado como limitación → Tarea 5.
5. **`security_opt: no-new-privileges`** en el compose de alguien: anula las capacidades de archivo y vuelve al caso 1. Esperado: comentario en el `compose.yaml` y el mensaje de la Tarea 1 → Tarea 5.

---

### Task 1: Mensaje claro cuando nmap existe pero no se puede ejecutar

**Files:**
- Modify: `src/topology_scanner/scanner.py` (los dos `except nmap.PortScannerError`)
- Modify: `src/topology_scanner/webapp.py` (`_construir_comando_nmap`)
- Test: `tests/test_scanner.py`, `tests/test_webapp.py`

**Interfaces:**
- Produces: `scanner.error_de_nmap(e: nmap.PortScannerError) -> ScannerError` — fuente única del mensaje; la usan `scanner.py` (fases 1 y 2) y `webapp._construir_comando_nmap`.

- [ ] **Step 1: Tests que fallan** en `tests/test_scanner.py`:
  - `test_error_de_nmap_si_nmap_existe_pero_no_arranca_lo_dice`: `PortScannerError("nmap program was not found in path. PATH is : /usr/bin")` con `shutil.which` parcheado a `"/usr/bin/nmap"` → el mensaje contiene `"/usr/bin/nmap"` y `"--cap-add NET_RAW --cap-add NET_ADMIN"`, y no contiene `"not found"`.
  - `test_error_de_nmap_si_nmap_no_esta_mantiene_el_mensaje`: mismo error con `shutil.which` → `None` → mensaje igual al actual (`"nmap error (are you running with sudo?): ..."`).
  - `test_descubrir_hosts_vivos_usa_error_de_nmap`: `nmap.PortScanner` con `side_effect` ese error y `shutil.which` → ruta: `ScannerError` con `"--cap-add"`.
  - En `tests/test_webapp.py`, el equivalente para `_construir_comando_nmap`.
- [ ] **Step 2:** `pytest tests/test_scanner.py tests/test_webapp.py -k "error_de_nmap or cap" -v` → FAIL (`error_de_nmap` no existe).
- [ ] **Step 3:** `error_de_nmap` en `scanner.py`. Si el texto contiene `"was not found"` y `shutil.which("nmap")` devuelve ruta: `ScannerError(f"nmap is installed ({ruta}) but the system refused to run it. If you're running the Docker image, add --cap-add NET_RAW --cap-add NET_ADMIN (and don't use no-new-privileges).")`. Si no, el mensaje de hoy. Sustituir los tres `raise ScannerError(f"nmap error ...")` por `raise error_de_nmap(e) from e`.
- [ ] **Step 4:** suite completa + ruff → PASS.
- [ ] **Step 5:** commit `fix: mensaje claro cuando nmap está instalado pero no se puede ejecutar`.

### Task 2: Errores de escritura de las salidas sin traceback

**Files:**
- Modify: `src/topology_scanner/export.py` (`exportar_html`, `exportar_csv`, mensaje de pyvis en inglés)
- Modify: `src/topology_scanner/cli.py` (`exportar_csv` dentro de un `try/except ExportError`)
- Test: `tests/test_export.py`, `tests/test_cli.py`

**Interfaces:**
- Produces: `exportar_html` y `exportar_csv` lanzan `ExportError(f"Could not write {archivo}: {e.strerror}")` ante un `OSError` al escribir. Sin cambio de firma.

- [ ] **Step 1: Tests que fallan:**
  - `test_exportar_html_sin_permiso_lanza_export_error` y `test_exportar_csv_sin_permiso_lanza_export_error`: `open` parcheado con `PermissionError(13, "Permission denied")` → `ExportError` cuyo mensaje contiene el nombre del archivo y `"Permission denied"`.
  - `test_cli_sale_con_mensaje_si_no_puede_escribir_el_csv`: `exportar_csv` lanza `ExportError("Could not write x.csv: Permission denied")` → `SystemExit` con ese texto (como ya hace el HTML).
- [ ] **Step 2:** los tests → FAIL.
- [ ] **Step 3:** envolver la escritura en `try/except OSError` en las dos funciones; `"Falta pyvis. Instala con: pip install pyvis"` → `"pyvis is missing. Install it with: pip install pyvis"`.
- [ ] **Step 4:** suite + ruff → PASS.
- [ ] **Step 5:** commit `fix: error claro, sin traceback, si no se pueden escribir el HTML o el CSV`.

### Task 3: La CI construye, prueba y escanea la imagen

**Files:**
- Add: `Dockerfile`, `.dockerignore` (ya escritos, sin cambios salvo lo que pida Trivy)
- Modify: `.github/workflows/ci.yml` (job nuevo `imagen`, en paralelo con `test`)

- [ ] **Step 1:** job `imagen` en `ci.yml`: `docker/setup-buildx-action`, `docker/build-push-action` con `load: true`, `tags: topology-scanner:ci`, caché `type=gha`. Smoke tests, en pasos separados:
  - `docker run --rm --entrypoint id topology-scanner:ci -u` imprime `10001`.
  - `docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN --entrypoint nmap topology-scanner:ci --version` acaba en 0.
  - `docker run --rm topology-scanner:ci 127.0.0.1` (sin capacidades) acaba en ≠ 0 y su salida contiene `--cap-add` (prueba de extremo a extremo de la Tarea 1).
  - `docker run --rm --entrypoint python topology-scanner:ci -c "import topology_scanner.webapp"` acaba en 0 (el extra `[web]` está instalado).
- [ ] **Step 2:** Trivy sobre `topology-scanner:ci` con `--severity CRITICAL --ignore-unfixed --exit-code 1`. **Fijado por digest, no por tag**: las tags de `aquasecurity/trivy-action` se reescribieron en un ataque a la cadena de suministro en 2026. Comprobarlo al implementar y elegir entre la imagen oficial `aquasec/trivy` fijada por `@sha256:` o la action fijada por SHA de commit. Dejar el porqué en un comentario del workflow.
- [ ] **Step 3:** abrir la PR y comprobar que el job pasa. Si Trivy encuentra críticas con arreglo, actualizar la base (`python:3.12-slim-trixie`) o el paquete: no se silencia sin una entrada en `docs/decisiones.md`.
- [ ] **Step 4:** commit `ci: construye, prueba y escanea la imagen Docker` (con `Dockerfile` y `.dockerignore`).

### Task 4: La release publica la imagen en GHCR

**Files:**
- Modify: `.github/workflows/release.yml` (job nuevo `imagen`)

- [ ] **Step 1:** job `imagen`: `needs: build` (reutiliza la comprobación tag = versión), `if: github.event_name == 'push'`, `permissions: { contents: read, packages: write }`. `docker/login-action` contra `ghcr.io` con `GITHUB_TOKEN`; `docker/metadata-action` con tags `type=semver,pattern={{version}}` y `latest`, y etiqueta `org.opencontainers.image.source` (enlaza el paquete con el repo). `build-push-action` con `platforms: linux/amd64,linux/arm64` (la elección de arm64 es del plan: Raspberry Pi en homelabs; QEMU con `docker/setup-qemu-action`), `push: true`.
- [ ] **Step 2:** commit `ci: la release publica la imagen en ghcr.io`.
- [ ] **Paso manual del mantenedor (tras la primera publicación):** en GitHub → Packages → `topology-scanner` → *Change visibility* → **Public**. GHCR crea los paquetes privados; sin esto k3s y los usuarios no pueden descargarla sin credenciales.

### Task 5: Documentación y `compose.yaml`

**Files:**
- Create: `compose.yaml` (raíz), `docs/devops/runbooks/01-contenedor.md`, `docs/devops/README.md`
- Modify: `README.md` (sección *Docker*, inglés), `CLAUDE.md` (estructura y comandos), `docs/decisiones.md`

- [ ] **Step 1:** `compose.yaml` con dos servicios de la misma imagen `ghcr.io/danielsm107/topology-scanner:latest`: `web` (entrypoint `topology-scanner-web`) y `scan` (perfil `scan`, para `docker compose run --rm scan 192.0.2.0/24`). Los dos con `network_mode: host`, `cap_add: [NET_RAW, NET_ADMIN]` y volumen con nombre en `/data`. Comentarios: por qué host network, que `no-new-privileges` lo rompe, que solo vale en Linux (no Docker Desktop).
- [ ] **Step 2:** runbook `01-contenedor.md` (castellano, formato del `00`): construir, la prueba L2 y cómo comprobarla (resultado con datos inventados), capacidades y UID 10001, volumen con permisos, limitaciones (red puente, Docker Desktop), publicación en GHCR y el paso manual de visibilidad.
- [ ] **Step 3:** `docs/devops/README.md`: índice de runbooks y en qué fase está cada pieza. README (inglés): sección *Docker* corta con `docker run`, el compose y las limitaciones, que enlace al runbook. `CLAUDE.md`: `Dockerfile`, `compose.yaml` y los comandos. `docs/decisiones.md`: usuario no root con `setcap`, Trivy fijado por digest, multi-arch, visibilidad de GHCR.
- [ ] **Step 4:** comprobar el compose en `docker-lab` con la imagen local (`image: topology-scanner:dev` temporalmente o `docker compose build`): la web responde en `:8501` y `docker compose run --rm scan <rango>` escanea.
- [ ] **Step 5:** commit `docs: runbook de la fase 1, compose.yaml y sección Docker del README`.

### Task 6: v1.2.1, primera release con imagen

- [ ] **Step 1:** CHANGELOG `[1.2.1]` (Fixed: Tareas 1 y 2; Added: imagen en GHCR, `compose.yaml`), `version = "1.2.1"`, commit `release: v1.2.1`. PR, merge del mantenedor, tag `v1.2.1`.
- [ ] **Step 2:** `release.yml` en verde, incluido `imagen`. El mantenedor pone el paquete en público.
- [ ] **Step 3:** en `docker-lab`, `docker pull ghcr.io/danielsm107/topology-scanner:1.2.1` sin login y repetir la prueba L2 con esa imagen: MAC y fabricante visibles.
- [ ] **Step 4:** fase 1 cerrada: actualizar `docs/devops/README.md`.
