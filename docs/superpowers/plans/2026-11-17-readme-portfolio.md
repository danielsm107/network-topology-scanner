# README de portfolio + arquitectura en inglés — plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Que el README venda en 30 segundos el escáner y la plataforma DevOps que lo ejecuta, con diagrama, y que `docs/architecture.md` cuente las 8 fases en inglés.

**Architecture:** Solo documentación. Un test nuevo (`tests/test_docs.py`) protege lo que se puede romper sin que nadie lo note: enlaces relativos rotos y el diagrama Mermaid ausente.

**Tech Stack:** Markdown + Mermaid (lo pinta GitHub), pytest.

**Spec:** `docs/superpowers/specs/2026-11-17-readme-portfolio-design.md`

## Global Constraints

- Todo en inglés salvo los runbooks enlazados (siguen en español, y se dice: "(in Spanish)").
- Ningún dato real: IPs, dominios, ID de cuenta AWS, buckets con la cuenta, MACs. Ejemplos con `192.0.2.0/24` / `198.51.100.0/24`.
- Sin exageraciones ("production-grade", "enterprise"): homelab, y se dice.
- `pip install` y `docker run` visibles en la primera pantalla tras las capturas (Quick start no se mueve de sitio relativo).
- Rama `readme-portfolio`; `pytest tests/ -v` y `ruff check src/ tests/ scripts/` en verde antes de cada commit.

## Review Focus

- Enlaces relativos de `architecture.md` a `devops/runbooks/*.md` y de README a `docs/architecture.md`: un nombre mal escrito da 404 en GitHub → test de enlaces (Tarea 1).
- Mermaid con sintaxis inválida: GitHub muestra un error en rojo en la portada → comprobar en la vista previa del PR (Tarea 3) y con `mmdc` si está disponible.
- Etiquetas Mermaid con paréntesis/barras sin comillas rompen el parseo → todas las etiquetas entre comillas `["..."]`.
- Imágenes del README con URL absoluta `raw.githubusercontent.com` (necesario para PyPI): no pasarlas a relativas.
- Datos reales colados al resumir runbooks (dominio de NPM, rangos de la LAN) → revisión manual con `grep` (Tarea 3).

---

### Task 1: `docs/architecture.md` + test de enlaces

**Files:**
- Create: `docs/architecture.md`
- Create: `tests/test_docs.py`

**Interfaces:**
- Produces: `docs/architecture.md` con anclas `#overview`, `#release-flow`, `#phases`, `#decisions-worth-asking-about` (el README enlaza a ellas).

- [ ] **Step 1: test que falla**

```python
RAIZ = Path(__file__).resolve().parent.parent
ENLACE = re.compile(r"\]\((?!https?://|#)([^)#\s]+)")

@pytest.mark.parametrize("doc", ["README.md", "docs/architecture.md"])
def test_enlaces_relativos_existen(doc): ...   # cada destino relativo al doc existe

def test_arquitectura_tiene_diagramas():        # >= 2 bloques ```mermaid
def test_arquitectura_enlaza_los_8_runbooks():  # 00-..07-*.md enlazados
```

- [ ] **Step 2:** `pytest tests/test_docs.py -v` → FAIL (no existe `docs/architecture.md`).
- [ ] **Step 3: escribir `docs/architecture.md`** a partir de `docs/devops/README.md`, los runbooks y `docs/decisiones.md`:
  - **Overview**: 1 párrafo + diagrama Mermaid general (`flowchart LR`, subgrafos: Maintainer PC, GitHub, Registries, Proxmox/k3s, AWS, Alerting; la LAN escaneada).
  - **Release flow**: diagrama de secuencia tag → CI → PyPI/GHCR → Jenkins sondea → `helm upgrade` → `helm test` → ok / rollback + email.
  - **Phases**: tabla o lista 0-7: qué, por qué (1-2 frases), runbook (in Spanish).
  - **Decisions worth asking about**: 6-8 entradas cortas (decisión → alternativa descartada → por qué), sacadas de `decisiones.md`.
  - **What it doesn't do**: homelab de un nodo, sin HA, cortes de luz fuera de alcance, nada expuesto a internet.
- [ ] **Step 4:** `pytest tests/test_docs.py -v` → PASS; `ruff check src/ tests/ scripts/` → OK.
- [ ] **Step 5: commit** `docs: arquitectura y fases DevOps en inglés (docs/architecture.md)`

### Task 2: README reordenado

**Files:**
- Modify: `README.md` (líneas 1-19 cabecera; 250-259 "Deployment (homelab + AWS)"; 271-288 Roadmap)

**Interfaces:**
- Consumes: anclas de `docs/architecture.md` (Tarea 1).

- [ ] **Step 1: test que falla** en `tests/test_docs.py`:
  `test_readme_tiene_diagrama_y_enlaza_arquitectura` → README contiene un bloque ```mermaid antes de la primera captura y enlaza `docs/architecture.md`.
- [ ] **Step 2:** `pytest tests/test_docs.py -v` → FAIL.
- [ ] **Step 3: editar README**:
  - Cabecera: badges (CI + PyPI + licencia si existe), frase doble ("A network topology scanner — and the small self-hosted platform that builds, deploys, monitors and backs it up"), párrafo de la herramienta acortado, diagrama Mermaid general (versión simplificada del de architecture.md, ≤ 15 nodos), capturas.
  - "Deployment (homelab + AWS)" → **"How it runs"** (~30 líneas): 1 párrafo + viñetas con las decisiones del spec (OIDC sin claves; tag → Jenkins → `helm test` → rollback; actions por SHA + Trivy; sin root con setcap; Watchdog → healthchecks.io; ensayos de fallo reales) + enlace a `docs/architecture.md`.
  - Roadmap: añadir `[x]` Jenkins CD, Prometheus/Grafana + Telegram, logs con Loki.
- [ ] **Step 4:** `pytest tests/ -v` y `ruff check src/ tests/ scripts/` → verde.
- [ ] **Step 5: commit** `docs(readme): portada de portfolio con diagrama y "How it runs"`

### Task 3: verificación y PR

- [ ] **Step 1:** buscar datos reales: `grep -nE '192\.168\.|10\.0\.10|599297|danielserrano' README.md docs/architecture.md` → sin resultados.
- [ ] **Step 2:** validar Mermaid (`npx -y @mermaid-js/mermaid-cli` sobre cada bloque si hay Node; si no, en la vista previa del PR).
- [ ] **Step 3:** push + PR; abrir la vista del PR y comprobar que ambos diagramas se pintan. El merge lo hace el usuario.
