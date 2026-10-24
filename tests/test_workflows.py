"""
Tests de los workflows de GitHub Actions (.github/workflows/*.yml).

Toda action que no sea de GitHub (actions/...) va fijada por SHA de commit:
una tag o una rama se pueden mover, y en marzo de 2026 reescribieron casi
todas las tags de aquasecurity/trivy-action para robar los secretos de los
pipelines que las usaban. Las de actions/ (mantenidas por GitHub) van por tag.
"""

import re
from pathlib import Path

CARPETA_WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
_USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)", re.MULTILINE)
_SHA = re.compile(r"^[0-9a-f]{40}$")


def _actions_usadas():
    for workflow in sorted(CARPETA_WORKFLOWS.glob("*.yml")):
        for uso in _USES.findall(workflow.read_text(encoding="utf-8")):
            yield workflow.name, uso


def test_hay_workflows_que_revisar():
    assert list(_actions_usadas())


def test_las_actions_de_terceros_van_fijadas_por_sha():
    sin_fijar = [
        f"{workflow}: {uso}"
        for workflow, uso in _actions_usadas()
        # ./.github/workflows/ci.yml (reutilizar un workflow propio) no es de terceros
        if not uso.startswith(("actions/", "./")) and not _SHA.match(uso.partition("@")[2])
    ]
    assert sin_fijar == []
