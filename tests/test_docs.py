"""Documentación de portada: enlaces relativos que no den 404 en GitHub y diagramas presentes.

Un enlace roto en el README o en docs/architecture.md no lo nota nadie hasta que
alguien (un reclutador, por ejemplo) hace clic y le sale un 404.
"""

import re
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
# [texto](destino): solo destinos relativos (ni http(s) ni anclas sueltas); se quita el #ancla.
ENLACE = re.compile(r"\]\((?!https?://|#|mailto:)([^)#\s]+)")
RUNBOOKS = sorted((RAIZ / "docs" / "devops" / "runbooks").glob("0*.md"))


def _leer(doc: str) -> str:
    return (RAIZ / doc).read_text(encoding="utf-8")


@pytest.mark.parametrize("doc", ["README.md", "docs/architecture.md"])
def test_enlaces_relativos_existen(doc):
    base = (RAIZ / doc).parent
    rotos = [d for d in ENLACE.findall(_leer(doc)) if not (base / d).exists()]
    assert rotos == [], f"{doc} enlaza a archivos que no existen: {rotos}"


def test_arquitectura_tiene_diagramas():
    assert _leer("docs/architecture.md").count("```mermaid") >= 2


def test_arquitectura_enlaza_los_8_runbooks():
    texto = _leer("docs/architecture.md")
    assert len(RUNBOOKS) == 8
    faltan = [r.name for r in RUNBOOKS if f"devops/runbooks/{r.name}" not in texto]
    assert faltan == []
