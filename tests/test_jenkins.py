"""
Tests del despliegue por Jenkins (deploy/jenkins/): ejecutan los scripts de
verdad con `sh`, con los programas externos (curl, helm, kubectl...) falsos en
el PATH. La lógica vive en los scripts para poder probar sin clúster los caminos
de fallo, que son justo los que peor se ensayan en vivo.

Se saltan si no hay `sh`.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parents[1]
JENKINS = RAIZ / "deploy" / "jenkins"
SH = shutil.which("sh")

necesita_sh = pytest.mark.skipif(SH is None, reason="sin sh")


def _falso(carpeta: Path, nombre: str, cuerpo: str):
    """Programa falso para el PATH, con finales LF aunque los tests corran en Windows."""
    carpeta.mkdir(exist_ok=True)
    programa = carpeta / nombre
    programa.write_text(f"#!/bin/sh\n{cuerpo}\n", encoding="utf-8", newline="\n")
    programa.chmod(0o755)


def _ejecutar(script: str, *args: str, bin_falso: Path | None = None, stdin: str = "", **entorno: str):
    ruta = f"{bin_falso.as_posix()}:{os.environ['PATH']}" if bin_falso else os.environ["PATH"]
    return subprocess.run(
        [SH, (JENKINS / script).as_posix(), *args],
        input=stdin, env={**os.environ, "PATH": ruta, **entorno}, capture_output=True, text=True,
    )


# --- elegir_version.sh -------------------------------------------------------


@necesita_sh
@pytest.mark.parametrize(("tags", "desplegada", "fallidas", "esperada"), [
    ("v1.4.0\nv1.5.0\n", "1.4.0", "", "1.5.0"),
    ("v1.9.0\nv1.10.0\n", "1.9.0", "", "1.10.0"),
    ("v1.4.0\n", "1.4.0", "", ""),
    ("v1.3.0\n", "1.4.0", "", ""),
    ("v1.5.0\n", "1.4.0", "1.5.0\n", ""),
    ("v1.5.0\nv1.6.0\n", "1.4.0", "1.6.0\n", "1.5.0"),
    ("v1.5.0-rc1\nv1.5\nrelease-1\n", "1.4.0", "", ""),
    ("", "1.4.0", "", ""),
])
def test_elegir_version(tags, desplegada, fallidas, esperada, tmp_path):
    archivo = tmp_path / "fallidas"
    archivo.write_text(fallidas, encoding="utf-8", newline="\n")

    resultado = _ejecutar("elegir_version.sh", desplegada, archivo.as_posix(), stdin=tags)

    assert resultado.returncode == 0, resultado.stderr
    assert resultado.stdout.strip() == esperada


@necesita_sh
def test_elegir_version_sin_desplegada_es_error(tmp_path):
    """Tratar "no sé qué hay desplegado" como "nada" haría desplegar cualquier tag."""
    archivo = tmp_path / "fallidas"
    archivo.write_text("", encoding="utf-8")

    resultado = _ejecutar("elegir_version.sh", "", archivo.as_posix(), stdin="v1.5.0\n")

    assert resultado.returncode == 2
    assert resultado.stdout == ""


@necesita_sh
def test_elegir_version_sin_archivo_de_fallidas_es_error(tmp_path):
    """Tratar "no sé cuáles fallaron" como "ninguna" reabriría el bucle de reintentos."""
    resultado = _ejecutar("elegir_version.sh", "1.4.0", (tmp_path / "no-existe").as_posix(), stdin="v1.5.0\n")

    assert resultado.returncode == 2
    assert resultado.stdout == ""


# --- comprobar_publicada.sh --------------------------------------------------


def _curl_falso(tmp_path: Path, release: int, ghcr: int) -> tuple[Path, Path]:
    """curl falso: apunta las URLs y responde el código pedido a cada una."""
    bin_falso = tmp_path / "bin"
    log = tmp_path / "curl.log"
    _falso(bin_falso, "curl", f"""
echo "$*" >> "{log.as_posix()}"
case "$*" in
  *api.github.com*) printf '{release}' ;;
  *ghcr.io/token*) printf '{{"token":"t0k3n"}}' ;;
  *ghcr.io/v2/*) printf '{ghcr}' ;;
  *) exit 7 ;;
esac
""")
    return bin_falso, log


@necesita_sh
@pytest.mark.parametrize(("release", "ghcr", "codigo"), [
    (200, 200, 0),
    (404, 200, 1),   # la release se crea la última: todavía no ha terminado
    (200, 404, 1),
    (500, 200, 1),   # un error de GitHub es "todavía no", no un fallo definitivo
    (403, 200, 1),   # límite de peticiones
    (200, 503, 1),
])
def test_comprobar_publicada(release, ghcr, codigo, tmp_path):
    bin_falso, _ = _curl_falso(tmp_path, release, ghcr)

    assert _ejecutar("comprobar_publicada.sh", "1.5.0", bin_falso=bin_falso).returncode == codigo


@necesita_sh
def test_comprobar_publicada_pregunta_por_esa_version(tmp_path):
    bin_falso, log = _curl_falso(tmp_path, 200, 200)

    _ejecutar("comprobar_publicada.sh", "1.5.0", bin_falso=bin_falso, REPO_GITHUB="o/r", IMAGEN_GHCR="o/i")

    llamadas = log.read_text(encoding="utf-8")
    assert "repos/o/r/releases/tags/v1.5.0" in llamadas
    assert "v2/o/i/manifests/1.5.0" in llamadas
    assert "Bearer t0k3n" in llamadas


@necesita_sh
def test_comprobar_publicada_sin_red_cuenta_como_no_publicada(tmp_path):
    bin_falso = tmp_path / "bin"
    _falso(bin_falso, "curl", "exit 7")

    assert _ejecutar("comprobar_publicada.sh", "1.5.0", bin_falso=bin_falso).returncode == 1
