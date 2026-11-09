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


# --- desplegar.sh ------------------------------------------------------------


class Escenario:
    """Un despliegue con helm, kubectl, git, curl y aws falsos. Las opciones del
    test llegan por entorno (F_*); todas las llamadas quedan en `self.llamadas`."""

    def __init__(self, tmp_path: Path):
        self.bin = tmp_path / "bin"
        self.log = tmp_path / "llamadas.log"
        self.tmp = tmp_path
        imagen = (tmp_path / "imagen").as_posix()
        pruebas = (tmp_path / "pruebas").as_posix()
        registro = f'echo "$(basename "$0") $*" >> "{self.log.as_posix()}"'
        _falso(self.bin, "git", f"""{registro}
case "$1" in
  ls-remote) [ -z "${{F_GIT:-}}" ] || exit 1; printf '%s' "$F_TAGS" ;;
  clone) [ -z "${{F_CLONE:-}}" ] || exit 1; for ultimo; do :; done; mkdir -p "$ultimo" ;;
esac""")
        # F_TEST: "primero" falla la prueba tras el upgrade; "siempre", también tras el rollback
        _falso(self.bin, "helm", f"""{registro}
case "$1" in
  upgrade)
    [ -z "${{F_UPGRADE:-}}" ] || exit 1
    for a; do case "$a" in image.tag=*) echo "${{a#image.tag=}}" > "{imagen}" ;; esac; done ;;
  test)
    echo x >> "{pruebas}"
    [ "${{F_TEST:-}}" != "siempre" ] || exit 1
    if [ "${{F_TEST:-}}" = "primero" ] && [ "$(wc -l < "{pruebas}")" -eq 1 ]; then exit 1; fi
    [ -n "${{F_TEST_VACIO:-}}" ] || echo "Phase:          Succeeded" ;;
  rollback)
    [ -z "${{F_ROLLBACK:-}}" ] || exit 1
    echo "$F_DESPLEGADA" > "{imagen}" ;;
esac""")
        _falso(self.bin, "kubectl", f"""{registro}
case "$*" in
  *"get deploy"*labels*) [ -z "${{F_LECTURA:-}}" ] || exit 1; printf '%s' "$F_DESPLEGADA" ;;
  *"get deploy"*|*"get cronjob"*)
    if [ -n "${{F_IMAGEN:-}}" ]; then printf 'r/i:%s' "$F_IMAGEN"
    elif [ -f "{imagen}" ]; then printf 'r/i:%s' "$(cat "{imagen}")"; fi ;;
  *"get configmap"*) [ -z "${{F_FALLIDAS_ERROR:-}}" ] || exit 1; printf '%s' "${{F_FALLIDAS:-}}" ;;
  *"get secret"*) [ -z "${{F_SECRET:-}}" ] || exit 1; printf 'dmFsb3Jlcw==' ;;
esac""")
        _falso(self.bin, "aws", f"""{registro}
[ -z "${{F_SNS:-}}" ] || exit 1""")
        _falso(self.bin, "curl", """
case "$*" in
  *ghcr.io/token*) printf '{"token":"t"}' ;;
  *) printf '%s' "${F_PUBLICADA:-200}" ;;
esac""")

    def correr(self, modo="automatico", desplegada="1.4.0", tags=("1.4.0", "1.5.0"), **opciones):
        self.resultado = _ejecutar(
            "desplegar.sh", bin_falso=self.bin, MODO=modo, F_DESPLEGADA=desplegada,
            F_TAGS="".join(f"abc123\trefs/tags/v{tag}\n" for tag in tags),
            TOPIC_ARN="arn:aws:sns:eu-south-2:123456789012:t", URL_EJECUCION="https://jenkins.example.com/job/1/",
            ESPERA_SEGUNDOS="0", INTERVALO_SEGUNDOS="0", TMPDIR=self.tmp.as_posix(), **opciones,
        )
        return self.resultado

    @property
    def llamadas(self) -> str:
        return self.log.read_text(encoding="utf-8") if self.log.exists() else ""

    def correos(self) -> list[str]:
        """Cada email, con su asunto y cuerpo (el cuerpo ocupa varias líneas del log)."""
        return [f"aws sns publish{trozo}" for trozo in self.llamadas.split("aws sns publish")[1:]]

    def marcas(self) -> list[str]:
        return [linea for linea in self.llamadas.splitlines() if " patch " in linea]


@pytest.fixture
def escenario(tmp_path):
    if SH is None:
        pytest.skip("sin sh")
    return Escenario(tmp_path)


def test_automatico_sin_version_nueva_no_despliega(escenario):
    resultado = escenario.correr(tags=("1.4.0",))

    assert resultado.returncode == 0, resultado.stderr
    assert "helm upgrade" not in escenario.llamadas
    assert escenario.correos() == []


def test_automatico_camino_feliz(escenario):
    resultado = escenario.correr()
    llamadas = escenario.llamadas

    assert resultado.returncode == 0, resultado.stderr
    assert "--branch v1.5.0" in llamadas
    assert llamadas.index("helm upgrade") < llamadas.index("helm test")
    (upgrade,) = [linea for linea in llamadas.splitlines() if linea.startswith("helm upgrade")]
    assert "--wait" in upgrade
    assert upgrade.index(" -f ") < upgrade.index("image.tag=1.5.0"), "image.tag manda sobre los values reales"
    assert "helm rollback" not in llamadas
    assert escenario.correos() == []
    assert escenario.marcas() == []


def test_falla_upgrade_vuelve_atras_marca_y_avisa(escenario):
    resultado = escenario.correr(F_UPGRADE="1")

    assert resultado.returncode == 1
    assert "helm rollback" in escenario.llamadas
    assert "1.5.0" in escenario.marcas()[0]
    assert len(escenario.correos()) == 1


def test_falla_helm_test_vuelve_atras_marca_y_avisa(escenario):
    resultado = escenario.correr(F_TEST="primero")

    assert resultado.returncode == 1
    assert "helm rollback" in escenario.llamadas
    assert "1.5.0" in escenario.marcas()[0]
    assert len(escenario.correos()) == 1
    assert "URGENT" not in escenario.correos()[0]


def test_helm_test_sin_pruebas_es_fallo(escenario):
    """Una revisión sin hooks daría un verde que no comprueba nada."""
    resultado = escenario.correr(F_TEST_VACIO="1")

    assert resultado.returncode != 0
    assert "helm rollback" in escenario.llamadas


def test_imagen_distinta_de_la_version_es_fallo(escenario):
    resultado = escenario.correr(F_IMAGEN="1.3.0")

    assert resultado.returncode != 0
    assert "helm rollback" in escenario.llamadas
    assert "1.5.0" in escenario.marcas()[0]


def test_email_de_rollback_lleva_advertencia_de_historial(escenario):
    escenario.correr(F_UPGRADE="1")
    (correo,) = escenario.correos()

    assert "04-aws.md" in correo
    assert "1.5.0" in correo
    assert "helm upgrade" in correo, "el paso que falló"
    assert "https://jenkins.example.com/job/1/" in correo


@pytest.mark.parametrize("opciones", [{"F_UPGRADE": "1", "F_ROLLBACK": "1"}, {"F_TEST": "siempre"}])
def test_rollback_fallido_email_urgente(escenario, opciones):
    """Que falle la vuelta, o que tras volver tampoco pase la prueba."""
    resultado = escenario.correr(**opciones)
    (correo,) = escenario.correos()

    assert resultado.returncode == 3
    assert "URGENT" in correo


def test_sns_caido_no_oculta_el_fallo(escenario):
    resultado = escenario.correr(F_UPGRADE="1", F_SNS="1")

    assert resultado.returncode == 1
    assert "helm rollback" in escenario.llamadas
    assert escenario.marcas(), "la marca va antes del aviso: si no, otro intento"
    assert "1.5.0" in resultado.stderr
    assert "helm upgrade" in resultado.stderr


@pytest.mark.parametrize("fallo", ["F_LECTURA", "F_FALLIDAS_ERROR", "F_GIT"])
def test_lectura_de_estado_fallida_no_despliega(escenario, fallo):
    resultado = escenario.correr(**{fallo: "1"})

    assert resultado.returncode == 4
    assert "helm upgrade" not in escenario.llamadas
    assert escenario.marcas() == []
    assert escenario.correos() == []


def test_sin_publicar_tras_la_espera_marca_y_avisa(escenario):
    resultado = escenario.correr(F_PUBLICADA="404")

    assert resultado.returncode == 1
    assert "helm upgrade" not in escenario.llamadas
    assert "1.5.0" in escenario.marcas()[0]
    assert len(escenario.correos()) == 1


@pytest.mark.parametrize("fallo", ["F_CLONE", "F_SECRET"])
def test_fallo_al_preparar_avisa_sin_rollback(escenario, fallo):
    """Sin haber tocado el clúster no hay nada que deshacer, pero se marca: un
    Secret que falta no puede convertirse en un intento cada 5 minutos, en silencio."""
    resultado = escenario.correr(**{fallo: "1"})

    assert resultado.returncode == 1
    assert "helm upgrade" not in escenario.llamadas
    assert "helm rollback" not in escenario.llamadas
    assert "1.5.0" in escenario.marcas()[0]
    assert len(escenario.correos()) == 1


def test_automatico_no_reintenta_una_fallida(escenario):
    resultado = escenario.correr(F_FALLIDAS="1.5.0\n")

    assert resultado.returncode == 0
    assert "helm upgrade" not in escenario.llamadas
    assert escenario.correos() == []


def test_marca_conserva_las_anteriores(escenario):
    escenario.correr(F_UPGRADE="1", F_FALLIDAS="1.4.5\n")

    assert "1.4.5\\n1.5.0\\n" in escenario.marcas()[0]


def test_manual_sin_version_redespliega_la_actual(escenario):
    resultado = escenario.correr(modo="manual", F_PUBLICADA="404")

    assert resultado.returncode == 0, resultado.stderr
    assert "--branch v1.4.0" in escenario.llamadas
    assert "image.tag=1.4.0" in escenario.llamadas


def test_manual_redespliegue_fallido_no_marca(escenario):
    """El problema son los values, no la versión que ya corría."""
    resultado = escenario.correr(modo="manual", F_UPGRADE="1")

    assert resultado.returncode == 1
    assert "helm rollback" in escenario.llamadas
    assert escenario.marcas() == []
    assert len(escenario.correos()) == 1


def test_manual_con_version_fallida_la_despliega_y_quita_la_marca(escenario):
    resultado = escenario.correr(modo="manual", VERSION="1.5.0", F_FALLIDAS="1.4.5\n1.5.0\n")

    assert resultado.returncode == 0, resultado.stderr
    assert "image.tag=1.5.0" in escenario.llamadas
    (marca,) = escenario.marcas()
    assert "1.4.5\\n" in marca
    assert "1.5.0" not in marca


def test_manual_permite_volver_a_una_version_anterior(escenario):
    resultado = escenario.correr(modo="manual", VERSION="1.3.0")

    assert resultado.returncode == 0, resultado.stderr
    assert "image.tag=1.3.0" in escenario.llamadas


def test_ensayos_solo_en_manual(escenario):
    resultado = escenario.correr(ENSAYO="no-arranca")

    assert resultado.returncode == 2
    assert "helm upgrade" not in escenario.llamadas


def test_ensayo_no_arranca(escenario):
    resultado = escenario.correr(modo="manual", ENSAYO="no-arranca", F_UPGRADE="1")

    assert resultado.returncode == 1
    assert "image.tag=0.0.0-ensayo-no-existe" in escenario.llamadas
    assert "helm rollback" in escenario.llamadas
    assert escenario.marcas() == []
    assert "REHEARSAL" in escenario.correos()[0]


def test_ensayo_falla_prueba(escenario):
    resultado = escenario.correr(modo="manual", ENSAYO="falla-prueba", F_TEST="primero")

    assert resultado.returncode == 1
    assert "image.tag=1.4.0" in escenario.llamadas
    assert "pruebas.versionEsperada=0.0.0-ensayo" in escenario.llamadas
    assert "helm rollback" in escenario.llamadas
    assert escenario.marcas() == []


def test_modo_consultar_imprime_la_version_sin_desplegar(escenario):
    resultado = escenario.correr(modo="consultar")

    assert resultado.returncode == 0, resultado.stderr
    assert resultado.stdout.strip() == "1.5.0"
    assert "helm" not in escenario.llamadas


def test_modo_desconocido_es_error(escenario):
    resultado = escenario.correr(modo="otro")

    assert resultado.returncode == 2
    assert "helm upgrade" not in escenario.llamadas
