"""
Tests de los workflows de GitHub Actions (.github/workflows/*.yml).

Toda action que no sea de GitHub (actions/...) va fijada por SHA de commit:
una tag o una rama se pueden mover, y en marzo de 2026 reescribieron casi
todas las tags de aquasecurity/trivy-action para robar los secretos de los
pipelines que las usaban. Las de actions/ (mantenidas por GitHub) van por tag.
"""

import re
from pathlib import Path

import yaml

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


def test_los_runners_van_fijados_por_version():
    # ubuntu-latest cambió de 24.04 a 26.04 en octubre de 2026 sin tocar nada del
    # repo: la versión del sistema del runner se sube a propósito, como las actions.
    runners = [
        (workflow.name, runner)
        for workflow in sorted(CARPETA_WORKFLOWS.glob("*.yml"))
        for runner in re.findall(r"^\s*runs-on:\s*(\S+)", workflow.read_text(encoding="utf-8"), re.MULTILINE)
    ]

    assert runners
    assert [f"{workflow}: {runner}" for workflow, runner in runners if runner.endswith("-latest")] == []


def test_la_ci_valida_cada_raiz_de_terraform():
    # Una raíz = carpeta de infra/ con .tf propios (los tests van en tests/, aparte;
    # .terraform/ es la caché de init, donde caen los módulos descargados).
    # Si se crea una nueva y no se añade al job terraform, nadie la valida.
    raiz_repo = CARPETA_WORKFLOWS.parents[1]
    raices = sorted(
        {
            tf.parent.relative_to(raiz_repo).as_posix()
            for tf in (raiz_repo / "infra").rglob("*.tf")
            if ".terraform" not in tf.parts
        }
    )
    ci = (CARPETA_WORKFLOWS / "ci.yml").read_text(encoding="utf-8")

    assert raices
    assert [raiz for raiz in raices if f"-chdir={raiz} validate" not in ci] == []


def _tf_de_infra():
    raiz_repo = CARPETA_WORKFLOWS.parents[1]
    return [tf for tf in (raiz_repo / "infra").rglob("*.tf") if ".terraform" not in tf.parts]


def test_ningun_tf_crea_claves_de_acceso():
    """La clave secreta de un aws_iam_access_key queda en el estado, y el rol
    de plan de los PRs lo lee: la del usuario del homelab se crea a mano."""
    assert [tf.name for tf in _tf_de_infra() if "aws_iam_access_key" in tf.read_text(encoding="utf-8")] == []


def test_email_de_avisos_es_sensible():
    """El plan se publica como comentario en los PRs de un repo público:
    sin sensitive, el email del mantenedor saldría ahí."""
    variables = CARPETA_WORKFLOWS.parents[1] / "infra" / "aws" / "hallazgos" / "variables.tf"
    (bloque,) = re.findall(r'variable "email_avisos" \{(.*?)\n\}', variables.read_text(encoding="utf-8"), re.DOTALL)

    assert re.search(r"^\s*sensitive\s*=\s*true", bloque, re.MULTILINE)


# "terraform apply" o "terraform -chdir=... apply": un apply en cualquier forma
_APPLY = re.compile(r"^\s*terraform\b.*\sapply\b", re.MULTILINE)


def _workflow_aws() -> dict:
    return yaml.safe_load((CARPETA_WORKFLOWS / "terraform-aws.yml").read_text(encoding="utf-8"))


def _comandos(trabajo: dict) -> str:
    return "\n".join(paso.get("run", "") for paso in trabajo["steps"])


def _trabajos_aws() -> tuple[dict, dict]:
    """(plan de los PRs, apply de main) del workflow de Terraform de AWS."""
    trabajos = _workflow_aws()["jobs"].values()
    (apply,) = [t for t in trabajos if _APPLY.search(_comandos(t))]
    (plan,) = [t for t in trabajos if t is not apply]
    return plan, apply


def test_apply_de_aws_solo_en_main_con_environment():
    """El apply toca AWS de verdad: solo tras mergear en main y con la
    aprobación del mantenedor (environment aws con revisor obligatorio)."""
    flujo = _workflow_aws()
    # PyYAML lee la clave "on" como el booleano True
    disparadores = flujo.get("on", flujo.get(True))
    _, apply = _trabajos_aws()

    assert disparadores["push"]["branches"] == ["main"]
    assert apply["environment"] == "aws"
    assert "github.event_name == 'push'" in apply["if"]


def test_plan_de_aws_no_corre_en_forks():
    """Un PR desde un fork no recibe token OIDC: el job fallaría siempre."""
    plan, _ = _trabajos_aws()

    assert "github.event.pull_request.head.repo.full_name == github.repository" in plan["if"]
    assert "environment" not in plan


def test_plan_de_aws_sin_lock():
    """El rol de plan solo lee: no puede escribir el .tflock del estado."""
    plan, _ = _trabajos_aws()

    assert "-lock=false" in _comandos(plan)
    assert not _APPLY.search(_comandos(plan))


def test_la_ci_valida_los_valores_de_jenkins():
    """El chart oficial, en versión fija, renderizado con nuestros valores."""
    ci = (CARPETA_WORKFLOWS / "ci.yml").read_text(encoding="utf-8")

    assert re.search(r"helm template ci jenkins/jenkins --version \d+\.\d+\.\d+ .*deploy/jenkins/values\.yaml", ci)


def test_la_ci_valida_los_valores_de_monitorizacion():
    """Los charts oficiales de la monitorización, con la misma versión que
    apuntan sus values, renderizados con nuestros valores."""
    ci = (CARPETA_WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    monitoring = CARPETA_WORKFLOWS.parents[1] / "deploy" / "monitoring"

    charts = (("kube-prometheus-stack", "values.yaml"), ("prometheus-pushgateway", "pushgateway.values.yaml"))
    for chart, valores in charts:
        # La cabecera de cada values dice "... (prometheus-community), versión X.Y.Z"
        (version,) = re.findall(r"versión\W+(\d+\.\d+\.\d+)",(monitoring / valores).read_text(encoding="utf-8"))[:1]
        comando = rf"helm template ci prometheus-community/{chart} --version {re.escape(version)} .*{valores}"
        assert re.search(comando, ci), chart


def test_la_ci_prueba_las_reglas_de_alerta():
    """promtool (imagen oficial por digest, como Trivy) ejecuta los tests de
    las reglas, y el chart que las carga pasa helm lint."""
    ci = (CARPETA_WORKFLOWS / "ci.yml").read_text(encoding="utf-8")

    assert re.search(r"prom/prometheus:v[\d.]+@sha256:[0-9a-f]{64}", ci)
    assert "test rules /m/pruebas/reglas.test.yaml" in ci
    assert "check rules /m/topology-monitoring/files/reglas.yaml" in ci
    assert "helm lint deploy/monitoring/topology-monitoring --strict" in ci


def test_la_ci_valida_el_chart_de_helm():
    """helm lint y helm template del chart con los values de ejemplo, y Helm
    también en el job de pytest: si no, tests/test_helm.py se saltaría en
    silencio y nadie comprobaría la seguridad de los pods."""
    ci = (CARPETA_WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    chart = "deploy/helm/topology-scanner"
    trabajos = re.split(r"^  (?=[a-z]+:$)", ci, flags=re.MULTILINE)
    test = next(t for t in trabajos if t.startswith("test:"))

    assert f"helm lint {chart} -f {chart}/values.example.yaml" in ci
    assert f"helm template ci {chart} -f {chart}/values.example.yaml" in ci
    assert "azure/setup-helm@" in test
