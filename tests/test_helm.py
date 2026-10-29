"""
Tests del chart de Helm (deploy/helm/topology-scanner): renderiza el chart
con `helm template` y comprueba lo que no puede romperse al desplegar. Sobre
todo la seguridad de los pods: el escáner necesita la red del nodo y dos
capacidades, y nada más (ver docs/devops/runbooks/01-contenedor.md).

Se saltan si `helm` no está instalado; en la CI el job `test` lo instala.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

RAIZ = Path(__file__).resolve().parents[1]
CHART = RAIZ / "deploy" / "helm" / "topology-scanner"
VALUES_EJEMPLO = CHART / "values.example.yaml"

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm no está instalado")


def _renderizar(*extra: str) -> dict[str, dict]:
    """{kind: manifiesto} del chart renderizado con values.example.yaml."""
    salida = subprocess.run(
        ["helm", "template", "t", str(CHART), "-f", str(VALUES_EJEMPLO), *extra],
        check=True, capture_output=True, text=True,
    ).stdout
    return {doc["kind"]: doc for doc in yaml.safe_load_all(salida) if doc}


def _pod(manifiestos: dict, kind: str) -> dict:
    if kind == "CronJob":
        return manifiestos["CronJob"]["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    return manifiestos[kind]["spec"]["template"]["spec"]


def _contenedor(manifiestos: dict, kind: str) -> dict:
    (contenedor,) = _pod(manifiestos, kind)["containers"]
    return contenedor


def _env(contenedor: dict) -> dict[str, dict]:
    return {variable["name"]: variable for variable in contenedor.get("env", [])}


@pytest.mark.parametrize("kind", ["CronJob", "Deployment"])
def test_pods_con_hostnetwork_y_capacidades_minimas(kind):
    """hostNetwork para ver las MACs del segmento; sin root y solo NET_RAW y
    NET_ADMIN. allowPrivilegeEscalation: false anularía las capacidades de
    archivo de nmap (fase 1), así que no puede aparecer."""
    manifiestos = _renderizar()
    pod = _pod(manifiestos, kind)
    contexto = _contenedor(manifiestos, kind)["securityContext"]

    assert pod["hostNetwork"] is True
    assert pod["dnsPolicy"] == "ClusterFirstWithHostNet"
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert pod["securityContext"]["runAsUser"] == 10001
    assert pod["securityContext"]["fsGroup"] == 10001
    assert contexto["capabilities"] == {"drop": ["ALL"], "add": ["NET_RAW", "NET_ADMIN"]}
    assert "privileged" not in contexto
    assert "allowPrivilegeEscalation" not in contexto


def test_cronjob_nocturno():
    manifiestos = _renderizar()
    cronjob = manifiestos["CronJob"]["spec"]
    args = _contenedor(manifiestos, "CronJob")["args"]

    assert cronjob["schedule"] == "0 3 * * *"
    assert cronjob["timeZone"] == "Europe/Madrid"
    assert cronjob["concurrencyPolicy"] == "Forbid"
    assert cronjob["jobTemplate"]["spec"]["backoffLimit"] == 0
    assert args[:2] == ["192.0.2.0/24", "198.51.100.0/24"]
    assert "--os-detection" in args
    assert args[args.index("--history-db") + 1] == "/data/historial.db"
    assert args[args.index("--snmp") + 1] == "192.0.2.1"


def test_cronjob_sin_snmp_ni_os():
    manifiestos = _renderizar("--set", "escaneo.snmp=null", "--set", "escaneo.osDetection=false")
    args = _contenedor(manifiestos, "CronJob")["args"]

    assert "--snmp" not in args
    assert "--os-detection" not in args


def test_imagen_con_tag_fijo():
    manifiestos = _renderizar()
    for kind in ("CronJob", "Deployment"):
        imagen = _contenedor(manifiestos, kind)["image"]
        repositorio, _, tag = imagen.rpartition(":")
        assert repositorio == "ghcr.io/danielsm107/topology-scanner"
        assert tag and tag != "latest"


def test_web_recreate_y_variables():
    """Recreate: con hostNetwork, la web nueva y la vieja pelearían por el
    mismo puerto del nodo durante un RollingUpdate."""
    manifiestos = _renderizar()
    web = _contenedor(manifiestos, "Deployment")
    env = _env(web)

    assert manifiestos["Deployment"]["spec"]["strategy"]["type"] == "Recreate"
    assert web["command"] == ["topology-scanner-web"]
    assert env["TOPOLOGY_ALLOWED_RANGES"]["value"] == "192.0.2.0/24 198.51.100.0/24"
    assert env["TOPOLOGY_HISTORY_DB"]["value"] == "/data/historial.db"
    assert env["STREAMLIT_SERVER_PORT"]["value"] == "8501"


def test_permitidos_por_defecto_son_los_rangos():
    """Sin rangosPermitidos, la web queda limitada a los rangos del nocturno:
    nunca sin límite dentro del clúster."""
    manifiestos = _renderizar("--set", "rangosPermitidos=null")

    env = _env(_contenedor(manifiestos, "Deployment"))
    assert env["TOPOLOGY_ALLOWED_RANGES"]["value"] == "192.0.2.0/24 198.51.100.0/24"


def test_pvc_se_conserva_al_desinstalar():
    """El historial no se pierde con un `helm uninstall`."""
    pvc = _renderizar()["PersistentVolumeClaim"]

    assert pvc["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"
    assert pvc["spec"]["accessModes"] == ["ReadWriteOnce"]
    assert pvc["spec"]["storageClassName"] == "local-path"


@pytest.mark.parametrize("kind", ["CronJob", "Deployment"])
def test_credenciales_snmp_desde_secret(kind):
    """Las claves SNMPv3 salen de un Secret creado a mano (nunca del chart ni
    de git). optional: sin escaneo.snmp no hace falta crearlo."""
    env = _env(_contenedor(_renderizar(), kind))

    for variable in ("TOPOLOGY_SNMP_USER", "TOPOLOGY_SNMP_AUTH_KEY", "TOPOLOGY_SNMP_PRIV_KEY"):
        referencia = env[variable]["valueFrom"]["secretKeyRef"]
        assert referencia["name"] == "topology-scanner-snmp"
        assert referencia["key"] == variable
        assert referencia["optional"] is True


def test_sin_service_ni_ingress():
    """NPM apunta directo a <IP del nodo>:8501 (hostNetwork)."""
    manifiestos = _renderizar()

    assert "Service" not in manifiestos
    assert "Ingress" not in manifiestos


def test_tag_latest_se_rechaza():
    salida = subprocess.run(
        ["helm", "template", "t", str(CHART), "--set", "image.tag=latest"], capture_output=True, text=True,
    )

    assert salida.returncode != 0
    assert "latest" in salida.stderr
