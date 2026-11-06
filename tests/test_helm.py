"""
Tests del chart de Helm (deploy/helm/topology-scanner): renderiza el chart
con `helm template` y comprueba lo que no puede romperse al desplegar. Sobre
todo la seguridad de los pods: el escáner necesita la red del nodo y tres
capacidades, y nada más (ver docs/devops/runbooks/01-contenedor.md).

Se saltan si `helm` no está instalado; en la CI el job `test` lo instala.
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

RAIZ = Path(__file__).resolve().parents[1]
CHART = RAIZ / "deploy" / "helm" / "topology-scanner"
VALUES_EJEMPLO = CHART / "values.example.yaml"
DOCKERFILE = RAIZ / "Dockerfile"

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
    """hostNetwork para ver las MACs del segmento; sin root y solo NET_RAW,
    NET_ADMIN y NET_BIND_SERVICE (rpcinfo de -sV sale desde un puerto <1024).
    allowPrivilegeEscalation: false anularía las capacidades de
    archivo de nmap (fase 1), así que no puede aparecer."""
    manifiestos = _renderizar()
    pod = _pod(manifiestos, kind)
    contexto = _contenedor(manifiestos, kind)["securityContext"]

    assert pod["hostNetwork"] is True
    assert pod["dnsPolicy"] == "ClusterFirstWithHostNet"
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert pod["securityContext"]["runAsUser"] == 10001
    assert pod["securityContext"]["fsGroup"] == 10001
    assert contexto["capabilities"] == {"drop": ["ALL"], "add": ["NET_RAW", "NET_ADMIN", "NET_BIND_SERVICE"]}
    assert "privileged" not in contexto
    assert "allowPrivilegeEscalation" not in contexto


def _capacidades_del_setcap() -> set[str]:
    """Capacidades que el Dockerfile le pone a nmap: `setcap cap_a,cap_b+eip`
    -> {"A", "B"}, con el nombre que usa Kubernetes."""
    (lista,) = re.findall(r"setcap ([\w,]+)\+eip /usr/bin/nmap", DOCKERFILE.read_text(encoding="utf-8"))
    return {capacidad.removeprefix("cap_").upper() for capacidad in lista.split(",")}


@pytest.mark.parametrize("kind", ["CronJob", "Deployment"])
def test_pods_dan_las_capacidades_que_pide_nmap_en_la_imagen(kind):
    """Con drop: [ALL], el kernel no ejecuta nmap si el pod no tiene todas las
    capacidades de archivo del binario (fase 1). Imagen y chart se cambian a la
    vez o nmap no arranca en el clúster."""
    contexto = _contenedor(_renderizar(), kind)["securityContext"]

    assert set(contexto["capabilities"]["add"]) == _capacidades_del_setcap()


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


def test_web_sin_dominio_no_fija_direccion():
    """Sin proxy delante, Streamlit sigue anunciándose con su IP y puerto."""
    env = _env(_contenedor(_renderizar(), "Deployment"))

    assert "STREAMLIT_BROWSER_SERVER_ADDRESS" not in env
    assert "STREAMLIT_BROWSER_SERVER_PORT" not in env


def test_web_con_dominio_detras_del_proxy():
    """Con web.dominio (el nombre del proxy inverso, HTTPS en el 443),
    Streamlit se anuncia con ese nombre: así ni consulta checkip.amazonaws.com
    para sacar la IP pública ni la usa al comprobar el Origin del websocket."""
    manifiestos = _renderizar("--set", "web.dominio=topology.example.com")
    env = _env(_contenedor(manifiestos, "Deployment"))

    assert env["STREAMLIT_BROWSER_SERVER_ADDRESS"]["value"] == "topology.example.com"
    assert env["STREAMLIT_BROWSER_SERVER_PORT"]["value"] == "443"


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


@pytest.mark.parametrize("kind", ["CronJob", "Deployment"])
def test_hora_local_en_los_pods(kind):
    """Sin TZ, el historial guarda la hora en UTC y el nocturno de las 3:00
    sale en la lista como 02:00. Formato POSIX: lo entiende la libc sin el
    paquete tzdata, que la imagen slim puede no traer."""
    env = _env(_contenedor(_renderizar(), kind))

    assert env["TZ"]["value"] == "CET-1CEST,M3.5.0,M10.5.0/3"


# --- aws.enabled: el nocturno sube informes y copia del historial, y avisa ---

CON_AWS = (
    "--set", "aws.enabled=true",
    "--set", "aws.bucket=topology-scanner-informes-123456789012",
    "--set", "aws.topicArn=arn:aws:sns:eu-south-2:123456789012:topology-scanner-hallazgos",
)


def _contenedores_del_job(manifiestos: dict) -> dict[str, dict]:
    """{nombre: contenedor} de initContainers y containers del CronJob."""
    pod = _pod(manifiestos, "CronJob")
    return {c["name"]: c for c in pod.get("initContainers", []) + pod["containers"]}


def test_sin_aws_el_cronjob_no_cambia():
    manifiestos = _renderizar()
    pod = _pod(manifiestos, "CronJob")
    args = _contenedor(manifiestos, "CronJob")["args"]

    assert "initContainers" not in pod
    assert [c["name"] for c in pod["containers"]] == ["escaneo"]
    assert "--changes-dir" not in args
    assert "ConfigMap" not in manifiestos


def test_con_aws_escaneo_es_init_y_subida_despues():
    """El escaneo como initContainer: si falla, la subida no arranca y el Job
    sale fallido. Los archivos de la noche pasan por un emptyDir."""
    manifiestos = _renderizar(*CON_AWS)
    pod = _pod(manifiestos, "CronJob")
    escaneo = _contenedores_del_job(manifiestos)["escaneo"]
    args = escaneo["args"]

    assert [c["name"] for c in pod["initContainers"]] == ["escaneo"]
    assert [c["name"] for c in pod["containers"]] == ["subida"]
    assert args[args.index("--output") + 1] == "/salida/network_topology.html"
    assert args[args.index("--csv") + 1] == "/salida/inventory.csv"
    assert args[args.index("--changes-dir") + 1] == "/salida/cambios"
    assert args[args.index("--history-backup") + 1] == "/salida/historial.db"
    assert args[args.index("--history-db") + 1] == "/data/historial.db"
    assert {"name": "salida", "emptyDir": {}} in pod["volumes"]


def test_escaneo_en_init_conserva_las_capacidades_de_nmap():
    escaneo = _contenedores_del_job(_renderizar(*CON_AWS))["escaneo"]

    assert set(escaneo["securityContext"]["capabilities"]["add"]) == _capacidades_del_setcap()


def test_subida_con_imagen_por_digest_y_sin_capacidades():
    subida = _contenedores_del_job(_renderizar(*CON_AWS))["subida"]
    contexto = subida["securityContext"]

    assert subida["image"].startswith("amazon/aws-cli:")
    assert "@sha256:" in subida["image"]
    assert contexto["capabilities"] == {"drop": ["ALL"]}
    assert contexto["allowPrivilegeEscalation"] is False
    assert contexto["readOnlyRootFilesystem"] is True


def test_subida_claves_desde_secret():
    env = _env(_contenedores_del_job(_renderizar(*CON_AWS))["subida"])

    for variable in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        referencia = env[variable]["valueFrom"]["secretKeyRef"]
        assert referencia["name"] == "topology-scanner-aws"
        assert referencia["key"] == variable
        assert "optional" not in referencia
    assert env["BUCKET"]["value"] == "topology-scanner-informes-123456789012"
    assert env["TOPIC_ARN"]["value"].endswith(":topology-scanner-hallazgos")
    assert env["AWS_REGION"]["value"] == "eu-south-2"


@pytest.mark.parametrize("falta", ["aws.bucket", "aws.topicArn"])
def test_aws_sin_bucket_o_topic_falla(falta):
    parejas = zip(CON_AWS[::2], CON_AWS[1::2], strict=True)
    extra = [arg for pareja in parejas if not pareja[1].startswith(falta + "=") for arg in pareja]
    salida = subprocess.run(
        ["helm", "template", "t", str(CHART), "-f", str(VALUES_EJEMPLO), *extra], capture_output=True, text=True,
    )

    assert salida.returncode != 0
    assert falta in salida.stderr


def test_script_de_subida_siempre_con_lf():
    """helm upgrade se lanza desde Windows, donde git (autocrlf) dejaría el
    script con CRLF: el sh del contenedor fallaría en la primera línea."""
    salida = subprocess.run(
        ["git", "check-attr", "eol", "--", "deploy/helm/topology-scanner/files/subir.sh"],
        cwd=RAIZ, check=True, capture_output=True, text=True,
    ).stdout

    assert salida.strip().endswith("eol: lf")
    # Los bytes del archivo, que es lo que Helm mete en el ConfigMap (leer el
    # render no sirve: el parser de YAML normaliza los saltos de línea)
    assert b"\r" not in (CHART / "files" / "subir.sh").read_bytes()


def test_script_de_subida():
    script = _renderizar(*CON_AWS)["ConfigMap"]["data"]["subir.sh"]

    assert "set -eu" in script
    assert "s3://$BUCKET/historial/historial.db" in script
    assert "aws s3 presign" in script and "--expires-in" in script
    assert "aws sns publish" in script
    # Sin cambios no hay email: el aviso depende de que exista cambios.json
    assert "cambios/cambios.json" in script
