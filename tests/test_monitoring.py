"""
Tests de la monitorización (deploy/monitoring/): los valores de los charts
oficiales (kube-prometheus-stack y prometheus-pushgateway) leídos como YAML,
sin Helm ni clúster. Comprueban lo que no puede romperse al instalar: que k3s
no dispare alertas permanentes, que el Watchdog llegue a healthchecks.io, que el
resto vaya a Telegram sin ruido y que ningún secreto acabe en el repo.
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

RAIZ = Path(__file__).resolve().parents[1]
MONITORING = RAIZ / "deploy" / "monitoring"
SECRETOS = "/etc/alertmanager/secrets/alertas"


def _valores(nombre: str = "values.yaml") -> dict:
    return yaml.safe_load((MONITORING / nombre).read_text(encoding="utf-8"))


def _alertmanager() -> dict:
    return _valores()["alertmanager"]["config"]


def _receptor(nombre: str) -> dict:
    (receptor,) = [r for r in _alertmanager()["receivers"] if r["name"] == nombre]
    return receptor


def _a_mib(cantidad: str) -> float:
    """"640Mi" / "1Gi" -> MiB."""
    numero, unidad = re.fullmatch(r"(\d+)(Mi|Gi)", cantidad).groups()
    return int(numero) * (1024 if unidad == "Gi" else 1)


def test_k3s_sin_componentes_que_no_expone():
    """k3s no expone controller-manager, scheduler, etcd ni kube-proxy por
    separado: sus ServiceMonitors y reglas darían alertas permanentes."""
    valores = _valores()

    for componente in ("kubeControllerManager", "kubeScheduler", "kubeEtcd", "kubeProxy"):
        assert valores[componente]["enabled"] is False
    reglas = valores["defaultRules"]["rules"]
    for regla in ("etcd", "kubeControllerManager", "kubeProxy", "kubeSchedulerAlerting", "kubeSchedulerRecording",
                  "windows"):
        assert reglas[regla] is False


def test_retencion_y_almacenamiento():
    spec = _valores()["prometheus"]["prometheusSpec"]
    plantilla = spec["storageSpec"]["volumeClaimTemplate"]["spec"]

    assert spec["retention"] == "15d"
    assert spec["retentionSize"]
    assert plantilla["storageClassName"] == "local-path"


def test_limites_de_memoria_dentro_del_presupuesto():
    """~1,5 GiB entre todo: la monitorización no puede dejar sin memoria al
    nocturno ni a Jenkins (el nodo tiene 8 GiB)."""
    valores = _valores()
    limites = [
        valores["prometheus"]["prometheusSpec"]["resources"]["limits"]["memory"],
        valores["alertmanager"]["alertmanagerSpec"]["resources"]["limits"]["memory"],
        valores["grafana"]["resources"]["limits"]["memory"],
        # Dos sidecars (paneles y datasources) con los mismos recursos
        valores["grafana"]["sidecar"]["resources"]["limits"]["memory"],
        valores["grafana"]["sidecar"]["resources"]["limits"]["memory"],
        valores["prometheusOperator"]["resources"]["limits"]["memory"],
        valores["kube-state-metrics"]["resources"]["limits"]["memory"],
        valores["prometheus-node-exporter"]["resources"]["limits"]["memory"],
        _valores("pushgateway.values.yaml")["resources"]["limits"]["memory"],
    ]

    # 1,5 GiB en el diseño; 1,75 tras ver los picos de arranque reales de Grafana
    assert sum(_a_mib(limite) for limite in limites) <= 1792


def test_grafana_con_memoria_para_arrancar():
    """Con 256Mi lo mataba el OOM en el primer arranque (migraciones de
    Grafana 13; instalación real del 2026-11-11). En reposo usa ~230Mi."""
    assert _a_mib(_valores()["grafana"]["resources"]["limits"]["memory"]) >= 512


def test_sidecars_de_grafana_con_memoria_para_arrancar():
    """Con 64Mi los mataba el OOM al cargar los paneles por defecto (instalación
    real del 2026-11-11)."""
    assert _a_mib(_valores()["grafana"]["sidecar"]["resources"]["limits"]["memory"]) >= 128


def test_watchdog_va_a_healthchecks():
    """El Watchdog siempre está disparado: repetido cada minuto hacia la URL
    de ping, demuestra que Prometheus evalúa y Alertmanager envía. Si deja de
    llegar, avisa healthchecks.io desde fuera."""
    (ruta,) = [r for r in _alertmanager()["route"]["routes"] if 'alertname = "Watchdog"' in r.get("matchers", [])]
    (webhook,) = _receptor("healthchecks")["webhook_configs"]

    assert ruta["receiver"] == "healthchecks"
    assert ruta["repeat_interval"] == "1m"
    assert ruta["group_interval"] == "1m"
    assert webhook["url_file"] == f"{SECRETOS}/HEALTHCHECKS_URL"
    assert webhook["send_resolved"] is False
    assert "url" not in webhook


def test_resto_va_a_telegram():
    (telegram,) = _receptor("telegram")["telegram_configs"]

    assert _alertmanager()["route"]["receiver"] == "telegram"
    assert telegram["bot_token_file"] == f"{SECRETOS}/TELEGRAM_BOT_TOKEN"
    assert telegram["chat_id_file"] == f"{SECRETOS}/TELEGRAM_CHAT_ID"
    assert telegram["send_resolved"] is True
    assert "chat_id" not in telegram and "bot_token" not in telegram
    assert _valores()["alertmanager"]["alertmanagerSpec"]["secrets"] == ["alertas"]


def test_avisos_sin_ruido():
    """Un mensaje por problema y un recordatorio cada pocas horas, no cada 5 min.
    Watchdog e InfoInhibitor existen para otra cosa: nunca llegan a Telegram."""
    ruta = _alertmanager()["route"]
    silenciadas = {
        matcher for r in ruta["routes"] if r["receiver"] == "null" for matcher in r.get("matchers", [])
    }

    assert ruta["group_by"] == ["alertname", "namespace"]
    horas = int(re.fullmatch(r"(\d+)h", ruta["repeat_interval"]).group(1))
    assert horas >= 4
    assert 'alertname = "InfoInhibitor"' in silenciadas
    assert ruta["routes"][0]["receiver"] == "healthchecks"


def test_mensaje_de_telegram_en_espanol():
    plantillas = _valores()["alertmanager"]["templateFiles"]
    (telegram,) = _receptor("telegram")["telegram_configs"]

    assert "telegram.mensaje" in telegram["message"]
    assert any('define "telegram.mensaje"' in texto for texto in plantillas.values())
    assert any("Resuelto" in texto for texto in plantillas.values())


def test_fallo_del_nocturno_no_avisa_tambien_de_metricas():
    """Si el nocturno no termina, tampoco sube métricas: Stale/Missing serían el
    mismo problema contado dos veces. Sin `equal`: las métricas vienen del
    Pushgateway (otro namespace) y absent() no tiene etiquetas."""
    reglas = [
        r for r in _alertmanager()["inhibit_rules"] if r["source_matchers"] == ["alertname = NightlyScanNotSucceeded"]
    ]

    assert reglas == [
        {
            "source_matchers": ["alertname = NightlyScanNotSucceeded"],
            "target_matchers": ['alertname =~ "ScanMetricsStale|ScanMetricsMissing"'],
        }
    ]


def test_grafana_sin_anonimo_y_admin_por_secret():
    grafana = _valores()["grafana"]

    assert grafana["admin"]["existingSecret"] == "grafana-admin"
    assert grafana["grafana.ini"]["auth.anonymous"]["enabled"] is False
    assert grafana["service"]["type"] == "NodePort"
    assert grafana["service"]["nodePort"] == 30300
    assert grafana["sidecar"]["dashboards"]["enabled"] is True
    assert grafana["sidecar"]["dashboards"]["label"] == "grafana_dashboard"


def test_pushgateway_lo_lee_prometheus():
    """Otro release: su ServiceMonitor necesita la etiqueta que selecciona el
    Prometheus del stack (ruleSelectorNilUsesHelmValues). honorLabels para que
    las etiquetas del push (range) no se pisen con las del scrape."""
    valores = _valores("pushgateway.values.yaml")

    assert valores["fullnameOverride"] == "prometheus-pushgateway"
    assert valores["serviceMonitor"]["enabled"] is True
    assert valores["serviceMonitor"]["additionalLabels"] == {"release": "monitoring"}
    assert valores["serviceMonitor"]["honorLabels"] is True


@pytest.mark.parametrize("archivo", ["values.yaml", "values.example.yaml", "pushgateway.values.yaml"])
def test_secretos_fuera_del_repo(archivo):
    texto = (MONITORING / archivo).read_text(encoding="utf-8")

    assert "api.telegram.org/bot" not in texto
    assert not re.search(r"hc-ping\.com/[0-9a-f-]{36}", texto)
    assert not re.search(r"adminPassword:\s*\S", texto)
    assert not re.search(r"\b\d{6,}:[A-Za-z0-9_-]{30,}", texto)  # forma de un token de bot


# --- Reglas propias (chart topology-monitoring) ---

CHART_PROPIO = MONITORING / "topology-monitoring"
PRUEBAS_REGLAS = MONITORING / "pruebas" / "reglas.test.yaml"


def _reglas() -> list[dict]:
    grupos = yaml.safe_load((CHART_PROPIO / "files" / "reglas.yaml").read_text(encoding="utf-8"))["groups"]
    return [regla for grupo in grupos for regla in grupo["rules"]]


def test_reglas_con_severidad_resumen_y_descripcion():
    for regla in _reglas():
        assert regla["labels"]["severity"] in {"warning", "critical", "info"}, regla["alert"]
        assert regla["annotations"]["summary"], regla["alert"]
        assert regla["annotations"]["description"], regla["alert"]


def test_cada_alerta_tiene_test_de_promtool():
    """Un aviso que nunca salta es tan inútil como uno que salta siempre:
    cada alerta propia se prueba disparando con promtool."""
    pruebas = yaml.safe_load(PRUEBAS_REGLAS.read_text(encoding="utf-8"))
    probadas = {
        caso["alertname"]
        for prueba in pruebas["tests"]
        for caso in prueba["alert_rule_test"]
        if caso["exp_alerts"]
    }

    assert {regla["alert"] for regla in _reglas()} <= probadas


def test_el_stack_no_duplica_las_reglas_propias():
    """KubeJobFailed avisaría del mismo Job que ScanJobFailed, y sin resolverse."""
    desactivadas = _valores()["defaultRules"]["disabled"]

    assert desactivadas["KubeJobFailed"] is True
    assert desactivadas["KubeCPUOvercommit"] is True
    assert desactivadas["KubeMemoryOvercommit"] is True


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm no está instalado")
def test_reglas_las_carga_el_operador():
    """Otro release: sin la etiqueta release=monitoring, el Prometheus del stack
    (ruleSelectorNilUsesHelmValues) ignoraría el PrometheusRule."""
    salida = subprocess.run(
        ["helm", "template", "t", str(CHART_PROPIO), "-n", "monitoring"], check=True, capture_output=True, text=True,
    ).stdout
    (regla,) = [doc for doc in yaml.safe_load_all(salida) if doc and doc["kind"] == "PrometheusRule"]

    assert regla["metadata"]["labels"]["release"] == "monitoring"
    assert regla["metadata"]["namespace"] == "monitoring"
    assert regla["spec"]["groups"][0]["rules"] == _reglas()


# --- Panel de Grafana ---

PANEL = CHART_PROPIO / "files" / "panel-escaneo.json"


def _metricas_que_existen() -> set[str]:
    """Las que escribe de verdad metricas_prometheus, con todas las opciones
    activadas (historial y SNMP): así el test no depende de una lista copiada."""
    from topology_scanner.export import metricas_prometheus

    diff = {"primera_vez": False, "hosts_nuevos": [], "hosts_caidos": [], "hosts_nunca_vistos": []}
    texto = metricas_prometheus({"192.0.2.0/24": {}}, {"192.0.2.0/24": diff}, 1, True, 0)
    return {linea.split()[2] for linea in texto.splitlines() if linea.startswith("# TYPE")}


def _panel() -> dict:
    import json

    return json.loads(PANEL.read_text(encoding="utf-8"))


def test_panel_con_uid_fijo():
    """uid fijo: los enlaces al panel no cambian al reinstalar."""
    assert _panel()["uid"] == "topology-scanner-escaneo"
    assert _panel()["title"] == "Escaneo nocturno"


def test_panel_solo_usa_metricas_que_existen():
    consultas = [
        objetivo["expr"] for panel in _panel()["panels"] for objetivo in panel.get("targets", [])
    ]
    usadas = {nombre for expr in consultas for nombre in re.findall(r"topology_scanner_\w+", expr)}

    assert consultas
    assert usadas
    assert usadas <= _metricas_que_existen()


def test_panel_usa_el_datasource_del_stack():
    for panel in _panel()["panels"]:
        if "targets" in panel:
            assert panel["datasource"] == {"type": "prometheus", "uid": "prometheus"}, panel["title"]


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm no está instalado")
def test_panel_lo_carga_el_sidecar():
    salida = subprocess.run(
        ["helm", "template", "t", str(CHART_PROPIO), "-n", "monitoring"], check=True, capture_output=True, text=True,
    ).stdout
    (mapa,) = [doc for doc in yaml.safe_load_all(salida) if doc and doc["kind"] == "ConfigMap"]

    assert mapa["metadata"]["labels"]["grafana_dashboard"] == "1"
    assert mapa["data"]["panel-escaneo.json"].strip() == PANEL.read_text(encoding="utf-8").strip()


# --- Imágenes por digest (como Trivy, aws-cli, curl y Jenkins) ---


def _imagenes_renderizadas(chart: str, version: str, *valores: str) -> set[str]:
    salida = subprocess.run(
        ["helm", "template", "ci", f"prometheus-community/{chart}", "--version", version, "-n", "monitoring",
         *[arg for v in valores for arg in ("-f", str(MONITORING / v))]],
        check=True, capture_output=True, text=True,
    ).stdout
    imagenes = set(re.findall(r"image: \"?([^\"\s]+)", salida))
    # El operador recibe la imagen del config-reloader como argumento, no como image:
    imagenes |= set(re.findall(r"--prometheus-config-reloader=(\S+)", salida))
    return imagenes


def _version_del_chart(valores: str) -> str:
    return re.findall(r"versión\W+(\d+\.\d+\.\d+)", (MONITORING / valores).read_text(encoding="utf-8"))[0]


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm no está instalado")
@pytest.mark.parametrize("chart, valores", [
    ("kube-prometheus-stack", ("values.yaml", "values.example.yaml")),
    ("prometheus-pushgateway", ("pushgateway.values.yaml",)),
])
def test_imagenes_de_la_monitorizacion_por_digest(chart, valores):
    """Una tag se puede mover (ataque a trivy-action, marzo de 2026): cada
    imagen que llega al clúster va fijada por digest. Necesita el repo de Helm
    prometheus-community añadido (la CI lo añade en el job de tests)."""
    imagenes = _imagenes_renderizadas(chart, _version_del_chart(valores[0]), *valores)

    assert imagenes
    sin_digest = sorted(imagen for imagen in imagenes if "@sha256:" not in imagen)
    assert sin_digest == []
