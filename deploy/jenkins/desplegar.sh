#!/bin/sh
# Despliega el escáner: elige versión, espera a que esté publicada, helm upgrade,
# helm test y, si algo falla, vuelve atrás, marca la versión y avisa por email.
# Toda la lógica vive aquí para probarla sin clúster (tests/test_jenkins.py).
#
# Entorno:
#   MODO             automatico: despliega la versión nueva, si la hay (sondeo)
#                    manual: despliega VERSION; vacía = vuelve a desplegar la
#                    actual con los values del Secret (así se aplica un cambio de rangos)
#                    consultar: solo imprime la versión que desplegaría
#   VERSION          X.Y.Z (solo manual)
#   ENSAYO           ninguno | no-arranca | falla-prueba (solo manual, runbook 05)
#   URL_EJECUCION    enlace a esta ejecución de Jenkins, para el email
#   ESPERA_SEGUNDOS, INTERVALO_SEGUNDOS  espera a la publicación
#
# Códigos de salida:
#   0  bien, o nada que hacer
#   1  falló, y se ha vuelto atrás (o no había nada que deshacer)
#   2  uso incorrecto
#   3  falló también la vuelta atrás: hay que intervenir
#   4  no se pudo leer el estado: no se ha tocado nada y el siguiente sondeo reintenta
set -u

MODO="${MODO:-}"
VERSION="${VERSION:-}"
ENSAYO="${ENSAYO:-ninguno}"
URL_EJECUCION="${URL_EJECUCION:-}"
ESPERA_SEGUNDOS="${ESPERA_SEGUNDOS:-3600}"
INTERVALO_SEGUNDOS="${INTERVALO_SEGUNDOS:-60}"

AQUI=$(dirname "$0")
REPO="${REPO_URL:-https://github.com/danielsm107/network-topology-scanner.git}"
NS=topology-scanner
RELEASE=topology-scanner
NS_JENKINS=jenkins
ESTADO=estado-despliegue
RESTAURAR="https://github.com/danielsm107/network-topology-scanner/blob/main/docs/devops/runbooks/04-aws.md"

log() { echo "$*" >&2; }

uso_incorrecto() {
  log "ERROR: $1"
  exit 2
}

case "$MODO" in
  automatico | consultar)
    [ "$ENSAYO" = "ninguno" ] || uso_incorrecto "los ensayos solo existen en ejecución manual"
    ;;
  manual)
    case "$ENSAYO" in
      ninguno | no-arranca | falla-prueba) ;;
      *) uso_incorrecto "ensayo desconocido: $ENSAYO" ;;
    esac
    ;;
  *) uso_incorrecto "MODO tiene que ser automatico, manual o consultar" ;;
esac

TEMPORAL=$(mktemp -d)
trap 'rm -rf "$TEMPORAL"' EXIT

# --- Estado: sin él no se toca nada ------------------------------------------

sin_estado() {
  log "ERROR: no se pudo leer $1. No se ha tocado nada."
  exit 4
}

DESPLEGADA=$(kubectl -n "$NS" get deploy "$RELEASE-web" \
  -o jsonpath='{.metadata.labels.app\.kubernetes\.io/version}') || sin_estado "la versión desplegada"
[ -n "$DESPLEGADA" ] || sin_estado "la versión desplegada"

FALLIDAS=$(kubectl -n "$NS_JENKINS" get configmap "$ESTADO" \
  -o jsonpath='{.data.fallidas}') || sin_estado "las versiones fallidas"

# --- Marcar y desmarcar versiones --------------------------------------------

guardar_fallidas() {
  json=$(printf '%s' "$1" | awk 'NF { printf "%s\\n", $0 }')
  kubectl -n "$NS_JENKINS" patch configmap "$ESTADO" --type merge \
    -p "{\"data\":{\"fallidas\":\"$json\"}}" > /dev/null
}

marcar_fallida() {
  [ "$MARCABLE" = "si" ] || return 0
  guardar_fallidas "$(printf '%s\n%s\n' "$FALLIDAS" "$OBJETIVO")" \
    || log "ERROR: no se pudo marcar $OBJETIVO como fallida: el siguiente sondeo lo volverá a intentar"
}

quitar_marca() {
  printf '%s\n' "$FALLIDAS" | grep -qxF "$OBJETIVO" || return 0
  guardar_fallidas "$(printf '%s\n' "$FALLIDAS" | grep -vxF "$OBJETIVO")" \
    || log "AVISO: no se pudo quitar la marca de $OBJETIVO"
}

# --- Aviso -------------------------------------------------------------------

avisar() {
  asunto="$1"
  cuerpo="$2"
  [ "$ENSAYO" = "ninguno" ] || asunto="REHEARSAL $asunto"
  log "$asunto"
  log "$cuerpo"
  sh "$AQUI/avisar.sh" "$asunto" "$cuerpo" || log "ERROR: no se pudo mandar el email"
}

cuerpo_fallo() {
  printf 'Version: %s\nFailed step: %s\nState: %s\nRun: %s\n' "$OBJETIVO" "$1" "$2" "$URL_EJECUCION"
}

# Sin haber tocado el clúster: no hay nada que deshacer
fallo_sin_cambios() {
  marcar_fallida
  avisar "topology-scanner deploy FAILED: $OBJETIVO" \
    "$(cuerpo_fallo "$1" "nothing changed in the cluster, still on $DESPLEGADA")"
  exit 1
}

# Helm no devuelve los datos atrás: una versión que migró el esquema del
# historial puede dejar la base en un formato que la anterior no entienda
ADVERTENCIA="The rollback does not revert data. If this version changed the history schema, \
check the next nightly scan and, if it fails, restore the history from S3: $RESTAURAR"

fallo_con_rollback() {
  paso="$1"
  # La marca lo primero: si este pod muere a medias, no hay otro intento
  marcar_fallida
  log "Volviendo a la versión anterior: falló $paso"
  if ! helm rollback "$RELEASE" 0 -n "$NS" --wait --timeout 5m >&2; then
    avisar "URGENT topology-scanner rollback FAILED: $OBJETIVO" \
      "$(cuerpo_fallo "$paso, then helm rollback" "the cluster may be broken, needs manual action")"
    exit 3
  fi
  if ! probar; then
    avisar "URGENT topology-scanner rollback FAILED: $OBJETIVO" \
      "$(cuerpo_fallo "$paso, then helm test after the rollback" "rolled back, but the test does not pass")"
    exit 3
  fi
  avisar "topology-scanner deploy FAILED: $OBJETIVO" \
    "$(cuerpo_fallo "$paso" "rolled back to $DESPLEGADA")

$ADVERTENCIA"
  exit 1
}

# --- Comprobaciones ----------------------------------------------------------

# Sin "Succeeded" no hubo ninguna prueba: una revisión sin hooks da código 0
probar() {
  salida=$(helm test "$RELEASE" -n "$NS" --timeout 10m --logs 2>&1)
  codigo=$?
  log "$salida"
  [ "$codigo" -eq 0 ] && printf '%s\n' "$salida" | grep -q 'Phase: *Succeeded'
}

corre_la_imagen() {
  web=$(kubectl -n "$NS" get deploy "$RELEASE-web" -o jsonpath='{.spec.template.spec.containers[*].image}') || return 1
  # Con aws.enabled, el escaneo va en initContainers
  escaneo=$(kubectl -n "$NS" get cronjob "$RELEASE-escaneo" -o jsonpath='{.spec.jobTemplate.spec.template.spec.initContainers[*].image} {.spec.jobTemplate.spec.template.spec.containers[*].image}') || return 1
  case " $web " in *":$1 "*) ;; *) return 1 ;; esac
  case " $escaneo " in *":$1 "*) ;; *) return 1 ;; esac
}

esperar_publicada() {
  limite=$(($(date +%s) + ESPERA_SEGUNDOS))
  while :; do
    sh "$AQUI/comprobar_publicada.sh" "$OBJETIVO" && return 0
    [ "$(date +%s)" -lt "$limite" ] || return 1
    log "$OBJETIVO todavía no está publicada; se vuelve a mirar en $INTERVALO_SEGUNDOS s"
    sleep "$INTERVALO_SEGUNDOS"
  done
}

# --- Qué desplegar -----------------------------------------------------------

MARCABLE=si
ESPERAR=si
case "$MODO" in
  automatico | consultar)
    TAGS=$(git ls-remote --tags --refs "$REPO") || sin_estado "los tags del repo"
    printf '%s\n' "$FALLIDAS" > "$TEMPORAL/fallidas"
    OBJETIVO=$(printf '%s\n' "$TAGS" | sed 's#.*refs/tags/##' \
      | sh "$AQUI/elegir_version.sh" "$DESPLEGADA" "$TEMPORAL/fallidas") || sin_estado "la versión a desplegar"
    if [ -z "$OBJETIVO" ]; then
      log "Nada que desplegar (desplegada: $DESPLEGADA)"
      exit 0
    fi
    if [ "$MODO" = "consultar" ]; then
      echo "$OBJETIVO"
      exit 0
    fi
    ;;
  manual)
    OBJETIVO="${VERSION:-$DESPLEGADA}"
    # El problema de volver a desplegar lo que ya corría son los values, no la versión
    if [ "$OBJETIVO" = "$DESPLEGADA" ]; then
      MARCABLE=no
      ESPERAR=no
    fi
    if [ "$ENSAYO" != "ninguno" ]; then
      OBJETIVO="$DESPLEGADA"
      MARCABLE=no
      ESPERAR=no
    fi
    ;;
esac

log "Desplegando $OBJETIVO (desplegada: $DESPLEGADA, modo: $MODO, ensayo: $ENSAYO)"

if [ "$ESPERAR" = "si" ] && ! esperar_publicada; then
  fallo_sin_cambios "waiting for the release and the image (${ESPERA_SEGUNDOS}s)"
fi

# --- Preparar: chart del tag y values del Secret -----------------------------

git clone --quiet --depth 1 --branch "v$OBJETIVO" "$REPO" "$TEMPORAL/repo" >&2 \
  || fallo_sin_cambios "cloning tag v$OBJETIVO"

VALUES=$(kubectl -n "$NS" get secret topology-scanner-values -o jsonpath='{.data.values\.yaml}') \
  || fallo_sin_cambios "reading Secret topology-scanner-values"
printf '%s' "$VALUES" | base64 -d > "$TEMPORAL/values.yaml" \
  || fallo_sin_cambios "decoding Secret topology-scanner-values"

# --- Desplegar y probar ------------------------------------------------------

TAG_IMAGEN="$OBJETIVO"
EXTRA=""
case "$ENSAYO" in
  no-arranca) TAG_IMAGEN="0.0.0-ensayo-no-existe" ;;
  falla-prueba) EXTRA="--set pruebas.versionEsperada=0.0.0-ensayo" ;;
esac

# image.tag después de -f: los values reales no pueden desplegar otra imagen
# shellcheck disable=SC2086
helm upgrade "$RELEASE" "$TEMPORAL/repo/deploy/helm/topology-scanner" -n "$NS" \
  -f "$TEMPORAL/values.yaml" --set "image.tag=$TAG_IMAGEN" $EXTRA --wait --timeout 5m >&2 \
  || fallo_con_rollback "helm upgrade"

probar || fallo_con_rollback "helm test"
corre_la_imagen "$TAG_IMAGEN" || fallo_con_rollback "image check"

[ "$MODO" != "manual" ] || quitar_marca
log "Desplegada $OBJETIVO: prueba correcta"
