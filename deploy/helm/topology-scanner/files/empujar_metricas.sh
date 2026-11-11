#!/bin/sh
# Contenedor "metricas" del Job nocturno (imagen curlimages/curl). Corre después
# del escaneo, que deja en /salida/metricas.prom sus métricas en el formato de
# texto de Prometheus (--metrics-file), y las sube al Pushgateway.
#
# PUT al grupo del job: sustituye todas sus series, así que un rango que se deja
# de escanear no se queda congelado con su último valor.
#
# Si el Pushgateway no está o falla, el Job NO falla: el escaneo ya se hizo y se
# guardó. El hueco lo avisa Prometheus (alerta ScanMetricsStale).
#
# Entorno: PUSHGATEWAY (p. ej. http://prometheus-pushgateway.monitoring.svc:9091);
# SALIDA solo se cambia en los tests.
set -eu

SALIDA="${SALIDA:-/salida}"
ARCHIVO="$SALIDA/metricas.prom"

if [ ! -f "$ARCHIVO" ]; then
  echo "AVISO: el escaneo no dejó $ARCHIVO; no se suben métricas." >&2
  exit 0
fi

if curl -sS --fail --max-time 30 --retry 3 -X PUT --data-binary "@$ARCHIVO" \
    "$PUSHGATEWAY/metrics/job/topology_scanner"; then
  echo "Métricas subidas a $PUSHGATEWAY."
else
  echo "AVISO: no se pudieron subir las métricas a $PUSHGATEWAY." >&2
fi
