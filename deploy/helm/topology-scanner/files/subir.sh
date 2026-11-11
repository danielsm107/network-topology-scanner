#!/bin/sh
# Contenedor "subida" del Job nocturno (imagen amazon/aws-cli). Corre después
# del escaneo, que deja sus archivos en /salida:
#   network_topology.html, inventory.csv, historial.db (copia consistente) y,
#   solo si algo merece aviso (history.merece_aviso), cambios/{cambios.json,asunto.txt,cuerpo.txt}.
# Sube los informes y la copia del historial a S3 y publica
# el aviso en SNS, si lo hay, con enlaces temporales al mapa y al CSV.
#
# Entorno: BUCKET, TOPIC_ARN, DIAS_ENLACES, AWS_REGION y las claves del Secret
# (SALIDA y TMPDIR solo se cambian en los tests).
# Cualquier fallo termina el Job como fallido: se ve en el clúster. Los errores
# pasajeros de AWS los reintenta aws-cli (AWS_RETRY_MODE en el chart).
set -eu

SALIDA="${SALIDA:-/salida}"
TEMPORAL="${TMPDIR:-/tmp}"
FALLO=0
PREFIJO="informes/$(date +%Y-%m-%dT%H%M)"
DESTINO="s3://$BUCKET/$PREFIJO"

aws s3 cp "$SALIDA/network_topology.html" "$DESTINO/network_topology.html" --only-show-errors
aws s3 cp "$SALIDA/inventory.csv" "$DESTINO/inventory.csv" --only-show-errors
echo "Informes subidos a $DESTINO/"

# Siempre la misma clave: el versionado del bucket guarda las anteriores (30 días).
# Si falla (o la app no pudo hacer la copia), el aviso de esta noche sale igual:
# el diff ya está en el historial y mañana no se volvería a avisar
if aws s3 cp "$SALIDA/historial.db" "s3://$BUCKET/historial/historial.db" --only-show-errors; then
  echo "Copia del historial subida a historial/historial.db"
else
  echo "ERROR: no se pudo subir la copia del historial" >&2
  FALLO=1
fi

# La app solo escribe cambios.json si algo merece aviso: sin él no hay email.
# Puede haber habido cambios (hosts que entran y salen): la web los enseña
if [ ! -f "$SALIDA/cambios/cambios.json" ]; then
  echo "Nada que merezca aviso (ni hosts nunca vistos con puertos ni cambios de puertos): no se avisa."
  exit "$FALLO"
fi

aws s3 cp "$SALIDA/cambios/cambios.json" "$DESTINO/cambios.json" --only-show-errors

# Enlaces firmados con las claves del usuario del homelab (máximo 7 días)
SEGUNDOS=$((DIAS_ENLACES * 86400))
MAPA=$(aws s3 presign "$DESTINO/network_topology.html" --expires-in "$SEGUNDOS")
CSV=$(aws s3 presign "$DESTINO/inventory.csv" --expires-in "$SEGUNDOS")

{
  cat "$SALIDA/cambios/cuerpo.txt"
  printf '\nREPORTS (links valid for %s days)\n  Map: %s\n  CSV: %s\n' "$DIAS_ENLACES" "$MAPA" "$CSV"
} > "$TEMPORAL/mensaje.txt"

aws sns publish \
  --topic-arn "$TOPIC_ARN" \
  --subject "$(cat "$SALIDA/cambios/asunto.txt")" \
  --message "file://$TEMPORAL/mensaje.txt" > /dev/null
echo "Aviso publicado en SNS."
exit "$FALLO"
