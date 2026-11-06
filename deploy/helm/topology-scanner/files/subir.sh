#!/bin/sh
# Contenedor "subida" del Job nocturno (imagen amazon/aws-cli). Corre después
# del escaneo, que deja sus archivos en /salida:
#   network_topology.html, inventory.csv, historial.db (copia consistente) y,
#   solo si hubo cambios, cambios/{cambios.json,asunto.txt,cuerpo.txt}.
# Sube los informes y la copia del historial a S3 y, si hubo cambios, publica
# el aviso en SNS con enlaces temporales al mapa y al CSV.
#
# Entorno: BUCKET, TOPIC_ARN, DIAS_ENLACES, AWS_REGION y las claves del Secret.
# Cualquier fallo termina el Job como fallido (set -e): se ve en el clúster.
set -eu

SALIDA=/salida
PREFIJO="informes/$(date +%Y-%m-%dT%H%M)"
DESTINO="s3://$BUCKET/$PREFIJO"

aws s3 cp "$SALIDA/network_topology.html" "$DESTINO/network_topology.html" --only-show-errors
aws s3 cp "$SALIDA/inventory.csv" "$DESTINO/inventory.csv" --only-show-errors
# Siempre la misma clave: el versionado del bucket guarda las anteriores (30 días)
aws s3 cp "$SALIDA/historial.db" "s3://$BUCKET/historial/historial.db" --only-show-errors
echo "Informes subidos a $DESTINO/ y copia del historial a historial/historial.db"

# La app solo escribe cambios.json si hubo cambios: sin él no hay email
if [ ! -f "$SALIDA/cambios/cambios.json" ]; then
  echo "Sin cambios respecto al escaneo anterior: no se avisa."
  exit 0
fi

aws s3 cp "$SALIDA/cambios/cambios.json" "$DESTINO/cambios.json" --only-show-errors

# Enlaces firmados con las claves del usuario del homelab (máximo 7 días)
SEGUNDOS=$((DIAS_ENLACES * 86400))
MAPA=$(aws s3 presign "$DESTINO/network_topology.html" --expires-in "$SEGUNDOS")
CSV=$(aws s3 presign "$DESTINO/inventory.csv" --expires-in "$SEGUNDOS")

{
  cat "$SALIDA/cambios/cuerpo.txt"
  printf '\nREPORTS (links valid for %s days)\n  Map: %s\n  CSV: %s\n' "$DIAS_ENLACES" "$MAPA" "$CSV"
} > /tmp/mensaje.txt

aws sns publish \
  --topic-arn "$TOPIC_ARN" \
  --subject "$(cat "$SALIDA/cambios/asunto.txt")" \
  --message file:///tmp/mensaje.txt > /dev/null
echo "Aviso publicado en SNS."
