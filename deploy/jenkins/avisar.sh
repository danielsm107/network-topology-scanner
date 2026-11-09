#!/bin/sh
# Avisa por email de un despliegue fallido: mismo topic SNS que los hallazgos.
#   avisar.sh <asunto> <cuerpo>
# Entorno: TOPIC_ARN y las claves del usuario IAM de Jenkins.
# La región sale del propio ARN: el aws-cli de alpine/k8s es la v1, que no lee AWS_REGION.
region=$(printf '%s' "$TOPIC_ARN" | cut -d: -f4)
exec aws sns publish --region "$region" --topic-arn "$TOPIC_ARN" --subject "$1" --message "$2" --output text > /dev/null
