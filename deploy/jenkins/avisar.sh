#!/bin/sh
# Avisa por email de un despliegue fallido: mismo topic SNS que los hallazgos.
#   avisar.sh <asunto> <cuerpo>
# Entorno: TOPIC_ARN, AWS_REGION y las claves del usuario IAM de Jenkins.
exec aws sns publish --topic-arn "$TOPIC_ARN" --subject "$1" --message "$2" --output text > /dev/null
