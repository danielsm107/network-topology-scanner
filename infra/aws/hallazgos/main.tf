data "aws_caller_identity" "actual" {}

locals {
  cuenta = data.aws_caller_identity.actual.account_id
  # El ID de la cuenta hace el nombre único en todo S3 sin inventar sufijos
  bucket     = "topology-scanner-informes-${local.cuenta}"
  bucket_arn = "arn:aws:s3:::${local.bucket}"
  # ARNs construidos a mano y no leídos de los recursos: así las políticas
  # (locals) se pueden comprobar en terraform test con el provider simulado
  topic_nombre = "topology-scanner-hallazgos"
  topic_arn    = "arn:aws:sns:${var.region}:${local.cuenta}:${local.topic_nombre}"
}

# --- Bucket de informes: informes/<fecha>/ (HTML, CSV, cambios) e historial/ ---

resource "aws_s3_bucket" "informes" {
  bucket = local.bucket
}

resource "aws_s3_bucket_public_access_block" "informes" {
  bucket = aws_s3_bucket.informes.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SSE-S3 (AES256) y no KMS: una clave KMS propia costaría ~1 $/mes
resource "aws_s3_bucket_server_side_encryption_configuration" "informes" {
  bucket = aws_s3_bucket.informes.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Versionado para historial/historial.db: cada copia nocturna deja la anterior
# recuperable (si una noche se sube una base mala, se restaura la de ayer)
resource "aws_s3_bucket_versioning" "informes" {
  bucket = aws_s3_bucket.informes.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "informes" {
  bucket = aws_s3_bucket.informes.id
  # Las reglas de versiones no actuales necesitan el versionado ya activo
  depends_on = [aws_s3_bucket_versioning.informes]

  rule {
    id     = "informes-90-dias"
    status = "Enabled"

    filter {
      prefix = "informes/"
    }

    expiration {
      days = 90
    }

    # Con versionado, expirar deja la versión como "no actual": se borra al día siguiente
    noncurrent_version_expiration {
      noncurrent_days = 1
    }
  }

  rule {
    id     = "historial-30-dias"
    status = "Enabled"

    filter {
      prefix = "historial/"
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }

  # Los marcadores de borrado que quedan solos tras expirar, fuera
  rule {
    id     = "marcadores-de-borrado"
    status = "Enabled"

    filter {}

    expiration {
      expired_object_delete_marker = true
    }
  }
}

# --- Avisos: SNS con suscripción por email ---

resource "aws_sns_topic" "hallazgos" {
  name = local.topic_nombre
}

# Queda "pending confirmation" hasta pulsar el enlace del email que manda AWS
resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.hallazgos.arn
  protocol  = "email"
  endpoint  = var.email_avisos
}
