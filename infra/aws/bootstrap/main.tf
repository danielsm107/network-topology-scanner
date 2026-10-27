data "aws_caller_identity" "actual" {}

# El ID de la cuenta hace el nombre único en todo S3 sin inventar sufijos
resource "aws_s3_bucket" "estado" {
  bucket = "topology-scanner-tfstate-${data.aws_caller_identity.actual.account_id}"

  # Borrar el bucket del estado dejaría huérfana toda la infraestructura
  lifecycle {
    prevent_destroy = true
  }
}

# Versionado: cada escritura del estado deja la anterior recuperable
resource "aws_s3_bucket_versioning" "estado" {
  bucket = aws_s3_bucket.estado.id

  versioning_configuration {
    status = "Enabled"
  }
}

# SSE-S3 (AES256) y no KMS: una clave KMS propia costaría ~1 $/mes
resource "aws_s3_bucket_server_side_encryption_configuration" "estado" {
  bucket = aws_s3_bucket.estado.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "estado" {
  bucket = aws_s3_bucket.estado.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "solo_tls" {
  statement {
    sid     = "DenegarSinTLS"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.estado.arn,
      "${aws_s3_bucket.estado.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "estado" {
  bucket = aws_s3_bucket.estado.id
  policy = data.aws_iam_policy_document.solo_tls.json

  # La política se rechaza si el bloqueo de acceso público aún se está aplicando
  depends_on = [aws_s3_bucket_public_access_block.estado]
}

# Las versiones antiguas del estado no se guardan para siempre
resource "aws_s3_bucket_lifecycle_configuration" "estado" {
  bucket = aws_s3_bucket.estado.id

  rule {
    id     = "caducar-versiones-antiguas"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }

  depends_on = [aws_s3_bucket_versioning.estado]
}
