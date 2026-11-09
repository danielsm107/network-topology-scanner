# Tests del plan con el provider simulado: no hablan con AWS ni necesitan
# credenciales, así que corren igual en el PC que en la CI. Las políticas IAM
# son locals (jsonencode), no data sources: simulados devolverían texto al azar.

mock_provider "aws" {
  override_data {
    target = data.aws_caller_identity.actual
    values = {
      account_id = "123456789012"
    }
  }
}

variables {
  email_avisos  = "alerts@example.com"
  bucket_estado = "topology-scanner-tfstate-123456789012"
}

run "bucket_de_informes_privado_y_cifrado" {
  command = plan

  assert {
    condition     = aws_s3_bucket.informes.bucket == "topology-scanner-informes-123456789012"
    error_message = "El bucket de informes no lleva el ID de la cuenta en el nombre."
  }

  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.informes.block_public_acls,
      aws_s3_bucket_public_access_block.informes.block_public_policy,
      aws_s3_bucket_public_access_block.informes.ignore_public_acls,
      aws_s3_bucket_public_access_block.informes.restrict_public_buckets,
    ])
    error_message = "El bucket de informes no bloquea todo el acceso público."
  }

  assert {
    # SSE-S3 y no KMS: una clave KMS propia costaría ~1 $/mes
    condition = alltrue([
      for regla in aws_s3_bucket_server_side_encryption_configuration.informes.rule :
      regla.apply_server_side_encryption_by_default[0].sse_algorithm == "AES256"
    ])
    error_message = "El bucket de informes no cifra con SSE-S3 (AES256)."
  }

  assert {
    condition     = aws_s3_bucket_versioning.informes.versioning_configuration[0].status == "Enabled"
    error_message = "Sin versionado no hay copias anteriores del historial que restaurar."
  }
}

run "retenciones_de_90_y_30_dias" {
  command = plan

  assert {
    condition = anytrue([
      for regla in aws_s3_bucket_lifecycle_configuration.informes.rule :
      regla.filter[0].prefix == "informes/" && regla.expiration[0].days == 90
    ])
    error_message = "Los informes no caducan a los 90 días."
  }

  assert {
    condition = anytrue([
      for regla in aws_s3_bucket_lifecycle_configuration.informes.rule :
      regla.filter[0].prefix == "historial/" && regla.noncurrent_version_expiration[0].noncurrent_days == 30
    ])
    error_message = "Las copias antiguas del historial no se borran a los 30 días."
  }
}

run "usuario_del_homelab_con_minimo_privilegio" {
  command = plan

  assert {
    condition     = length(local.politica_homelab.Statement) == 3
    error_message = "La política del homelab tiene que ser: subir, leer informes (enlaces) y publicar."
  }

  assert {
    condition = alltrue(flatten([
      for sentencia in local.politica_homelab.Statement : [
        for accion in sentencia.Action : !strcontains(accion, "*")
      ]
    ]))
    error_message = "La política del homelab usa comodines en las acciones."
  }

  assert {
    condition = anytrue([
      for sentencia in local.politica_homelab.Statement :
      sentencia.Action == ["s3:GetObject"] && sentencia.Resource == ["arn:aws:s3:::topology-scanner-informes-123456789012/informes/*"]
    ])
    error_message = "El homelab solo puede leer informes/ (para firmar los enlaces), no historial/."
  }
}

run "usuario_de_jenkins_solo_avisa" {
  command = plan

  assert {
    condition     = aws_iam_user.jenkins.name == "topology-scanner-jenkins"
    error_message = "El usuario de Jenkins no se llama como se espera (el rol de apply solo gestiona topology-scanner-*)."
  }

  assert {
    condition     = length(local.politica_jenkins.Statement) == 1
    error_message = "Jenkins solo necesita publicar: el usuario del homelab ya tiene S3 y por eso no se reutiliza."
  }

  assert {
    condition = (
      local.politica_jenkins.Statement[0].Action == ["sns:Publish"] &&
      local.politica_jenkins.Statement[0].Resource == ["arn:aws:sns:eu-south-2:123456789012:topology-scanner-hallazgos"]
    )
    error_message = "Jenkins solo puede publicar en el topic de avisos."
  }
}

run "roles_de_github_separados" {
  command = plan

  assert {
    condition     = local.trust_plan.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:danielsm107@159171084/network-topology-scanner@1338150966:pull_request"
    error_message = "El rol de plan no está limitado a los PRs del repo."
  }

  assert {
    condition     = local.trust_apply.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:danielsm107@159171084/network-topology-scanner@1338150966:environment:aws"
    error_message = "El rol de apply no está limitado al environment aws (con aprobación)."
  }

  assert {
    condition = alltrue([
      for trust in [local.trust_plan, local.trust_apply] :
      trust.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
    ])
    error_message = "Los roles de GitHub no comprueban la audiencia del token OIDC."
  }
}

run "aviso_por_email" {
  command = plan

  assert {
    condition     = aws_sns_topic_subscription.email.protocol == "email"
    error_message = "La suscripción del topic no es por email."
  }

  assert {
    condition     = aws_sns_topic_subscription.email.endpoint == "alerts@example.com"
    error_message = "La suscripción no usa var.email_avisos."
  }
}
