# Quién entra en AWS y con qué permisos:
# - el CronJob del homelab, con un usuario IAM (claves estáticas en un Secret de
#   Kubernetes: sin PKI no hay forma de evitarlas, ver docs/decisiones.md);
# - GitHub Actions, por OIDC y sin claves, con un rol de solo lectura para el
#   plan de los PRs y otro de escritura para el apply en main (con aprobación).
#
# Las políticas son locals (jsonencode) para que terraform test pueda mirarlas.

locals {
  oidc_url = "token.actions.githubusercontent.com"
  oidc_arn = "arn:aws:iam::${local.cuenta}:oidc-provider/${local.oidc_url}"

  estado_arn = "arn:aws:s3:::${var.bucket_estado}"
  # Lo que gestiona esta raíz en IAM: todo empieza por topology-scanner
  iam_propios = [
    "arn:aws:iam::${local.cuenta}:user/topology-scanner-*",
    "arn:aws:iam::${local.cuenta}:role/topology-scanner-*",
    local.oidc_arn,
  ]

  # --- Homelab: subir, leer informes (los enlaces se firman con estas claves) y avisar ---
  politica_homelab = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Subir"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = ["${local.bucket_arn}/informes/*", "${local.bucket_arn}/historial/*"]
      },
      {
        # Un enlace prefirmado solo funciona si quien firma puede leer el objeto.
        # historial/ no: la restauración se hace desde el PC del mantenedor.
        Sid      = "EnlacesDeInformes"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["${local.bucket_arn}/informes/*"]
      },
      {
        Sid      = "Avisar"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [local.topic_arn]
      },
    ]
  }

  # --- Jenkins: solo avisar de un despliegue fallido. No reutiliza el usuario del homelab, que escribe en S3 ---
  politica_jenkins = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Avisar"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [local.topic_arn]
      },
    ]
  }

  # --- GitHub Actions ---
  trust_github = {
    for nombre, sub in {
      plan  = "repo:${var.repo_github}:pull_request"
      apply = "repo:${var.repo_github}:environment:${var.environment_apply}"
      } : nombre => {
      Version = "2012-10-17"
      Statement = [{
        Effect    = "Allow"
        Principal = { Federated = local.oidc_arn }
        Action    = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${local.oidc_url}:aud" = "sts.amazonaws.com"
            "${local.oidc_url}:sub" = sub
          }
        }
      }]
    }
  }
  trust_plan  = local.trust_github["plan"]
  trust_apply = local.trust_github["apply"]

  # Leer la configuración de lo que gestiona esta raíz (nunca los objetos del
  # bucket de informes: ahí está la copia del historial)
  lectura = [
    {
      Sid    = "LeerBucket"
      Effect = "Allow"
      Action = [
        "s3:ListBucket", "s3:GetBucket*", "s3:GetLifecycleConfiguration", "s3:GetEncryptionConfiguration",
        "s3:GetAccelerateConfiguration", "s3:GetReplicationConfiguration",
      ]
      Resource = [local.bucket_arn]
    },
    {
      Sid      = "LeerSns"
      Effect   = "Allow"
      Action   = ["sns:GetTopicAttributes", "sns:GetSubscriptionAttributes", "sns:ListTagsForResource", "sns:GetDataProtectionPolicy"]
      Resource = [local.topic_arn, "${local.topic_arn}:*"]
    },
    {
      Sid      = "LeerIam"
      Effect   = "Allow"
      Action   = ["iam:Get*", "iam:List*"]
      Resource = local.iam_propios
    },
    {
      Sid      = "LeerEstado"
      Effect   = "Allow"
      Action   = ["s3:ListBucket"]
      Resource = [local.estado_arn]
    },
    {
      Sid      = "LeerClaveDelEstado"
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = ["${local.estado_arn}/${var.clave_estado}"]
    },
  ]

  politica_plan = {
    Version   = "2012-10-17"
    Statement = local.lectura
  }

  politica_apply = {
    Version = "2012-10-17"
    Statement = concat(local.lectura, [
      {
        Sid    = "GestionarBucket"
        Effect = "Allow"
        Action = [
          "s3:CreateBucket", "s3:DeleteBucket", "s3:PutBucket*", "s3:PutLifecycleConfiguration",
          "s3:PutEncryptionConfiguration",
        ]
        Resource = [local.bucket_arn]
      },
      {
        Sid    = "GestionarSns"
        Effect = "Allow"
        Action = [
          "sns:CreateTopic", "sns:DeleteTopic", "sns:SetTopicAttributes", "sns:TagResource", "sns:UntagResource",
          "sns:Subscribe", "sns:Unsubscribe", "sns:SetSubscriptionAttributes",
        ]
        Resource = [local.topic_arn, "${local.topic_arn}:*"]
      },
      {
        Sid      = "GestionarIam"
        Effect   = "Allow"
        Action   = ["iam:*"]
        Resource = local.iam_propios
      },
      {
        # Ni el pipeline crea claves o contraseñas: la del homelab se hace a mano
        Sid      = "SinClavesNiContrasenas"
        Effect   = "Deny"
        Action   = ["iam:CreateAccessKey", "iam:UpdateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile"]
        Resource = ["*"]
      },
      {
        Sid      = "EscribirEstado"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:DeleteObject"]
        Resource = ["${local.estado_arn}/${var.clave_estado}", "${local.estado_arn}/${var.clave_estado}.tflock"]
      },
      {
        Sid      = "LeerLockDelEstado"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["${local.estado_arn}/${var.clave_estado}.tflock"]
      },
    ])
  }
}

resource "aws_iam_user" "homelab" {
  name = "topology-scanner-homelab"
}

resource "aws_iam_user_policy" "homelab" {
  name   = "subir-informes-y-avisar"
  user   = aws_iam_user.homelab.name
  policy = jsonencode(local.politica_homelab)
}

# Su clave se crea a mano (runbook 05), como la del homelab: en Terraform quedaría en el estado
resource "aws_iam_user" "jenkins" {
  name = "topology-scanner-jenkins"
}

resource "aws_iam_user_policy" "jenkins" {
  name   = "avisar"
  user   = aws_iam_user.jenkins.name
  policy = jsonencode(local.politica_jenkins)
}

# Sin thumbprint: AWS ya no lo comprueba para el OIDC de GitHub
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://${local.oidc_url}"
  client_id_list = ["sts.amazonaws.com"]
}

resource "aws_iam_role" "github_plan" {
  name               = "topology-scanner-github-plan"
  assume_role_policy = jsonencode(local.trust_plan)
  # El provider OIDC tiene que existir antes que el trust que lo nombra
  depends_on = [aws_iam_openid_connect_provider.github]
}

resource "aws_iam_role_policy" "github_plan" {
  name   = "plan-solo-lectura"
  role   = aws_iam_role.github_plan.id
  policy = jsonencode(local.politica_plan)
}

resource "aws_iam_role" "github_apply" {
  name               = "topology-scanner-github-apply"
  assume_role_policy = jsonencode(local.trust_apply)
  depends_on         = [aws_iam_openid_connect_provider.github]
}

resource "aws_iam_role_policy" "github_apply" {
  name   = "apply-de-esta-raiz"
  role   = aws_iam_role.github_apply.id
  policy = jsonencode(local.politica_apply)
}
