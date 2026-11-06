# Lo de AWS que usa el despliegue del homelab: bucket de informes (y copia del
# historial), SNS para los avisos por email, el usuario IAM con el que sube el
# CronJob, y la entrada de GitHub Actions por OIDC (rol de plan y rol de apply).
#
# El estado vive en el bucket del bootstrap (infra/aws/bootstrap). El backend
# va vacío: en el PC se completa con backend.hcl (ignorado), y en GitHub
# Actions con -backend-config desde las variables del repo.

terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  backend "s3" {}
}
