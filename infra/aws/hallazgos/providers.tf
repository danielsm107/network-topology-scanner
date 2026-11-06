provider "aws" {
  region = var.region
  # En el PC, "personal" (nunca el default: es la cuenta del trabajo). En
  # GitHub Actions, null: las credenciales llegan por OIDC en el entorno.
  profile = var.aws_profile

  default_tags {
    tags = {
      Project   = "topology-scanner"
      ManagedBy = "terraform"
    }
  }
}
