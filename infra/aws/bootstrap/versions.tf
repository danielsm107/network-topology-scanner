# Bootstrap: crea el bucket donde el resto de raíces guardan su estado.
# Su propio estado es local (terraform.tfstate, ignorado por git): Terraform no
# puede guardar el estado en un bucket que todavía no existe. Si se pierde, el
# bucket se recupera con `terraform import`.

terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  # Nunca el perfil default: en este PC es la cuenta del trabajo
  profile = "personal"
  region  = "eu-south-2"

  default_tags {
    tags = {
      Project   = "topology-scanner"
      ManagedBy = "terraform"
    }
  }
}
