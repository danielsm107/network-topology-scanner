# VM del nodo k3s en Proxmox. El estado vive en el bucket S3 del bootstrap
# (infra/aws/bootstrap): el backend va vacío y se completa con backend.hcl
# (`terraform init -backend-config=backend.hcl`), que no se versiona porque
# lleva el ID de la cuenta en el nombre del bucket.

terraform {
  # Validaciones que se refieren a otras variables (gateway vs. ip_cidr): TF >= 1.9
  required_version = ">= 1.10"

  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "~> 0.118"
    }
  }

  backend "s3" {}
}
