variable "region" {
  description = "Región de AWS (la misma que el bucket del estado)"
  type        = string
  default     = "eu-south-2"
}

variable "aws_profile" {
  description = "Perfil de AWS CLI en el PC (personal). Vacío en GitHub Actions"
  type        = string
  default     = null
}

variable "email_avisos" {
  description = "Dirección que recibe los avisos de cambios en la red"
  type        = string
  # Sensible: el plan se publica en los PRs de un repo público
  sensitive = true
}

variable "bucket_estado" {
  description = "Bucket del estado de Terraform (output bucket_estado del bootstrap)"
  type        = string
}

variable "clave_estado" {
  description = "Clave del estado de esta raíz dentro de bucket_estado"
  type        = string
  default     = "hallazgos/terraform.tfstate"
}

variable "repo_github" {
  description = "Repositorio cuyos workflows pueden entrar en AWS por OIDC, como aparece en el sub del token"
  type        = string
  # Formato inmutable (usuario@id/repo@id) que GitHub usa en este repo: el sub
  # del token lleva los IDs, que no cambian. Si el repo se renombra o se borra y
  # alguien crea otro con el mismo nombre, no puede entrar en esta cuenta.
  # Comprobar con: gh api repos/{owner}/{repo}/actions/oidc/customization/sub
  default = "danielsm107@159171084/network-topology-scanner@1338150966"
}

variable "environment_apply" {
  description = "Environment de GitHub (con aprobación) que puede usar el rol de apply"
  type        = string
  default     = "aws"
}
