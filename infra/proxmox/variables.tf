variable "nodo" {
  description = "Nodo de Proxmox donde se crea la VM."
  type        = string
  default     = "pve"
}

variable "ip_cidr" {
  description = "IP fija de la VM con su máscara, p. ej. 192.0.2.50/24 (fuera del pool DHCP)."
  type        = string

  validation {
    # cidrhost() ya falla sin máscara, pero el strcontains deja el motivo claro
    condition     = strcontains(var.ip_cidr, "/") && can(cidrhost(var.ip_cidr, 0))
    error_message = "ip_cidr tiene que ser una IP con máscara, p. ej. 192.0.2.50/24."
  }
}

variable "gateway" {
  description = "Puerta de enlace de la VM; tiene que estar en la misma red que ip_cidr."
  type        = string

  validation {
    # Si ip_cidr está mal ya falla su propia validación: aquí no se repite el error
    condition = !can(cidrhost(var.ip_cidr, 0)) || try(
      cidrsubnet("${var.gateway}/${split("/", var.ip_cidr)[1]}", 0, 0) == cidrsubnet(var.ip_cidr, 0, 0),
      false
    )
    error_message = "gateway tiene que ser una IP de la misma red que ip_cidr."
  }
}

variable "dns" {
  description = "Servidores DNS de la VM. Vacío = usar el gateway."
  type        = list(string)
  default     = []
}

variable "k3s_version" {
  description = "Versión exacta de k3s (canal stable), p. ej. v1.34.1+k3s1."
  type        = string
}

variable "memoria_mib" {
  description = "RAM de la VM en MiB. Bajar a 6144 si vuelve a estar encendida la VM 202."
  type        = number
  default     = 8192
}

variable "ssh_clave_publica" {
  description = "Clave pública que se autoriza para el usuario ubuntu de la VM."
  type        = string
  default     = "~/.ssh/homelab_ed25519.pub"
}

variable "ssh_clave_privada" {
  description = "Clave privada para entrar por SSH como root al nodo (solo para subir el snippet de cloud-init)."
  type        = string
  default     = "~/.ssh/homelab_ed25519"
}

variable "proxmox_insecure" {
  description = "Aceptar el certificado autofirmado de la API de Proxmox."
  type        = bool
  default     = true
}
