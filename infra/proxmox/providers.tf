provider "proxmox" {
  # endpoint y api_token salen del entorno (PROXMOX_VE_ENDPOINT y
  # PROXMOX_VE_API_TOKEN): nunca en variables, que acaban en el estado y en el plan
  insecure = var.proxmox_insecure

  # Los snippets de cloud-init no se pueden subir por la API: el provider entra
  # por SSH al nodo. Todo lo demás va por el token de mínimo privilegio.
  ssh {
    username    = "root"
    private_key = file(pathexpand(var.ssh_clave_privada))
  }
}
