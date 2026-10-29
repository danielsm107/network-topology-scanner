# Tests del plan de la VM con el provider simulado: no hablan con Proxmox ni
# necesitan token, así que corren igual en el PC que en la CI.

mock_provider "proxmox" {}

variables {
  ip_cidr     = "192.0.2.50/24"
  gateway     = "192.0.2.1"
  k3s_version = "v1.99.0+k3s1"
  # Clave pública inventada: en la CI no existe ~/.ssh/homelab_ed25519.pub.
  # La privada no hace falta: con mock_provider no se configura el provider.
  ssh_clave_publica = "tests/clave_prueba.pub"
}

# k3s fijado a una versión exacta y con la IP en el certificado: sin --tls-san,
# kubectl desde el PC falla con un error x509 al usar la IP en vez de 127.0.0.1
run "cloud_init_contiene_k3s_fijado" {
  command = plan

  assert {
    condition     = strcontains(local.cloud_init, "INSTALL_K3S_VERSION=v1.99.0+k3s1")
    error_message = "El cloud-init no instala la versión de k3s de la variable."
  }

  assert {
    condition     = strcontains(local.cloud_init, "--tls-san 192.0.2.50")
    error_message = "El cloud-init no añade la IP (sin máscara) al certificado de k3s."
  }

  assert {
    condition     = strcontains(local.cloud_init, "- ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClaveFalsaSoloParaLosTestsDeTerraform00000 tests@example")
    error_message = "El cloud-init no autoriza la clave pública para el usuario ubuntu."
  }
}

# Red propia en vez del ipconfig0 de Proxmox: ese llama "eth0" a la interfaz y
# la renombra, y en Ubuntu 26.04 el renombrado falla (dracut ya la levantó por
# DHCP), así que la VM se quedaba con una IP del pool en vez de la fija
run "red_fija_sin_renombrar_la_interfaz" {
  command = plan

  assert {
    condition     = strcontains(local.network_config, "name: \"en*\"")
    error_message = "El network-config no busca la interfaz por su nombre real (en*)."
  }

  assert {
    condition     = !strcontains(local.network_config, "set-name:")
    error_message = "El network-config renombra la interfaz: falla con dracut y la VM coge DHCP."
  }

  assert {
    condition = alltrue([
      strcontains(local.network_config, "- 192.0.2.50/24"),
      strcontains(local.network_config, "via: 192.0.2.1"),
      strcontains(local.network_config, "addresses: [192.0.2.1]"),
    ])
    error_message = "El network-config no tiene la IP, el gateway o el DNS de las variables."
  }

  assert {
    condition     = length(proxmox_virtual_environment_vm.k3s.initialization[0].ip_config) == 0
    error_message = "La VM sigue usando ip_config (ipconfig0 de Proxmox) además del network-config propio."
  }
}

run "vm_con_los_recursos_del_diseno" {
  command = plan

  assert {
    condition     = proxmox_virtual_environment_vm.k3s.memory[0].dedicated == 8192
    error_message = "La VM no tiene 8 GiB de RAM."
  }

  assert {
    condition     = proxmox_virtual_environment_vm.k3s.cpu[0].cores == 4
    error_message = "La VM no tiene 4 vCPU."
  }

  assert {
    condition     = proxmox_virtual_environment_vm.k3s.disk[0].size == 40
    error_message = "El disco no es de 40 GB."
  }

  assert {
    condition     = proxmox_virtual_environment_vm.k3s.network_device[0].bridge == "vmbr0"
    error_message = "La VM no está en el bridge vmbr0."
  }

  assert {
    condition     = proxmox_virtual_environment_vm.k3s.vm_id == 210
    error_message = "El VMID no es 210."
  }

  assert {
    condition     = proxmox_virtual_environment_vm.k3s.on_boot == true
    error_message = "La VM no arranca con el host."
  }
}

# Una IP sin máscara daría una VM inalcanzable: tiene que fallar en el plan
run "ip_sin_mascara_falla" {
  command = plan

  variables {
    ip_cidr = "192.0.2.50"
  }

  expect_failures = [var.ip_cidr]
}

run "gateway_fuera_de_la_red_falla" {
  command = plan

  variables {
    gateway = "198.51.100.1"
  }

  expect_failures = [var.gateway]
}
