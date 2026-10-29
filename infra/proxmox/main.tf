locals {
  ip  = split("/", var.ip_cidr)[0]
  dns = length(var.dns) > 0 ? var.dns : [var.gateway]

  cloud_init = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    clave_publica = trimspace(file(pathexpand(var.ssh_clave_publica)))
    k3s_version   = var.k3s_version
    ip            = local.ip
  })

  network_config = templatefile("${path.module}/network-config.yaml.tftpl", {
    ip_cidr = var.ip_cidr
    gateway = var.gateway
    dns     = local.dns
  })
}

# Imagen cloud de Ubuntu 26.04 LTS. Release con fecha (no release/, que cambia)
# y checksum: la misma URL siempre da la misma imagen.
resource "proxmox_download_file" "ubuntu" {
  node_name    = var.nodo
  datastore_id = "local"
  content_type = "import"
  url          = "https://cloud-images.ubuntu.com/releases/resolute/release-20261016/ubuntu-26.04-server-cloudimg-amd64.img"
  # Proxmox solo importa .qcow2/.raw/.vmdk; la .img de Ubuntu ya es qcow2
  file_name          = "ubuntu-26.04-server-cloudimg-amd64-20261016.qcow2"
  checksum           = "5645d0318ad21f643ebb1ac4567514620e9893380b07b0201fda163baa5b7eb5"
  checksum_algorithm = "sha256"
}

resource "proxmox_virtual_environment_file" "cloud_init" {
  node_name    = var.nodo
  datastore_id = "local"
  content_type = "snippets"

  source_raw {
    data      = local.cloud_init
    file_name = "k3s-cloud-init.yaml"
  }
}

resource "proxmox_virtual_environment_file" "network_config" {
  node_name    = var.nodo
  datastore_id = "local"
  content_type = "snippets"

  source_raw {
    data      = local.network_config
    file_name = "k3s-network-config.yaml"
  }
}

resource "proxmox_virtual_environment_vm" "k3s" {
  node_name = var.nodo
  vm_id     = 210
  name      = "k3s"
  on_boot   = true

  agent {
    enabled = true
  }

  cpu {
    cores = 4
    type  = "host"
  }

  memory {
    dedicated = var.memoria_mib
  }

  scsi_hardware = "virtio-scsi-single"

  disk {
    datastore_id = "local-lvm"
    import_from  = proxmox_download_file.ubuntu.id
    interface    = "scsi0"
    size         = 40
    discard      = "on"
    iothread     = true
    ssd          = true
  }

  network_device {
    bridge = "vmbr0"
  }

  operating_system {
    type = "l26"
  }

  # Las imágenes cloud de Ubuntu esperan una consola serie
  serial_device {}

  initialization {
    datastore_id = "local-lvm"

    # Red por network-config propio, no con ip_config/dns (ver la plantilla)
    user_data_file_id    = proxmox_virtual_environment_file.cloud_init.id
    network_data_file_id = proxmox_virtual_environment_file.network_config.id
  }
}
