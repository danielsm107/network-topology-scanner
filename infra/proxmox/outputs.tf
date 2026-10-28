output "ip" {
  description = "IP de la VM, sin máscara."
  value       = local.ip
}

output "ssh" {
  description = "Comando para entrar a la VM."
  value       = "ssh -i ${var.ssh_clave_privada} ubuntu@${local.ip}"
}

output "kubeconfig" {
  description = "Comando (Git Bash) que trae el kubeconfig con la IP de la VM en lugar de 127.0.0.1."
  value       = "ssh -i ${var.ssh_clave_privada} ubuntu@${local.ip} sudo cat /etc/rancher/k3s/k3s.yaml | sed 's/127.0.0.1/${local.ip}/' > kubeconfig"
}
