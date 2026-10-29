output "bucket_estado" {
  description = "Bucket del estado de Terraform: va en el backend.hcl de cada raíz"
  value       = aws_s3_bucket.estado.id
}
