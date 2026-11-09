# Van al values.local.yaml del chart (bucket, topic) y a las variables del repo
# en GitHub (roles). Ninguno es secreto, pero llevan el ID de la cuenta: no al repo.

output "bucket_informes" {
  description = "Bucket de informes y copia del historial (aws.bucket en el chart)"
  value       = aws_s3_bucket.informes.id
}

output "topic_arn" {
  description = "Topic de los avisos (aws.topicArn en el chart)"
  value       = aws_sns_topic.hallazgos.arn
}

output "usuario_homelab" {
  description = "Usuario IAM del CronJob: su clave se crea a mano (runbook 04)"
  value       = aws_iam_user.homelab.name
}

output "usuario_jenkins" {
  description = "Usuario IAM de los avisos de Jenkins: su clave se crea a mano (runbook 05)"
  value       = aws_iam_user.jenkins.name
}

output "rol_plan_arn" {
  description = "Variable AWS_ROLE_PLAN_ARN del repo en GitHub"
  value       = aws_iam_role.github_plan.arn
}

output "rol_apply_arn" {
  description = "Variable AWS_ROLE_APPLY_ARN del repo en GitHub"
  value       = aws_iam_role.github_apply.arn
}
