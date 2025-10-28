output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.main.name
}

output "ecs_service_name" {
  description = "Name of the ECS service"
  value       = aws_ecs_service.collector.name
}

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.main.dns_name
}

output "alb_url" {
  description = "URL of the collector API"
  value       = "http://${aws_lb.main.dns_name}"
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket for evidence storage"
  value       = aws_s3_bucket.evidence.id
}

output "ecr_collector_api_url" {
  description = "URL of the collector API ECR repository"
  value       = aws_ecr_repository.collector_api.repository_url
}

output "ecr_fluent_bit_url" {
  description = "URL of the Fluent Bit ECR repository"
  value       = aws_ecr_repository.fluent_bit.repository_url
}

output "cloudwatch_log_group" {
  description = "Name of the CloudWatch log group"
  value       = aws_cloudwatch_log_group.collector.name
}
