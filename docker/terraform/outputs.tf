# =============================================================================
# ALDECI — Terraform Outputs
# =============================================================================

# ---------------------------------------------------------------------------
# URLs
# ---------------------------------------------------------------------------

output "api_url" {
  description = "HTTPS URL for the ALDECI API (via Route53 + ACM)."
  value       = "https://${var.api_subdomain}.${var.domain_name}"
}

output "ui_url" {
  description = "HTTPS URL for the ALDECI UI (via Route53 + ACM)."
  value       = "https://${var.ui_subdomain}.${var.domain_name}"
}

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer (use for CNAME before Route53 is live)."
  value       = aws_lb.aldeci.dns_name
}

output "alb_zone_id" {
  description = "Hosted zone ID of the ALB (needed for Route53 alias records)."
  value       = aws_lb.aldeci.zone_id
}

output "alb_arn" {
  description = "ARN of the Application Load Balancer."
  value       = aws_lb.aldeci.arn
}

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

output "vpc_id" {
  description = "ID of the VPC created for ALDECI."
  value       = aws_vpc.aldeci.id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets (ALB lives here)."
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets (ECS tasks + RDS live here)."
  value       = aws_subnet.private[*].id
}

# ---------------------------------------------------------------------------
# ECS
# ---------------------------------------------------------------------------

output "ecs_cluster_name" {
  description = "Name of the ECS cluster."
  value       = aws_ecs_cluster.aldeci.name
}

output "ecs_cluster_arn" {
  description = "ARN of the ECS cluster."
  value       = aws_ecs_cluster.aldeci.arn
}

output "api_service_name" {
  description = "Name of the ECS service running the API."
  value       = aws_ecs_service.api.name
}

output "ui_service_name" {
  description = "Name of the ECS service running the UI."
  value       = aws_ecs_service.ui.name
}

output "api_task_definition_arn" {
  description = "ARN of the latest API task definition revision."
  value       = aws_ecs_task_definition.api.arn
}

output "ui_task_definition_arn" {
  description = "ARN of the latest UI task definition revision."
  value       = aws_ecs_task_definition.ui.arn
}

# ---------------------------------------------------------------------------
# ACM
# ---------------------------------------------------------------------------

output "acm_certificate_arn" {
  description = "ARN of the ACM certificate covering the domain and subdomains."
  value       = aws_acm_certificate.aldeci.arn
}

# ---------------------------------------------------------------------------
# RDS (conditional)
# ---------------------------------------------------------------------------

output "rds_endpoint" {
  description = "RDS PostgreSQL endpoint (empty string if RDS is disabled)."
  value       = var.enable_rds ? aws_db_instance.aldeci[0].endpoint : ""
}

output "rds_port" {
  description = "RDS PostgreSQL port."
  value       = var.enable_rds ? aws_db_instance.aldeci[0].port : null
}

output "rds_db_name" {
  description = "Name of the database on RDS."
  value       = var.enable_rds ? aws_db_instance.aldeci[0].db_name : ""
}

# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------

output "backup_bucket_name" {
  description = "Name of the S3 bucket used for ALDECI backups."
  value       = aws_s3_bucket.backups.bucket
}

output "backup_bucket_arn" {
  description = "ARN of the S3 backup bucket."
  value       = aws_s3_bucket.backups.arn
}

# ---------------------------------------------------------------------------
# IAM
# ---------------------------------------------------------------------------

output "ecs_task_execution_role_arn" {
  description = "ARN of the ECS task execution IAM role."
  value       = aws_iam_role.ecs_task_execution.arn
}

output "ecs_task_role_arn" {
  description = "ARN of the ECS task IAM role (runtime permissions)."
  value       = aws_iam_role.ecs_task.arn
}

# ---------------------------------------------------------------------------
# CloudWatch
# ---------------------------------------------------------------------------

output "api_log_group_name" {
  description = "CloudWatch log group for API container logs."
  value       = aws_cloudwatch_log_group.api.name
}

output "ui_log_group_name" {
  description = "CloudWatch log group for UI container logs."
  value       = aws_cloudwatch_log_group.ui.name
}
