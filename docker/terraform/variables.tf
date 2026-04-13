# =============================================================================
# ALDECI — Terraform Variables
# AWS ECS Fargate deployment: API + UI + ALB + Route53 + ACM + RDS + S3
# =============================================================================

# ---------------------------------------------------------------------------
# Core / Region
# ---------------------------------------------------------------------------

variable "aws_region" {
  description = "AWS region to deploy ALDECI into."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment name (e.g. production, staging, dev)."
  type        = string
  default     = "production"

  validation {
    condition     = contains(["production", "staging", "dev"], var.environment)
    error_message = "environment must be one of: production, staging, dev."
  }
}

variable "project_name" {
  description = "Short project identifier used as a prefix for all resource names."
  type        = string
  default     = "aldeci"
}

# ---------------------------------------------------------------------------
# Networking / Domain
# ---------------------------------------------------------------------------

variable "domain_name" {
  description = "Root domain name (e.g. aldeci.example.com). Must be managed in Route53."
  type        = string
}

variable "api_subdomain" {
  description = "Subdomain for the ALDECI API (prepended to domain_name)."
  type        = string
  default     = "api"
}

variable "ui_subdomain" {
  description = "Subdomain for the ALDECI UI (prepended to domain_name)."
  type        = string
  default     = "app"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets (one per AZ, minimum 2)."
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets (one per AZ, minimum 2)."
  type        = list(string)
  default     = ["10.0.11.0/24", "10.0.12.0/24"]
}

variable "availability_zones" {
  description = "List of availability zones to use (must match subnet count)."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

# ---------------------------------------------------------------------------
# ECS — API Service
# ---------------------------------------------------------------------------

variable "api_image" {
  description = "Docker image for the ALDECI API (ECR URI or public registry)."
  type        = string
  default     = "devopsmaddog/aldeci-api:latest"
}

variable "api_cpu" {
  description = "vCPU units for the API Fargate task (256 = 0.25 vCPU)."
  type        = number
  default     = 512

  validation {
    condition     = contains([256, 512, 1024, 2048, 4096], var.api_cpu)
    error_message = "api_cpu must be a valid Fargate CPU value: 256, 512, 1024, 2048, or 4096."
  }
}

variable "api_memory" {
  description = "Memory (MiB) for the API Fargate task."
  type        = number
  default     = 1024
}

variable "api_port" {
  description = "Container port the API FastAPI service listens on."
  type        = number
  default     = 8000
}

variable "api_desired_count" {
  description = "Desired number of API ECS task replicas."
  type        = number
  default     = 2
}

variable "api_min_count" {
  description = "Minimum number of API tasks for auto-scaling."
  type        = number
  default     = 1
}

variable "api_max_count" {
  description = "Maximum number of API tasks for auto-scaling."
  type        = number
  default     = 10
}

# ---------------------------------------------------------------------------
# ECS — UI Service
# ---------------------------------------------------------------------------

variable "ui_image" {
  description = "Docker image for the ALDECI UI (ECR URI or public registry)."
  type        = string
  default     = "devopsmaddog/aldeci-ui:latest"
}

variable "ui_cpu" {
  description = "vCPU units for the UI Fargate task."
  type        = number
  default     = 256

  validation {
    condition     = contains([256, 512, 1024, 2048, 4096], var.ui_cpu)
    error_message = "ui_cpu must be a valid Fargate CPU value: 256, 512, 1024, 2048, or 4096."
  }
}

variable "ui_memory" {
  description = "Memory (MiB) for the UI Fargate task."
  type        = number
  default     = 512
}

variable "ui_port" {
  description = "Container port the UI Nginx/Node service listens on."
  type        = number
  default     = 80
}

variable "ui_desired_count" {
  description = "Desired number of UI ECS task replicas."
  type        = number
  default     = 2
}

variable "ui_min_count" {
  description = "Minimum number of UI tasks for auto-scaling."
  type        = number
  default     = 1
}

variable "ui_max_count" {
  description = "Maximum number of UI tasks for auto-scaling."
  type        = number
  default     = 5
}

# ---------------------------------------------------------------------------
# RDS PostgreSQL (optional — future migration from SQLite)
# ---------------------------------------------------------------------------

variable "enable_rds" {
  description = "Whether to provision an RDS PostgreSQL instance."
  type        = bool
  default     = false
}

variable "rds_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t3.micro"
}

variable "rds_allocated_storage" {
  description = "Allocated storage in GiB for RDS."
  type        = number
  default     = 20
}

variable "rds_engine_version" {
  description = "PostgreSQL engine version."
  type        = string
  default     = "15.4"
}

variable "rds_db_name" {
  description = "Name of the initial database created on RDS."
  type        = string
  default     = "aldeci"
}

variable "rds_username" {
  description = "Master username for RDS. Stored in SSM Parameter Store."
  type        = string
  default     = "aldeci_admin"
  sensitive   = true
}

variable "rds_password" {
  description = "Master password for RDS. Stored in SSM Parameter Store — do not commit."
  type        = string
  sensitive   = true
  default     = ""
}

variable "rds_multi_az" {
  description = "Enable Multi-AZ for RDS (recommended for production)."
  type        = bool
  default     = false
}

variable "rds_deletion_protection" {
  description = "Enable deletion protection on RDS instance."
  type        = bool
  default     = true
}

variable "rds_backup_retention_days" {
  description = "Number of days to retain automated RDS backups."
  type        = number
  default     = 7
}

# ---------------------------------------------------------------------------
# S3 — Backups
# ---------------------------------------------------------------------------

variable "backup_bucket_name" {
  description = "S3 bucket name for ALDECI backups. Must be globally unique."
  type        = string
  default     = ""
}

variable "backup_retention_days" {
  description = "Number of days before backup objects are moved to Glacier."
  type        = number
  default     = 30
}

variable "enable_backup_replication" {
  description = "Enable cross-region S3 replication for disaster recovery."
  type        = bool
  default     = false
}

variable "backup_replication_region" {
  description = "Destination region for S3 replication (if enabled)."
  type        = string
  default     = "us-west-2"
}

# ---------------------------------------------------------------------------
# Secrets / Application Config
# ---------------------------------------------------------------------------

variable "api_key_secret_arn" {
  description = "ARN of the AWS Secrets Manager secret containing ALDECI API keys."
  type        = string
  default     = ""
  sensitive   = true
}

variable "openrouter_api_key_ssm_path" {
  description = "SSM Parameter Store path for the OpenRouter API key."
  type        = string
  default     = "/aldeci/production/openrouter_api_key"
}

variable "fixops_use_council" {
  description = "Set to '1' to enable LLM Council mode (FIXOPS_USE_COUNCIL env var)."
  type        = string
  default     = "0"
}

# ---------------------------------------------------------------------------
# Logging / Observability
# ---------------------------------------------------------------------------

variable "log_retention_days" {
  description = "Number of days to retain CloudWatch log streams."
  type        = number
  default     = 30
}

variable "enable_container_insights" {
  description = "Enable CloudWatch Container Insights for the ECS cluster."
  type        = bool
  default     = true
}

# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------

variable "tags" {
  description = "Additional tags to apply to all resources."
  type        = map(string)
  default     = {}
}
