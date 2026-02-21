
terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
  }
  
  backend "s3" {
    # terraform init -backend-config="backend.hcl"
    # 
    # region         = "us-east-1"
    # encrypt        = true
    encrypt = true
  }
}

# Variables
variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be development, staging, or production"
  }
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
}

variable "namespace" {
  description = "Kubernetes namespace for FixOps"
  type        = string
  default     = "fixops"
}

variable "terraform_state_bucket" {
  description = "S3 bucket for Terraform state"
  type        = string
}

variable "terraform_lock_table" {
  description = "DynamoDB table for Terraform state locking"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for EKS cluster"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs for EKS cluster"
  type        = list(string)
}

variable "backend_replicas" {
  description = "Number of backend replicas"
  type        = number
  default     = 3
}

variable "storage_size" {
  description = "Evidence Lake storage size"
  type        = string
  default     = "10Gi"
}

variable "emergent_llm_key" {
  description = "Emergent LLM API key"
  type        = string
  sensitive   = true
}

variable "enable_monitoring" {
  description = "Enable Prometheus/Grafana monitoring"
  type        = bool
  default     = true
}

variable "backend_image_tag" {
  description = "Docker image tag for backend (use semantic versioning, not 'latest')"
  type        = string
  default     = "v1.0.0"
}

variable "enable_autoscaling" {
  description = "Enable horizontal pod autoscaling"
  type        = bool
  default     = true
}

variable "enable_backup" {
  description = "Enable automated backups for Evidence Lake PVC using AWS Backup"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Number of days to retain Evidence Lake backups"
  type        = number
  default     = 30
}

variable "enable_network_policies" {
  description = "Enable Kubernetes network policies for pod-to-pod traffic control"
  type        = bool
  default     = true
}

variable "cost_center" {
  description = "Cost center tag for resource cost tracking and allocation"
  type        = string
  default     = ""
}

variable "budget_alert_threshold" {
  description = "Monthly budget threshold in USD for cost alerts (0 to disable)"
  type        = number
  default     = 0
}

variable "tags" {
  description = "AWS resource tags"
  type        = map(string)
  default     = {}
}

# Local values
locals {
  common_tags = merge(
    var.tags,
    {
      "Application"  = "FixOps"
      "Environment"  = var.environment
      "ManagedBy"    = "Terraform"
      "Component"    = "DecisionEngine"
    }
  )
  
  labels = {
    "app.kubernetes.io/name"       = "fixops"
    "app.kubernetes.io/instance"   = "fixops-${var.environment}"
    "app.kubernetes.io/version"    = "1.0.0"
    "app.kubernetes.io/component"  = "decision-engine"
    "app.kubernetes.io/part-of"    = "security-platform"
    "app.kubernetes.io/managed-by" = "terraform"
    "environment"                  = var.environment
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = local.common_tags
  }
}

data "aws_eks_cluster" "cluster" {
  name = var.cluster_name
}

data "aws_eks_cluster_auth" "cluster" {
  name = var.cluster_name
}

data "aws_iam_openid_connect_provider" "eks" {
  url = data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer
}

# Kubernetes provider
provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.cluster.token
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.cluster.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.cluster.token
  }
}

resource "aws_iam_role" "ebs_csi_driver" {
  name = "fixops-${var.environment}-ebs-csi-driver"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRoleWithWebIdentity"
      Effect = "Allow"
      Principal = {
        Federated = data.aws_iam_openid_connect_provider.eks.arn
      }
      Condition = {
        StringEquals = {
          "${replace(data.aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:kube-system:ebs-csi-controller-sa"
          "${replace(data.aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ebs_csi_driver" {
  role       = aws_iam_role.ebs_csi_driver.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

resource "kubernetes_namespace" "fixops" {
  metadata {
    name = var.namespace
    labels = local.labels
  }
}

resource "kubernetes_network_policy" "fixops_backend" {
  count = var.enable_network_policies ? 1 : 0
  
  metadata {
    name      = "fixops-backend-netpol"
    namespace = kubernetes_namespace.fixops.metadata[0].name
  }
  
  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/name"      = "fixops"
        "app.kubernetes.io/component" = "backend"
      }
    }
    
    policy_types = ["Ingress", "Egress"]
    
    ingress {
      from {
        pod_selector {
          match_labels = {
            "app.kubernetes.io/name" = "fixops"
          }
        }
      }
      
      ports {
        protocol = "TCP"
        port     = "8001"
      }
    }
    
    egress {
      to {
        pod_selector {}
      }
      
      to {
        namespace_selector {}
      }
      
      ports {
        protocol = "TCP"
        port     = "443"
      }
      
      ports {
        protocol = "TCP"
        port     = "27017"
      }
      
      ports {
        protocol = "TCP"
        port     = "6379"
      }
    }
  }
}

resource "kubernetes_storage_class" "ebs_gp3" {
  metadata {
    name = "fixops-ebs-gp3"
  }
  
  storage_provisioner = "ebs.csi.aws.com"
  reclaim_policy      = "Retain"
  volume_binding_mode = "WaitForFirstConsumer"
  
  parameters = {
    type      = "gp3"
    encrypted = "true"
    fsType    = "ext4"
  }
}

resource "kubernetes_persistent_volume_claim" "evidence_lake" {
  metadata {
    name      = "fixops-evidence-lake"
    namespace = kubernetes_namespace.fixops.metadata[0].name
    labels    = merge(local.labels, {
      "backup.kubernetes.io/enabled" = var.enable_backup ? "true" : "false"
    })
  }
  
  spec {
    access_modes       = ["ReadWriteOnce"]
    storage_class_name = kubernetes_storage_class.ebs_gp3.metadata[0].name
    
    resources {
      requests = {
        storage = var.storage_size
      }
    }
  }
}

resource "aws_backup_vault" "fixops" {
  count = var.enable_backup ? 1 : 0
  name  = "fixops-${var.environment}-backup-vault"
  
  tags = merge(local.tags, {
    Name = "fixops-${var.environment}-backup-vault"
  })
}

resource "aws_backup_plan" "fixops" {
  count = var.enable_backup ? 1 : 0
  name  = "fixops-${var.environment}-backup-plan"
  
  rule {
    rule_name         = "daily_backup"
    target_vault_name = aws_backup_vault.fixops[0].name
    schedule          = "cron(0 2 * * ? *)"
    
    lifecycle {
      delete_after = var.backup_retention_days
    }
  }
  
  tags = merge(local.tags, {
    Name = "fixops-${var.environment}-backup-plan"
  })
}

resource "kubernetes_config_map" "fixops" {
  metadata {
    name      = "fixops-config"
    namespace = kubernetes_namespace.fixops.metadata[0].name
    labels    = local.labels
  }
  
  data = {
    FIXOPS_ENVIRONMENT = var.environment
    FIXOPS_DEMO_MODE   = "false"
    AWS_REGION         = var.aws_region
    MONGO_URL          = "mongodb://mongodb.${var.namespace}:27017/fixops_${var.environment}"
    REDIS_URL          = "redis://redis.${var.namespace}:6379/0"
  }
}

resource "kubernetes_secret" "fixops" {
  metadata {
    name      = "fixops-secrets"
    namespace = kubernetes_namespace.fixops.metadata[0].name
    labels    = local.labels
  }
  
  data = {
    EMERGENT_LLM_KEY = base64encode(var.emergent_llm_key)
  }
  
  type = "Opaque"
}

resource "kubernetes_deployment" "backend" {
  metadata {
    name      = "fixops-backend"
    namespace = kubernetes_namespace.fixops.metadata[0].name
    labels    = local.labels
  }
  
  spec {
    replicas = var.backend_replicas
    
    selector {
      match_labels = {
        "app.kubernetes.io/name"      = "fixops"
        "app.kubernetes.io/component" = "backend"
      }
    }
    
    template {
      metadata {
        labels = merge(local.labels, {
          "app.kubernetes.io/component" = "backend"
        })
      }
      
      spec {
        container {
          name  = "fixops-backend"
          image = "fixops/backend:${var.backend_image_tag}"
          
          port {
            container_port = 8001
            name           = "http"
          }
          
          env_from {
            config_map_ref {
              name = kubernetes_config_map.fixops.metadata[0].name
            }
          }
          
          env_from {
            secret_ref {
              name = kubernetes_secret.fixops.metadata[0].name
            }
          }
          
          resources {
            requests = {
              memory = "512Mi"
              cpu    = "250m"
            }
            limits = {
              memory = "2Gi"
              cpu    = "1000m"
            }
          }
          
          liveness_probe {
            http_get {
              path = "/health"
              port = 8001
            }
            initial_delay_seconds = 30
            period_seconds        = 10
          }
          
          readiness_probe {
            http_get {
              path = "/ready"
              port = 8001
            }
            initial_delay_seconds = 10
            period_seconds        = 5
          }
          
          volume_mount {
            name       = "evidence-storage"
            mount_path = "/app/data/evidence"
          }
        }
        
        volume {
          name = "evidence-storage"
          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim.evidence_lake.metadata[0].name
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "backend" {
  metadata {
    name      = "fixops-backend-service"
    namespace = kubernetes_namespace.fixops.metadata[0].name
    labels    = local.labels
  }
  
  spec {
    selector = {
      "app.kubernetes.io/name"      = "fixops"
      "app.kubernetes.io/component" = "backend"
    }
    
    port {
      port        = 8001
      target_port = 8001
      protocol    = "TCP"
      name        = "http"
    }
    
    type = "ClusterIP"
  }
}

resource "kubernetes_horizontal_pod_autoscaler_v2" "backend" {
  count = var.enable_autoscaling ? 1 : 0
  
  metadata {
    name      = "fixops-backend-hpa"
    namespace = kubernetes_namespace.fixops.metadata[0].name
  }
  
  spec {
    scale_target_ref {
      api_version = "apps/v1"
      kind        = "Deployment"
      name        = kubernetes_deployment.backend.metadata[0].name
    }
    
    min_replicas = var.backend_replicas
    max_replicas = var.backend_replicas * 3
    
    metric {
      type = "Resource"
      resource {
        name = "cpu"
        target {
          type                = "Utilization"
          average_utilization = 70
        }
      }
    }
    
    metric {
      type = "Resource"
      resource {
        name = "memory"
        target {
          type                = "Utilization"
          average_utilization = 80
        }
      }
    }
  }
}

resource "kubernetes_ingress_v1" "fixops" {
  metadata {
    name      = "fixops-ingress"
    namespace = kubernetes_namespace.fixops.metadata[0].name
    labels    = local.labels
    
    annotations = {
      "kubernetes.io/ingress.class"                    = "alb"
      "alb.ingress.kubernetes.io/scheme"               = "internet-facing"
      "alb.ingress.kubernetes.io/target-type"          = "ip"
      "alb.ingress.kubernetes.io/healthcheck-path"     = "/health"
      "alb.ingress.kubernetes.io/listen-ports"         = "[{\"HTTPS\":443}]"
      "alb.ingress.kubernetes.io/ssl-redirect"         = "443"
      "alb.ingress.kubernetes.io/certificate-arn"      = aws_acm_certificate.fixops.arn
    }
  }
  
  spec {
    rule {
      host = "fixops-${var.environment}.${var.domain_name}"
      
      http {
        path {
          path      = "/"
          path_type = "Prefix"
          
          backend {
            service {
              name = kubernetes_service.backend.metadata[0].name
              port {
                number = 8001
              }
            }
          }
        }
      }
    }
  }
}

variable "domain_name" {
  description = "Domain name for FixOps"
  type        = string
}

resource "aws_acm_certificate" "fixops" {
  domain_name       = "fixops-${var.environment}.${var.domain_name}"
  validation_method = "DNS"
  
  lifecycle {
    create_before_destroy = true
  }
}

output "fixops_api_url" {
  description = "FixOps API endpoint"
  value       = "https://fixops-${var.environment}.${var.domain_name}"
}

output "namespace" {
  description = "Kubernetes namespace"
  value       = kubernetes_namespace.fixops.metadata[0].name
}

output "backend_service" {
  description = "Backend service name"
  value       = kubernetes_service.backend.metadata[0].name
}

resource "aws_budgets_budget" "fixops" {
  count = var.budget_alert_threshold > 0 ? 1 : 0
  
  name              = "fixops-${var.environment}-monthly-budget"
  budget_type       = "COST"
  limit_amount      = tostring(var.budget_alert_threshold)
  limit_unit        = "USD"
  time_period_start = "2025-01-01_00:00"
  time_unit         = "MONTHLY"
  
  cost_filter {
    name = "TagKeyValue"
    values = [
      "Environment$${var.environment}",
      "Application$fixops"
    ]
  }
  
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = []
  }
  
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = []
  }
}
