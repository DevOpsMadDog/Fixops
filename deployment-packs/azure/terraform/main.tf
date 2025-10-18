
terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
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
  
  backend "azurerm" {
    resource_group_name  = var.terraform_resource_group
    storage_account_name = var.terraform_storage_account
    container_name       = "tfstate"
    key                  = "fixops/${var.environment}/terraform.tfstate"
  }
}

# Variables
variable "environment" {
  description = "Deployment environment"
  type        = string
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be development, staging, or production"
  }
}

variable "location" {
  description = "Azure region for deployment"
  type        = string
  default     = "eastus"
}

variable "resource_group_name" {
  description = "Azure resource group name"
  type        = string
}

variable "cluster_name" {
  description = "AKS cluster name"
  type        = string
}

variable "namespace" {
  description = "Kubernetes namespace for FixOps"
  type        = string
  default     = "fixops"
}

variable "terraform_resource_group" {
  description = "Resource group for Terraform state"
  type        = string
}

variable "terraform_storage_account" {
  description = "Storage account for Terraform state"
  type        = string
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
  description = "Enable Azure Monitor integration"
  type        = bool
  default     = true
}

variable "enable_autoscaling" {
  description = "Enable horizontal pod autoscaling"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Azure resource tags"
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

provider "azurerm" {
  features {}
}

data "azurerm_kubernetes_cluster" "cluster" {
  name                = var.cluster_name
  resource_group_name = var.resource_group_name
}

# Kubernetes provider
provider "kubernetes" {
  host                   = data.azurerm_kubernetes_cluster.cluster.kube_config.0.host
  client_certificate     = base64decode(data.azurerm_kubernetes_cluster.cluster.kube_config.0.client_certificate)
  client_key             = base64decode(data.azurerm_kubernetes_cluster.cluster.kube_config.0.client_key)
  cluster_ca_certificate = base64decode(data.azurerm_kubernetes_cluster.cluster.kube_config.0.cluster_ca_certificate)
}

provider "helm" {
  kubernetes {
    host                   = data.azurerm_kubernetes_cluster.cluster.kube_config.0.host
    client_certificate     = base64decode(data.azurerm_kubernetes_cluster.cluster.kube_config.0.client_certificate)
    client_key             = base64decode(data.azurerm_kubernetes_cluster.cluster.kube_config.0.client_key)
    cluster_ca_certificate = base64decode(data.azurerm_kubernetes_cluster.cluster.kube_config.0.cluster_ca_certificate)
  }
}

resource "kubernetes_namespace" "fixops" {
  metadata {
    name = var.namespace
    labels = local.labels
  }
}

resource "kubernetes_storage_class" "azure_disk" {
  metadata {
    name = "fixops-azure-disk"
  }
  
  storage_provisioner = "disk.csi.azure.com"
  reclaim_policy      = "Retain"
  volume_binding_mode = "WaitForFirstConsumer"
  
  parameters = {
    skuName = "Premium_LRS"
    kind    = "Managed"
  }
}

resource "kubernetes_persistent_volume_claim" "evidence_lake" {
  metadata {
    name      = "fixops-evidence-lake"
    namespace = kubernetes_namespace.fixops.metadata[0].name
    labels    = local.labels
  }
  
  spec {
    access_modes       = ["ReadWriteOnce"]
    storage_class_name = kubernetes_storage_class.azure_disk.metadata[0].name
    
    resources {
      requests = {
        storage = var.storage_size
      }
    }
  }
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
    AZURE_LOCATION     = var.location
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
          image = "fixops/backend:latest"
          
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
      "kubernetes.io/ingress.class"                = "azure/application-gateway"
      "appgw.ingress.kubernetes.io/ssl-redirect"   = "true"
      "appgw.ingress.kubernetes.io/backend-path-prefix" = "/"
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
    
    tls {
      hosts = ["fixops-${var.environment}.${var.domain_name}"]
      secret_name = "fixops-tls-cert"
    }
  }
}

variable "domain_name" {
  description = "Domain name for FixOps"
  type        = string
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

output "resource_group" {
  description = "Azure resource group"
  value       = var.resource_group_name
}
