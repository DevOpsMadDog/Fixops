# FixOps Backend Deployment Module
# Bank-grade backend deployment with security and monitoring

# ConfigMap for application configuration
resource "kubernetes_config_map" "fixops_config" {
  metadata {
    name      = "fixops-config"
    namespace = var.namespace
    labels    = var.labels
  }
  
  data = merge(var.config, {
    # Performance configuration
    HOT_PATH_TARGET_LATENCY_US = "299"
    
    # Compliance configuration
    EVIDENCE_RETENTION_DAYS = "2555"  # 7 years
    AUDIT_LOG_LEVEL = "detailed"
    PCI_DSS_MODE = "true"
    SOX_COMPLIANCE_MODE = "true"
    
    # Monitoring
    PROMETHEUS_METRICS_ENABLED = "true"
    STRUCTURED_LOGGING = "true"
  })
}

# Secret for sensitive configuration
resource "kubernetes_secret" "fixops_secrets" {
  metadata {
    name      = "fixops-secrets"
    namespace = var.namespace
    labels    = var.labels
  }
  
  type = "Opaque"
  
  data = var.secrets
}

# Deployment
resource "kubernetes_deployment" "fixops_backend" {
  metadata {
    name      = "fixops-backend"
    namespace = var.namespace
    labels    = var.labels
  }
  
  spec {
    replicas = var.replicas
    
    selector {
      match_labels = {
        app = "fixops-backend"
      }
    }
    
    template {
      metadata {
        labels = merge(var.labels, {
          app = "fixops-backend"
        })
        
        annotations = {
          "prometheus.io/scrape" = "true"
          "prometheus.io/port"   = "8001"
          "prometheus.io/path"   = "/metrics"
        }
      }
      
      spec {
        service_account_name = "fixops-backend"
        
        security_context {
          run_as_non_root = true
          run_as_user     = 1000
          run_as_group    = 1000
          fs_group        = 1000
        }
        
        container {
          name  = "fixops-backend"
          image = var.image
          
          port {
            container_port = 8001
            name          = "http"
          }
          
          env_from {
            config_map_ref {
              name = kubernetes_config_map.fixops_config.metadata[0].name
            }
          }
          
          env_from {
            secret_ref {
              name = kubernetes_secret.fixops_secrets.metadata[0].name
            }
          }
          
          resources {
            requests = var.resources.requests
            limits   = var.resources.limits
          }
          
          # Health checks
          liveness_probe {
            http_get {
              path = var.health_checks.liveness.path
              port = var.health_checks.liveness.port
            }
            initial_delay_seconds = 60
            period_seconds        = 30
            timeout_seconds       = 10
            failure_threshold     = 3
          }
          
          readiness_probe {
            http_get {
              path = var.health_checks.readiness.path
              port = var.health_checks.readiness.port
            }
            initial_delay_seconds = 30
            period_seconds        = 10
            timeout_seconds       = 5
            failure_threshold     = 3
          }
          
          volume_mount {
            name       = "data"
            mount_path = "/app/data"
          }
          
          volume_mount {
            name       = "logs"
            mount_path = "/app/logs"
          }
        }
        
        volume {
          name = "data"
          persistent_volume_claim {
            claim_name = "fixops-data"
          }
        }
        
        volume {
          name = "logs"
          empty_dir {}
        }
        
        # Pod anti-affinity for HA
        affinity {
          pod_anti_affinity {
            preferred_during_scheduling_ignored_during_execution {
              weight = 100
              pod_affinity_term {
                label_selector {
                  match_expressions {
                    key      = "app"
                    operator = "In"
                    values   = ["fixops-backend"]
                  }
                }
                topology_key = "kubernetes.io/hostname"
              }
            }
          }
        }
      }
    }
  }
}

# Service
resource "kubernetes_service" "fixops_backend" {
  metadata {
    name      = "fixops-backend-service"
    namespace = var.namespace
    labels    = var.labels
    
    annotations = {
      "prometheus.io/scrape" = "true"
      "prometheus.io/port"   = "8001"
    }
  }
  
  spec {
    selector = {
      app = "fixops-backend"
    }
    
    port {
      name        = "http"
      port        = 8001
      target_port = 8001
      protocol    = "TCP"
    }
    
    type = "ClusterIP"
  }
}

# Variables
variable "namespace" {
  description = "Kubernetes namespace"
  type        = string
}

variable "labels" {
  description = "Common labels"
  type        = map(string)
}

variable "replicas" {
  description = "Number of replicas"
  type        = number
  default     = 3
}

variable "image" {
  description = "Container image"
  type        = string
  default     = "core/decision-engine:latest"
}

variable "config" {
  description = "Configuration variables"
  type        = map(string)
  default     = {}
}

variable "secrets" {
  description = "Secret variables"
  type        = map(string)
  sensitive   = true
  default     = {}
}

variable "resources" {
  description = "Resource limits and requests"
  type = object({
    requests = map(string)
    limits   = map(string)
  })
}

variable "health_checks" {
  description = "Health check configuration"
  type = object({
    liveness = object({
      path = string
      port = number
    })
    readiness = object({
      path = string
      port = number
    })
  })
}

# Outputs
output "service_name" {
  description = "Backend service name"
  value       = kubernetes_service.fixops_backend.metadata[0].name
}

output "deployment_name" {
  description = "Backend deployment name" 
  value       = kubernetes_deployment.fixops_backend.metadata[0].name
}
