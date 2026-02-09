# FixOps MongoDB Module
# Bank-grade MongoDB deployment for Evidence Lake

# MongoDB StatefulSet
resource "kubernetes_stateful_set" "mongodb" {
  metadata {
    name      = "mongodb"
    namespace = var.namespace
    labels    = var.labels
  }
  
  spec {
    service_name = "mongodb"
    replicas     = var.replicas
    
    selector {
      match_labels = {
        app = "mongodb"
      }
    }
    
    template {
      metadata {
        labels = merge(var.labels, {
          app = "mongodb"
        })
      }
      
      spec {
        security_context {
          run_as_non_root = true
          run_as_user     = 999
          run_as_group    = 999
          fs_group        = 999
        }
        
        container {
          name  = "mongodb"
          image = "mongo:7.0"
          
          port {
            container_port = 27017
            name          = "mongodb"
          }
          
          env {
            name = "MONGO_INITDB_ROOT_PASSWORD"
            value_from {
              secret_key_ref {
                name = "fixops-secrets"
                key  = "mongodb_password"
              }
            }
          }
          
          env {
            name  = "MONGO_INITDB_ROOT_USERNAME"
            value = "fixops"
          }
          
          env {
            name  = "MONGO_INITDB_DATABASE"
            value = "fixops_production"
          }
          
          resources {
            requests = {
              memory = "512Mi"
              cpu    = "250m"
            }
            limits = {
              memory = "1Gi"
              cpu    = "500m"
            }
          }
          
          volume_mount {
            name       = "mongodb-data"
            mount_path = "/data/db"
          }
          
          volume_mount {
            name       = "mongodb-config"
            mount_path = "/data/configdb"
          }
          
          liveness_probe {
            exec {
              command = ["mongo", "--eval", "db.adminCommand('ping')"]
            }
            initial_delay_seconds = 30
            period_seconds        = 10
            timeout_seconds       = 5
            failure_threshold     = 3
          }
          
          readiness_probe {
            exec {
              command = ["mongo", "--eval", "db.adminCommand('ping')"]
            }
            initial_delay_seconds = 5
            period_seconds        = 10
            timeout_seconds       = 1
            failure_threshold     = 3
          }
        }
      }
    }
    
    volume_claim_template {
      metadata {
        name   = "mongodb-data"
        labels = var.labels
      }
      
      spec {
        access_modes = ["ReadWriteOnce"]
        
        resources {
          requests = {
            storage = var.storage_size
          }
        }
        
        storage_class_name = var.storage_class
      }
    }
    
    volume_claim_template {
      metadata {
        name   = "mongodb-config"
        labels = var.labels
      }
      
      spec {
        access_modes = ["ReadWriteOnce"]
        
        resources {
          requests = {
            storage = "1Gi"
          }
        }
        
        storage_class_name = var.storage_class
      }
    }
  }
}

# MongoDB Service
resource "kubernetes_service" "mongodb" {
  metadata {
    name      = "mongodb"
    namespace = var.namespace
    labels    = var.labels
  }
  
  spec {
    selector = {
      app = "mongodb"
    }
    
    port {
      name        = "mongodb"
      port        = 27017
      target_port = 27017
    }
    
    cluster_ip = "None"  # Headless service for StatefulSet
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
  description = "Number of MongoDB replicas"
  type        = number
  default     = 3
}

variable "storage_size" {
  description = "Storage size for MongoDB"
  type        = string
  default     = "10Gi"
}

variable "storage_class" {
  description = "Storage class for bank encryption"
  type        = string
  default     = "bank-encrypted-ssd"
}

variable "auth_enabled" {
  description = "Enable MongoDB authentication"
  type        = bool
  default     = true
}

variable "backup_enabled" {
  description = "Enable automated backups"
  type        = bool
  default     = true
}

variable "monitoring_enabled" {
  description = "Enable MongoDB monitoring"
  type        = bool
  default     = true
}

# Outputs
output "service_name" {
  description = "MongoDB service name"
  value       = kubernetes_service.mongodb.metadata[0].name
}

output "connection_string" {
  description = "MongoDB connection string"
  value       = "mongodb://mongodb.${var.namespace}:27017/fixops_production"
  sensitive   = true
}
