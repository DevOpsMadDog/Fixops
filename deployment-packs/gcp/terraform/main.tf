terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
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
  
  backend "gcs" {
  }
}

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP region for deployment"
  type        = string
  default     = "us-central1"
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
  description = "GKE cluster name"
  type        = string
}

variable "namespace" {
  description = "Kubernetes namespace for FixOps"
  type        = string
  default     = "fixops"
}

variable "node_count" {
  description = "Number of nodes in the GKE cluster"
  type        = number
  default     = 3
}

variable "machine_type" {
  description = "GCE machine type for nodes"
  type        = string
  default     = "e2-standard-4"
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
  description = "Docker image tag for backend"
  type        = string
  default     = "v1.0.0"
}

variable "domain_name" {
  description = "Domain name for FixOps"
  type        = string
}

locals {
  common_labels = {
    "app.kubernetes.io/name"       = "fixops"
    "app.kubernetes.io/instance"   = "fixops-${var.environment}"
    "app.kubernetes.io/version"    = "1.0.0"
    "app.kubernetes.io/component"  = "decision-engine"
    "app.kubernetes.io/part-of"    = "security-platform"
    "app.kubernetes.io/managed-by" = "terraform"
    "environment"                  = var.environment
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_container_cluster" "fixops" {
  name     = var.cluster_name
  location = var.region
  
  remove_default_node_pool = true
  initial_node_count       = 1
  
  network    = "default"
  subnetwork = "default"
  
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }
  
  addons_config {
    http_load_balancing {
      disabled = false
    }
    horizontal_pod_autoscaling {
      disabled = false
    }
  }
  
  release_channel {
    channel = "REGULAR"
  }
}

resource "google_container_node_pool" "fixops_nodes" {
  name       = "${var.cluster_name}-node-pool"
  location   = var.region
  cluster    = google_container_cluster.fixops.name
  node_count = var.node_count
  
  node_config {
    machine_type = var.machine_type
    
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
    
    labels = {
      environment = var.environment
    }
    
    tags = ["fixops", var.environment]
    
    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }
  
  management {
    auto_repair  = true
    auto_upgrade = true
  }
}

data "google_client_config" "default" {}

data "google_container_cluster" "fixops" {
  name     = google_container_cluster.fixops.name
  location = var.region
}

provider "kubernetes" {
  host  = "https://${data.google_container_cluster.fixops.endpoint}"
  token = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(
    data.google_container_cluster.fixops.master_auth[0].cluster_ca_certificate
  )
}

provider "helm" {
  kubernetes {
    host  = "https://${data.google_container_cluster.fixops.endpoint}"
    token = data.google_client_config.default.access_token
    cluster_ca_certificate = base64decode(
      data.google_container_cluster.fixops.master_auth[0].cluster_ca_certificate
    )
  }
}

resource "kubernetes_namespace" "fixops" {
  metadata {
    name   = var.namespace
    labels = local.common_labels
  }
}

resource "kubernetes_storage_class" "fixops_ssd" {
  metadata {
    name = "fixops-ssd"
  }
  
  storage_provisioner = "kubernetes.io/gce-pd"
  reclaim_policy      = "Retain"
  volume_binding_mode = "WaitForFirstConsumer"
  
  parameters = {
    type             = "pd-ssd"
    replication-type = "regional-pd"
  }
}

resource "kubernetes_persistent_volume_claim" "evidence_lake" {
  metadata {
    name      = "fixops-evidence-lake"
    namespace = kubernetes_namespace.fixops.metadata[0].name
    labels    = local.common_labels
  }
  
  spec {
    access_modes       = ["ReadWriteOnce"]
    storage_class_name = kubernetes_storage_class.fixops_ssd.metadata[0].name
    
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
    labels    = local.common_labels
  }
  
  data = {
    FIXOPS_ENVIRONMENT = var.environment
    FIXOPS_DEMO_MODE   = "false"
    GCP_PROJECT        = var.project_id
    GCP_REGION         = var.region
    MONGO_URL          = "mongodb://mongodb.${var.namespace}:27017/fixops_${var.environment}"
    REDIS_URL          = "redis://redis.${var.namespace}:6379/0"
  }
}

resource "kubernetes_secret" "fixops" {
  metadata {
    name      = "fixops-secrets"
    namespace = kubernetes_namespace.fixops.metadata[0].name
    labels    = local.common_labels
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
    labels    = local.common_labels
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
        labels = merge(local.common_labels, {
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
    labels    = local.common_labels
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
  }
}

output "cluster_name" {
  description = "GKE cluster name"
  value       = google_container_cluster.fixops.name
}

output "cluster_endpoint" {
  description = "GKE cluster endpoint"
  value       = google_container_cluster.fixops.endpoint
  sensitive   = true
}

output "namespace" {
  description = "Kubernetes namespace"
  value       = kubernetes_namespace.fixops.metadata[0].name
}
