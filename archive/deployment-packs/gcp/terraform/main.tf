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

variable "mongo_password" {
  description = "MongoDB root password"
  type        = string
  sensitive   = true
}

variable "redis_password" {
  description = "Redis password"
  type        = string
  sensitive   = true
}

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

resource "google_compute_instance" "mongodb" {
  name         = "${var.cluster_name}-mongodb"
  machine_type = "e2-standard-2"
  zone         = "${var.region}-a"
  
  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2004-lts"
      size  = 50
    }
  }
  
  network_interface {
    network = "default"
    access_config {}
  }
  
  metadata_startup_script = <<-EOF
    #!/bin/bash
    apt-get update
    apt-get install -y gnupg curl
    curl -fsSL https://pgp.mongodb.com/server-6.0.asc | gpg -o /usr/share/keyrings/mongodb-server-6.0.gpg --dearmor
    echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-6.0.gpg ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-6.0.list
    apt-get update
    apt-get install -y mongodb-org
    
    sed -i 's/bindIp: 127.0.0.1/bindIp: 0.0.0.0/' /etc/mongod.conf
    
    systemctl start mongod
    systemctl enable mongod
    
    sleep 5
    
    mongosh --eval 'db.getSiblingDB("admin").createUser({user: "fixops", pwd: "${var.mongo_password}", roles: [{role: "root", db: "admin"}]})'
  EOF
  
  labels = local.common_labels
}

resource "google_redis_instance" "redis" {
  name           = "${var.cluster_name}-redis"
  tier           = "STANDARD_HA"
  memory_size_gb = 1
  region         = var.region
  
  authorized_network = "default"
  
  labels = local.common_labels
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

resource "kubernetes_secret" "backend_secrets" {
  metadata {
    name      = "fixops-backend-secrets"
    namespace = kubernetes_namespace.fixops.metadata[0].name
  }
  
  string_data = {
    EMERGENT_LLM_KEY = var.emergent_llm_key
    MONGO_URL        = "mongodb://fixops:${var.mongo_password}@${google_compute_instance.mongodb.network_interface[0].network_ip}:27017/fixops?authSource=admin"
    REDIS_URL        = "redis://:${var.redis_password}@${google_redis_instance.redis.host}:${google_redis_instance.redis.port}/0"
  }
  
  type = "Opaque"
}

resource "kubernetes_persistent_volume_claim" "evidence_lake" {
  metadata {
    name      = "fixops-evidence-lake"
    namespace = kubernetes_namespace.fixops.metadata[0].name
    labels    = local.common_labels
  }
  
  spec {
    access_modes = ["ReadWriteOnce"]
    resources {
      requests = {
        storage = var.storage_size
      }
    }
  }
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
          name  = "backend"
          image = "fixops/backend:${var.backend_image_tag}"
          
          port {
            container_port = 8000
            name           = "http"
          }
          
          env_from {
            secret_ref {
              name = kubernetes_secret.backend_secrets.metadata[0].name
            }
          }
          
          volume_mount {
            name       = "evidence-lake"
            mount_path = "/data/evidence"
          }
          
          resources {
            requests = {
              cpu    = "500m"
              memory = "1Gi"
            }
            limits = {
              cpu    = "2000m"
              memory = "4Gi"
            }
          }
          
          liveness_probe {
            http_get {
              path = "/health"
              port = 8000
            }
            initial_delay_seconds = 30
            period_seconds        = 10
          }
          
          readiness_probe {
            http_get {
              path = "/health"
              port = 8000
            }
            initial_delay_seconds = 10
            period_seconds        = 5
          }
        }
        
        volume {
          name = "evidence-lake"
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
    name      = "fixops-backend"
    namespace = kubernetes_namespace.fixops.metadata[0].name
    labels    = local.common_labels
  }
  
  spec {
    selector = {
      "app.kubernetes.io/name"      = "fixops"
      "app.kubernetes.io/component" = "backend"
    }
    
    port {
      port        = 80
      target_port = 8000
      protocol    = "TCP"
      name        = "http"
    }
    
    type = "LoadBalancer"
  }
}

output "cluster_name" {
  description = "GKE cluster name"
  value       = google_container_cluster.fixops.name
}

output "namespace" {
  description = "Kubernetes namespace"
  value       = kubernetes_namespace.fixops.metadata[0].name
}

output "backend_service_ip" {
  description = "Backend service external IP"
  value       = kubernetes_service.backend.status[0].load_balancer[0].ingress[0].ip
}

output "mongodb_ip" {
  description = "MongoDB instance IP"
  value       = google_compute_instance.mongodb.network_interface[0].network_ip
}

output "redis_host" {
  description = "Redis instance host"
  value       = google_redis_instance.redis.host
}
