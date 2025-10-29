terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.24"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

locals {
  overlay_path = var.overlay_path != "" ? var.overlay_path : "${path.root}/../../../config/fixops.overlay.yml"
  overlay_data = yamldecode(file(local.overlay_path))
  telemetry_config = local.overlay_data.telemetry_bridge
  gcp_config = local.telemetry_config.gcp
  retention_days = local.telemetry_config.retention_days
  ring_buffer = local.telemetry_config.ring_buffer
  fluentbit = local.telemetry_config.fluentbit
}

data "google_storage_bucket" "evidence" {
  name = local.gcp_config.gcs_bucket
}

resource "google_container_cluster" "autopilot" {
  name     = "${var.prefix}-autopilot-cluster"
  location = var.region
  
  enable_autopilot = true
  
  release_channel {
    channel = "REGULAR"
  }
  
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }
  
  addons_config {
    gcs_fuse_csi_driver_config {
      enabled = true
    }
  }
  
  deletion_protection = false
}

data "google_client_config" "default" {}

provider "kubernetes" {
  host                   = "https://${google_container_cluster.autopilot.endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(google_container_cluster.autopilot.master_auth[0].cluster_ca_certificate)
}

resource "kubernetes_namespace" "telemetry" {
  metadata {
    name = "fixops-telemetry"
  }
  
  depends_on = [google_container_cluster.autopilot]
}

resource "google_service_account" "collector" {
  account_id   = "${var.prefix}-collector-sa"
  display_name = "FixOps Collector Service Account"
}

resource "google_storage_bucket_iam_member" "collector_storage_access" {
  bucket = data.google_storage_bucket.evidence.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.collector.email}"
}

resource "google_project_iam_member" "collector_secret_access" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.collector.email}"
}

resource "google_service_account_iam_member" "workload_identity_binding" {
  service_account_id = google_service_account.collector.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${kubernetes_namespace.telemetry.metadata[0].name}/collector-sa]"
}

resource "kubernetes_service_account" "collector" {
  metadata {
    name      = "collector-sa"
    namespace = kubernetes_namespace.telemetry.metadata[0].name
    
    annotations = {
      "iam.gke.io/gcp-service-account" = google_service_account.collector.email
    }
  }
}

resource "kubernetes_config_map" "overlay" {
  metadata {
    name      = "fixops-overlay"
    namespace = kubernetes_namespace.telemetry.metadata[0].name
  }
  
  data = {
    "fixops.overlay.yml" = file(local.overlay_path)
  }
}

resource "kubernetes_secret" "fixops_api_key" {
  metadata {
    name      = "fixops-api-key"
    namespace = kubernetes_namespace.telemetry.metadata[0].name
  }
  
  data = {
    api-key = base64encode(var.fixops_api_key)
  }
  
  type = "Opaque"
}

resource "kubernetes_deployment" "collector_api" {
  metadata {
    name      = "collector-api"
    namespace = kubernetes_namespace.telemetry.metadata[0].name
    
    labels = {
      app       = "collector-api"
      component = "telemetry-bridge"
    }
  }
  
  spec {
    replicas = 2
    
    selector {
      match_labels = {
        app = "collector-api"
      }
    }
    
    template {
      metadata {
        labels = {
          app = "collector-api"
        }
      }
      
      spec {
        service_account_name = kubernetes_service_account.collector.metadata[0].name
        
        container {
          name  = "collector-api"
          image = "${var.region}-docker.pkg.dev/${var.project_id}/${var.prefix}-images/collector-api:latest"
          
          port {
            container_port = 8080
            name           = "http"
          }
          
          env {
            name  = "FIXOPS_OVERLAY_PATH"
            value = "/app/config/fixops.overlay.yml"
          }
          
          env {
            name  = "CLOUD_PROVIDER"
            value = "gcp"
          }
          
          env {
            name = "FIXOPS_API_KEY"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.fixops_api_key.metadata[0].name
                key  = "api-key"
              }
            }
          }
          
          env {
            name  = "RING_BUFFER_MAX_LINES"
            value = tostring(local.ring_buffer.max_lines)
          }
          
          env {
            name  = "RING_BUFFER_MAX_SECONDS"
            value = tostring(local.ring_buffer.max_seconds)
          }
          
          volume_mount {
            name       = "overlay-config"
            mount_path = "/app/config"
            read_only  = true
          }
          
          resources {
            requests = {
              cpu    = "250m"
              memory = "512Mi"
            }
            limits = {
              cpu    = "1000m"
              memory = "1Gi"
            }
          }
          
          liveness_probe {
            http_get {
              path = "/health"
              port = 8080
            }
            initial_delay_seconds = 10
            period_seconds        = 30
          }
          
          readiness_probe {
            http_get {
              path = "/health"
              port = 8080
            }
            initial_delay_seconds = 5
            period_seconds        = 10
          }
        }
        
        volume {
          name = "overlay-config"
          config_map {
            name = kubernetes_config_map.overlay.metadata[0].name
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "collector_api" {
  metadata {
    name      = "collector-api"
    namespace = kubernetes_namespace.telemetry.metadata[0].name
    
    labels = {
      app = "collector-api"
    }
  }
  
  spec {
    type = "ClusterIP"
    
    selector = {
      app = "collector-api"
    }
    
    port {
      name        = "http"
      port        = 8080
      target_port = 8080
      protocol    = "TCP"
    }
  }
}

resource "kubernetes_daemon_set" "fluent_bit" {
  metadata {
    name      = "fluent-bit"
    namespace = kubernetes_namespace.telemetry.metadata[0].name
    
    labels = {
      app       = "fluent-bit"
      component = "telemetry-bridge"
    }
  }
  
  spec {
    selector {
      match_labels = {
        app = "fluent-bit"
      }
    }
    
    template {
      metadata {
        labels = {
          app = "fluent-bit"
        }
      }
      
      spec {
        service_account_name = kubernetes_service_account.collector.metadata[0].name
        
        container {
          name  = "fluent-bit"
          image = "${var.region}-docker.pkg.dev/${var.project_id}/${var.prefix}-images/fluent-bit:latest"
          
          env {
            name  = "INPUT_PATH"
            value = local.fluentbit.input_path
          }
          
          env {
            name  = "AGGREGATION_INTERVAL"
            value = tostring(local.fluentbit.aggregation_interval)
          }
          
          env {
            name  = "RETRY_LIMIT"
            value = tostring(local.fluentbit.retry_limit)
          }
          
          volume_mount {
            name       = "varlog"
            mount_path = "/var/log"
            read_only  = true
          }
          
          resources {
            requests = {
              cpu    = "100m"
              memory = "128Mi"
            }
            limits = {
              cpu    = "500m"
              memory = "256Mi"
            }
          }
        }
        
        volume {
          name = "varlog"
          host_path {
            path = "/var/log"
          }
        }
      }
    }
  }
}

resource "google_artifact_registry_repository" "images" {
  location      = var.region
  repository_id = "${var.prefix}-images"
  format        = "DOCKER"
  
  description = "FixOps telemetry bridge container images"
}
