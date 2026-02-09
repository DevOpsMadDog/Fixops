terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
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
}

resource "google_storage_bucket" "evidence" {
  name          = local.gcp_config.gcs_bucket
  location      = var.region
  force_destroy = false
  
  uniform_bucket_level_access = true
  
  versioning {
    enabled = true
  }
  
  lifecycle_rule {
    condition {
      age = local.retention_days.raw
      matches_prefix = ["raw/"]
    }
    action {
      type = "Delete"
    }
  }
  
  lifecycle_rule {
    condition {
      age = local.retention_days.summary
      matches_prefix = ["summary/"]
    }
    action {
      type = "Delete"
    }
  }
  
  lifecycle_rule {
    condition {
      age = 90
      matches_prefix = ["evidence/"]
    }
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
  }
  
  lifecycle_rule {
    condition {
      age = 180
      matches_prefix = ["evidence/"]
    }
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
  }
  
  lifecycle_rule {
    condition {
      age = local.retention_days.evidence
      matches_prefix = ["evidence/"]
    }
    action {
      type          = "SetStorageClass"
      storage_class = "ARCHIVE"
    }
  }
  
  labels = var.labels
}

resource "google_pubsub_topic" "telemetry" {
  name = "${var.prefix}-telemetry-topic"
  
  labels = var.labels
}

resource "google_pubsub_subscription" "telemetry" {
  name  = "${var.prefix}-telemetry-sub"
  topic = google_pubsub_topic.telemetry.name
  
  ack_deadline_seconds = 60
  
  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }
  
  labels = var.labels
}

resource "google_logging_project_sink" "telemetry" {
  name        = "${var.prefix}-telemetry-sink"
  destination = "pubsub.googleapis.com/${google_pubsub_topic.telemetry.id}"
  
  filter = "resource.type=\"http_load_balancer\" AND jsonPayload.enforcedSecurityPolicy.name!=\"\""
  
  unique_writer_identity = true
}

resource "google_pubsub_topic_iam_member" "log_writer" {
  topic  = google_pubsub_topic.telemetry.name
  role   = "roles/pubsub.publisher"
  member = google_logging_project_sink.telemetry.writer_identity
}

resource "google_secret_manager_secret" "fixops_api_key" {
  secret_id = "fixops-api-key"
  
  replication {
    auto {}
  }
  
  labels = var.labels
}

resource "google_secret_manager_secret_version" "fixops_api_key" {
  secret      = google_secret_manager_secret.fixops_api_key.id
  secret_data = var.fixops_api_key
}

resource "google_service_account" "function" {
  account_id   = "${var.prefix}-telemetry-fn"
  display_name = "FixOps Telemetry Function"
}

resource "google_secret_manager_secret_iam_member" "function_secret_access" {
  secret_id = google_secret_manager_secret.fixops_api_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.function.email}"
}

resource "google_storage_bucket_iam_member" "function_storage_access" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.function.email}"
}

data "archive_file" "function_zip" {
  type        = "zip"
  source_dir  = "${path.module}/.."
  output_path = "${path.module}/function.zip"
  excludes    = ["terraform", "test_main.py", "__pycache__", "*.pyc"]
}

resource "google_storage_bucket" "function_source" {
  name          = "${var.prefix}-telemetry-fn-source"
  location      = var.region
  force_destroy = true
  
  uniform_bucket_level_access = true
  
  labels = var.labels
}

resource "google_storage_bucket_object" "function_zip" {
  name   = "function-${data.archive_file.function_zip.output_md5}.zip"
  bucket = google_storage_bucket.function_source.name
  source = data.archive_file.function_zip.output_path
}

resource "google_cloudfunctions2_function" "telemetry" {
  name        = "${var.prefix}-telemetry-function"
  location    = var.region
  description = "FixOps telemetry ingestion from Pub/Sub"
  
  build_config {
    runtime     = "python311"
    entry_point = "telemetry_handler"
    
    source {
      storage_source {
        bucket = google_storage_bucket.function_source.name
        object = google_storage_bucket_object.function_zip.name
      }
    }
  }
  
  service_config {
    max_instance_count    = 10
    min_instance_count    = 0
    available_memory      = "256M"
    timeout_seconds       = 60
    service_account_email = google_service_account.function.email
    
    environment_variables = {
      FIXOPS_OVERLAY_PATH = "/workspace/config/fixops.overlay.yml"
      FIXOPS_API_KEY      = var.fixops_api_key
    }
    
    secret_environment_variables {
      key        = "FIXOPS_API_KEY"
      project_id = var.project_id
      secret     = google_secret_manager_secret.fixops_api_key.secret_id
      version    = "latest"
    }
  }
  
  event_trigger {
    trigger_region        = var.region
    event_type           = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic         = google_pubsub_topic.telemetry.id
    retry_policy         = "RETRY_POLICY_RETRY"
    service_account_email = google_service_account.function.email
  }
  
  labels = var.labels
}

resource "google_cloud_run_service_iam_member" "pubsub_invoker" {
  location = google_cloudfunctions2_function.telemetry.location
  service  = google_cloudfunctions2_function.telemetry.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.function.email}"
}
