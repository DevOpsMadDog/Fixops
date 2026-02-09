output "function_name" {
  description = "Name of the Cloud Function"
  value       = google_cloudfunctions2_function.telemetry.name
}

output "function_url" {
  description = "URL of the Cloud Function"
  value       = google_cloudfunctions2_function.telemetry.service_config[0].uri
}

output "pubsub_topic" {
  description = "Pub/Sub topic name"
  value       = google_pubsub_topic.telemetry.name
}

output "pubsub_subscription" {
  description = "Pub/Sub subscription name"
  value       = google_pubsub_subscription.telemetry.name
}

output "storage_bucket" {
  description = "GCS bucket name for evidence storage"
  value       = google_storage_bucket.evidence.name
}

output "service_account_email" {
  description = "Service account email for the function"
  value       = google_service_account.function.email
}
