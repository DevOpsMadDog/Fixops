output "cluster_name" {
  description = "Name of the GKE Autopilot cluster"
  value       = google_container_cluster.autopilot.name
}

output "cluster_endpoint" {
  description = "Endpoint of the GKE cluster"
  value       = google_container_cluster.autopilot.endpoint
  sensitive   = true
}

output "cluster_location" {
  description = "Location of the GKE cluster"
  value       = google_container_cluster.autopilot.location
}

output "service_account_email" {
  description = "Email of the collector service account"
  value       = google_service_account.collector.email
}

output "artifact_registry_url" {
  description = "URL of the Artifact Registry repository"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}"
}

output "collector_service_url" {
  description = "Internal URL of the collector service"
  value       = "http://collector-api.${kubernetes_namespace.telemetry.metadata[0].name}.svc.cluster.local:8080"
}

output "namespace" {
  description = "Kubernetes namespace for telemetry components"
  value       = kubernetes_namespace.telemetry.metadata[0].name
}
