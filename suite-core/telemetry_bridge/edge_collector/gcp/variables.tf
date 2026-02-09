variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region for deployment"
  type        = string
  default     = "australia-southeast1"
}

variable "prefix" {
  description = "Prefix for resource names"
  type        = string
  default     = "fixops"
}

variable "overlay_path" {
  description = "Path to fixops.overlay.yml (defaults to repo config)"
  type        = string
  default     = ""
}

variable "fixops_api_key" {
  description = "FixOps API key for authentication"
  type        = string
  sensitive   = true
}
