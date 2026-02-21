variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "ap-southeast-2"
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

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Project   = "FixOps"
    Component = "TelemetryBridge"
    ManagedBy = "Terraform"
  }
}
