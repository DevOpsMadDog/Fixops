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

variable "fixops_api_key_secret_arn" {
  description = "ARN of AWS Secrets Manager secret containing FixOps API key"
  type        = string
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    project    = "fixops"
    component  = "telemetry-bridge"
    managed-by = "terraform"
  }
}
