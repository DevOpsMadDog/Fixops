# FixOps Namespace Module
# Creates secure namespace with bank policies

resource "kubernetes_namespace" "fixops" {
  metadata {
    name   = var.namespace
    labels = var.labels
    
    annotations = {
      "security.bank/classification" = "confidential"
      "compliance.bank/frameworks"   = "pci-dss,sox,ffiec"
      "backstage.io/managed-by"      = "platform-engineering"
    }
  }
}

# Network policies for bank security
resource "kubernetes_network_policy" "fixops_network_policy" {
  count = var.network_policies_enabled ? 1 : 0
  
  metadata {
    name      = "fixops-network-policy"
    namespace = kubernetes_namespace.fixops.metadata[0].name
    labels    = var.labels
  }
  
  spec {
    pod_selector {
      match_labels = {
        "app.kubernetes.io/part-of" = "fixops"
      }
    }
    
    policy_types = ["Ingress", "Egress"]
    
    # Allow ingress from bank's ingress controllers
    ingress {
      from {
        namespace_selector {
          match_labels = {
            "name" = "ingress-nginx"
          }
        }
      }
      
      ports {
        protocol = "TCP"
        port     = "8001"
      }
      ports {
        protocol = "TCP" 
        port     = "3000"
      }
    }
    
    # Allow internal communication
    ingress {
      from {
        namespace_selector {
          match_labels = {
            "name" = kubernetes_namespace.fixops.metadata[0].name
          }
        }
      }
    }
    
    # Allow egress to bank APIs
    egress {
      to {
        namespace_selector {
          match_labels = {
            "security.bank/api-access" = "allowed"
          }
        }
      }
    }
    
    # Allow DNS resolution
    egress {
      to {}
      ports {
        protocol = "UDP"
        port     = "53"
      }
    }
  }
}

# Resource quotas for bank compliance
resource "kubernetes_resource_quota" "fixops_quota" {
  count = var.resource_quotas_enabled ? 1 : 0
  
  metadata {
    name      = "fixops-resource-quota"
    namespace = kubernetes_namespace.fixops.metadata[0].name
    labels    = var.labels
  }
  
  spec {
    hard = {
      "requests.cpu"    = "2"
      "requests.memory" = "4Gi"
      "limits.cpu"      = "4"
      "limits.memory"   = "8Gi"
      "pods"            = "20"
      "services"        = "10"
      "persistentvolumeclaims" = "5"
    }
  }
}

# Variables
variable "namespace" {
  description = "Kubernetes namespace name"
  type        = string
}

variable "labels" {
  description = "Common labels for all resources"
  type        = map(string)
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "network_policies_enabled" {
  description = "Enable network policies"
  type        = bool
  default     = true
}

variable "resource_quotas_enabled" {
  description = "Enable resource quotas"
  type        = bool
  default     = true
}

# Outputs
output "name" {
  description = "Namespace name"
  value       = kubernetes_namespace.fixops.metadata[0].name
}

output "labels" {
  description = "Namespace labels"
  value       = kubernetes_namespace.fixops.metadata[0].labels
}
