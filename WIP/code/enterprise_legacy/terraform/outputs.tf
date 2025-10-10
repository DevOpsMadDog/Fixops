# FixOps Terraform Outputs
# Information for bank integration teams

output "fixops_api_url" {
  description = "FixOps Decision Engine API endpoint for CI/CD integration"
  value       = "https://api.fixops.devops.ai"
}

output "fixops_ui_url" {
  description = "FixOps UI for security team access"
  value       = "https://fixops.devops.ai"
}

output "marketplace_url" {
  description = "FixOps Security Marketplace"
  value       = "https://marketplace.fixops.devops.ai"
}

output "namespace" {
  description = "Kubernetes namespace where FixOps is deployed"
  value       = module.fixops_namespace.name
}

output "backend_service" {
  description = "Internal backend service endpoint"
  value       = "http://${module.fixops_backend.service_name}.${module.fixops_namespace.name}:8001"
}

output "mongodb_connection" {
  description = "Internal MongoDB connection string"
  value       = module.fixops_mongodb.connection_string
  sensitive   = true
}

output "deployment_info" {
  description = "Complete deployment information for integration teams"
  value = {
    api_endpoint      = "https://api.fixops.devops.ai"
    ui_endpoint       = "https://fixops.devops.ai"
    marketplace       = "https://marketplace.fixops.devops.ai"
    health_check      = "https://api.fixops.devops.ai/health"
    readiness_check   = "https://api.fixops.devops.ai/ready"
    metrics_endpoint  = "https://api.fixops.devops.ai/metrics"
    
    # CI/CD Integration
    cicd_decision_api = "https://api.fixops.devops.ai/api/v1/cicd/decision"
    file_upload_api   = "https://api.fixops.devops.ai/api/v1/scans/upload"
    
    # Kubernetes info
    namespace         = module.fixops_namespace.name
    backend_replicas  = var.replicas
    storage_size      = var.storage_size
    
    # Example CI/CD integration
    curl_example = "curl -X POST https://api.fixops.devops.ai/api/v1/cicd/decision -H 'Content-Type: application/json' --data '{\"service_name\": \"your-service\", \"environment\": \"production\"}'"
  }
}

output "kubectl_commands" {
  description = "Useful kubectl commands for bank operations teams"
  value = {
    check_pods     = "kubectl get pods -n ${module.fixops_namespace.name}"
    check_services = "kubectl get services -n ${module.fixops_namespace.name}"
    view_logs      = "kubectl logs -f deployment/fixops-backend -n ${module.fixops_namespace.name}"
    port_forward   = "kubectl port-forward service/fixops-backend-service 8001:8001 -n ${module.fixops_namespace.name}"
    scale_backend  = "kubectl scale deployment fixops-backend --replicas=5 -n ${module.fixops_namespace.name}"
  }
}

output "monitoring_info" {
  description = "Monitoring and observability information"
  value = {
    prometheus_metrics = "https://fixops-api.bank.internal/metrics"
    grafana_dashboard  = "https://grafana.bank.internal/d/fixops-dashboard"
    log_aggregation    = "Available via bank's logging infrastructure"
    alert_channels     = ["bank-security-team", "platform-engineering"]
  }
}

output "compliance_info" {
  description = "Compliance and audit information for bank compliance teams"
  value = {
    evidence_lake = {
      storage_location = "MongoDB in ${module.fixops_namespace.name} namespace"
      retention_period = "7 years (2555 days)"
      encryption      = "Enabled via bank storage class"
      backup_strategy = "Automated daily backups"
    }
    
    audit_trail = {
      evidence_format    = "Cryptographically signed JSON records"
      integrity_checking = "SHA256 hash validation"
      access_logging     = "All API calls logged with correlation IDs"
      compliance_ready   = "PCI DSS, SOX, FFIEC compliant"
    }
    
    security_controls = {
      network_isolation = "Kubernetes network policies"
      rbac_enabled     = "Minimal permissions with service accounts"
      secrets_management = "Kubernetes secrets with bank encryption"
      container_security = "Non-root containers with security contexts"
    }
  }
}