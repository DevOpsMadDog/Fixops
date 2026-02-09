# Complete Terraform deployment for FixOps
# Uses all modules for full bank-grade deployment

module "fixops_namespace" {
  source = "./modules/namespace"
  
  namespace   = var.namespace
  labels      = local.labels
  environment = var.environment
}

module "fixops_rbac" {
  source = "./modules/rbac"
  
  namespace = module.fixops_namespace.name
  labels    = local.labels
}

module "fixops_storage" {
  source = "./modules/storage"
  
  namespace     = module.fixops_namespace.name
  labels        = local.labels
  storage_size  = var.storage_size
  storage_class = "bank-encrypted-ssd"
}

module "fixops_mongodb" {
  source = "./modules/mongodb"
  
  namespace    = module.fixops_namespace.name
  labels       = local.labels
  replicas     = 3
  storage_size = var.storage_size
  
  depends_on = [module.fixops_namespace]
}

module "fixops_redis" {
  source = "./modules/redis"
  
  namespace = module.fixops_namespace.name
  labels    = local.labels
  replicas  = 3
  
  depends_on = [module.fixops_namespace]
}

module "fixops_backend" {
  source = "./modules/backend"
  
  namespace = module.fixops_namespace.name
  labels    = local.labels
  replicas  = var.replicas
  image     = "core/decision-engine:latest"
  
  config = {
    FIXOPS_ENVIRONMENT   = var.environment
    FIXOPS_DEMO_MODE     = "false"
    FIXOPS_AUTH_DISABLED = "true"
    MONGO_URL = module.fixops_mongodb.connection_string
    REDIS_URL = "redis://redis.${module.fixops_namespace.name}:6379/0"
  }
  
  secrets = {
    EMERGENT_LLM_KEY = var.emergent_llm_key
  }
  
  resources = {
    requests = {
      memory = "512Mi"
      cpu    = "250m"
    }
    limits = {
      memory = "1Gi"
      cpu    = "500m"
    }
  }
  
  health_checks = {
    liveness = {
      path = "/health"
      port = 8001
    }
    readiness = {
      path = "/ready"
      port = 8001
    }
  }
  
  depends_on = [
    module.fixops_storage,
    module.fixops_mongodb,
    module.fixops_redis
  ]
}

module "fixops_frontend" {
  source = "./modules/frontend"
  
  namespace   = module.fixops_namespace.name
  labels      = local.labels
  replicas    = 2
  backend_url = "http://${module.fixops_backend.service_name}:8001"
  
  depends_on = [module.fixops_backend]
}

module "fixops_ingress" {
  source = "./modules/ingress"
  
  namespace = module.fixops_namespace.name
  labels    = local.labels
  
  hosts = {
    api = "fixops-api.bank.internal"
    ui  = "fixops.bank.internal"
  }
  
  backend_service  = module.fixops_backend.service_name
  frontend_service = module.fixops_frontend.service_name
  
  depends_on = [
    module.fixops_backend,
    module.fixops_frontend
  ]
}
