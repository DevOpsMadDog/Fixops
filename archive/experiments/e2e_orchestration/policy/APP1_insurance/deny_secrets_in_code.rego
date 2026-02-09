package terraform.insurance.secrets

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# METADATA
# title: Deny Hardcoded Secrets and Credentials
# description: Prevents secrets, API keys, and credentials from being hardcoded in infrastructure code
# custom:
#   severity: critical
#   compliance: ["HIPAA 164.312(a)(2)(i)", "SOC2 CC6.1", "PCI-DSS 8.2.1"]
#   remediation: "Use AWS Secrets Manager, HashiCorp Vault, or Kubernetes Secrets"

# Deny plaintext secrets in ConfigMaps
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "kubernetes_config_map"
    
    # Check for common secret patterns in data
    data_value := resource.change.after.data[key]
    is_secret(key, data_value)
    
    msg := sprintf(
        "CRITICAL: ConfigMap '%s' contains plaintext secret in key '%s'. This violates HIPAA 164.312(a)(2)(i) and PCI-DSS 8.2.1. Use Kubernetes Secret with encryption at rest.",
        [resource.name, key]
    )
}

# Deny Secrets without encryption at rest
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "kubernetes_secret"
    
    # Check if etcd encryption is disabled (would need cluster-level check)
    # For now, warn about sensitive secrets
    data_key := resource.change.after.data[key]
    contains(lower(key), "stripe") or contains(lower(key), "database")
    
    msg := sprintf(
        "HIGH: Kubernetes Secret '%s' contains sensitive data (%s). Ensure etcd encryption at rest is enabled. Violates HIPAA 164.312(a)(2)(iv).",
        [resource.name, key]
    )
}

# Deny hardcoded AWS credentials
deny[msg] {
    resource := input.resource_changes[_]
    resource.type in ["aws_instance", "aws_lambda_function", "aws_ecs_task_definition"]
    
    # Check environment variables for hardcoded credentials
    env := resource.change.after.environment[_]
    env_value := env.value
    
    # Pattern matching for AWS credentials
    contains(env_value, "AKIA") or 
    contains(env_value, "aws_access_key_id") or
    contains(env_value, "aws_secret_access_key")
    
    msg := sprintf(
        "CRITICAL: Resource '%s' contains hardcoded AWS credentials in environment variables. This violates SOC2 CC6.1. Use IAM roles or AWS Secrets Manager.",
        [resource.name]
    )
}

# Deny database passwords in environment variables
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "kubernetes_deployment"
    
    container := resource.change.after.spec[_].template[_].spec[_].containers[_]
    env := container.env[_]
    
    # Check for database password patterns
    contains(lower(env.name), "password") or
    contains(lower(env.name), "db_pass") or
    contains(lower(env.name), "database_password")
    
    # Check if value is hardcoded (not from secret)
    env.value != null
    
    msg := sprintf(
        "CRITICAL: Deployment '%s' container '%s' has hardcoded database password in env var '%s'. This violates HIPAA 164.312(a)(2)(i). Use valueFrom.secretKeyRef.",
        [resource.name, container.name, env.name]
    )
}

# Deny Stripe/payment API keys in plaintext
deny[msg] {
    resource := input.resource_changes[_]
    
    # Check all string values for Stripe key patterns
    value := walk_values(resource.change.after)[_]
    is_string(value)
    
    # Stripe key patterns
    startswith(value, "sk_live_") or
    startswith(value, "pk_live_") or
    startswith(value, "rk_live_")
    
    msg := sprintf(
        "CRITICAL: Resource '%s' contains Stripe API key in plaintext. This violates PCI-DSS 8.2.1 and could lead to payment fraud. Use AWS Secrets Manager.",
        [resource.name]
    )
}

# Deny SSH private keys in code
deny[msg] {
    resource := input.resource_changes[_]
    
    value := walk_values(resource.change.after)[_]
    is_string(value)
    
    contains(value, "BEGIN RSA PRIVATE KEY") or
    contains(value, "BEGIN OPENSSH PRIVATE KEY") or
    contains(value, "BEGIN PRIVATE KEY")
    
    msg := sprintf(
        "CRITICAL: Resource '%s' contains SSH private key in plaintext. This violates SOC2 CC6.1. Use AWS Systems Manager Parameter Store.",
        [resource.name]
    )
}

# Deny JWT secrets shorter than 256 bits
deny[msg] {
    resource := input.resource_changes[_]
    
    env := walk_env_vars(resource.change.after)[_]
    contains(lower(env.name), "jwt_secret") or
    contains(lower(env.name), "jwt_key")
    
    # Check if secret is too short (< 32 chars = 256 bits)
    count(env.value) < 32
    
    msg := sprintf(
        "HIGH: Resource '%s' has weak JWT secret (< 256 bits). This violates OWASP recommendations and makes tokens vulnerable to brute force. Use crypto.randomBytes(32).",
        [resource.name]
    )
}

# Helper function to detect secrets
is_secret(key, value) {
    secret_patterns := [
        "password", "passwd", "pwd",
        "secret", "token", "api_key", "apikey",
        "private_key", "access_key", "secret_key",
        "stripe", "paypal", "auth",
        "credential", "jwt"
    ]
    
    pattern := secret_patterns[_]
    contains(lower(key), pattern)
}

# Helper function to walk all values
walk_values(obj) = values {
    values := [v | walk(obj, [_, v])]
}

# Helper function to walk environment variables
walk_env_vars(obj) = envs {
    envs := [e | 
        walk(obj, [path, value]);
        path[_] == "environment";
        e := value[_]
    ]
}

# Test cases
test_deny_configmap_with_stripe_key {
    deny[msg] with input as {
        "resource_changes": [{
            "type": "kubernetes_config_map",
            "name": "app-config",
            "change": {
                "after": {
                    "data": {
                        "stripe_secret_key": "sk_live_1234567890abcdef"
                    }
                }
            }
        }]
    }
    
    contains(msg, "CRITICAL")
    contains(msg, "stripe_secret_key")
}

test_deny_hardcoded_db_password {
    deny[msg] with input as {
        "resource_changes": [{
            "type": "kubernetes_deployment",
            "name": "pricing-api",
            "change": {
                "after": {
                    "spec": [{
                        "template": [{
                            "spec": [{
                                "containers": [{
                                    "name": "api",
                                    "env": [{
                                        "name": "DATABASE_PASSWORD",
                                        "value": "supersecret123"
                                    }]
                                }]
                            }]
                        }]
                    }]
                }
            }
        }]
    }
    
    contains(msg, "CRITICAL")
    contains(msg, "DATABASE_PASSWORD")
}

test_allow_secret_from_secretref {
    count(deny) == 0 with input as {
        "resource_changes": [{
            "type": "kubernetes_deployment",
            "name": "pricing-api",
            "change": {
                "after": {
                    "spec": [{
                        "template": [{
                            "spec": [{
                                "containers": [{
                                    "name": "api",
                                    "env": [{
                                        "name": "DATABASE_PASSWORD",
                                        "valueFrom": {
                                            "secretKeyRef": {
                                                "name": "db-credentials",
                                                "key": "password"
                                            }
                                        }
                                    }]
                                }]
                            }]
                        }]
                    }]
                }
            }
        }]
    }
}
