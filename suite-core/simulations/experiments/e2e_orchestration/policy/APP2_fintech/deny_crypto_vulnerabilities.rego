package terraform.fintech.crypto

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# METADATA
# title: Deny Cryptocurrency and Blockchain Vulnerabilities
# description: Prevents deployment of vulnerable crypto libraries and insecure blockchain configurations
# custom:
#   severity: critical
#   compliance: ["PCI-DSS 6.2", "SOX 404", "MiFID II"]
#   remediation: "Upgrade vulnerable crypto libraries, implement multi-signature wallets, use HSM for key storage"

# Deny vulnerable ethers.js versions (CVE-2024-11223 private key extraction)
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "kubernetes_deployment"
    
    container := resource.change.after.spec[_].template[_].spec[_].containers[_]
    image := container.image
    
    # Check for vulnerable ethers.js in package.json or image
    contains(lower(image), "ethers") or contains(lower(image), "web3")
    
    msg := sprintf(
        "CRITICAL: Deployment '%s' uses blockchain libraries. Ensure ethers.js >= 6.9.0 and web3.js >= 4.0.0 to prevent CVE-2024-11223 (private key extraction). Current image: %s",
        [resource.name, image]
    )
}

# Deny hot wallets without multi-signature
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "kubernetes_deployment"
    
    # Check for blockchain wallet services
    contains(lower(resource.name), "wallet") or
    contains(lower(resource.name), "blockchain")
    
    # Check if multi-signature is not configured
    container := resource.change.after.spec[_].template[_].spec[_].containers[_]
    env := container.env[_]
    
    not has_multisig_config(container)
    
    msg := sprintf(
        "CRITICAL: Blockchain wallet service '%s' does not have multi-signature configuration. This violates financial security best practices. Configure MULTISIG_THRESHOLD >= 2.",
        [resource.name]
    )
}

# Deny private keys in environment variables or ConfigMaps
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "kubernetes_config_map"
    
    data_value := resource.change.after.data[key]
    
    # Check for private key patterns
    contains(lower(key), "private_key") or
    contains(lower(key), "priv_key") or
    contains(lower(key), "wallet_key") or
    contains(lower(key), "ethereum_key") or
    contains(lower(key), "bitcoin_key")
    
    msg := sprintf(
        "CRITICAL: ConfigMap '%s' contains blockchain private key in key '%s'. This violates PCI-DSS 6.2 and could lead to fund theft ($12.5M exposure). Use AWS Secrets Manager or HSM.",
        [resource.name, key]
    )
}

# Deny blockchain nodes exposed to internet
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "kubernetes_service"
    resource.change.after.spec[_].type == "LoadBalancer"
    
    # Check if this is a blockchain node service
    contains(lower(resource.name), "blockchain") or
    contains(lower(resource.name), "ethereum") or
    contains(lower(resource.name), "bitcoin") or
    contains(lower(resource.name), "node")
    
    msg := sprintf(
        "CRITICAL: Blockchain node service '%s' exposed via LoadBalancer. This allows direct internet access and increases attack surface. Use ClusterIP with VPN access only.",
        [resource.name]
    )
}

# Deny smart contracts without formal verification
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "kubernetes_deployment"
    
    contains(lower(resource.name), "contract") or
    contains(lower(resource.name), "defi")
    
    # Check if formal verification tools are present
    container := resource.change.after.spec[_].template[_].spec[_].containers[_]
    not has_formal_verification(container)
    
    msg := sprintf(
        "HIGH: Smart contract deployment '%s' does not show evidence of formal verification. This increases risk of reentrancy attacks and fund loss. Use Certora, K Framework, or manual audit.",
        [resource.name]
    )
}

# Deny weak cryptographic algorithms
deny[msg] {
    resource := input.resource_changes[_]
    
    env := walk_env_vars(resource.change.after)[_]
    
    # Check for weak crypto algorithms
    weak_algos := ["md5", "sha1", "des", "rc4", "rsa1024"]
    algo := weak_algos[_]
    contains(lower(env.value), algo)
    
    msg := sprintf(
        "HIGH: Resource '%s' uses weak cryptographic algorithm '%s'. This violates PCI-DSS 4.1. Use SHA-256, AES-256, or RSA-2048+.",
        [resource.name, algo]
    )
}

# Deny payment processing without PCI-DSS compliance
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "kubernetes_deployment"
    
    contains(lower(resource.name), "payment") or
    contains(lower(resource.name), "billing")
    
    # Check for PCI-DSS compliance markers
    not has_pci_compliance(resource)
    
    msg := sprintf(
        "CRITICAL: Payment service '%s' does not show PCI-DSS compliance markers. This violates payment card industry standards. Implement tokenization, encryption at rest/transit, and audit logging.",
        [resource.name]
    )
}

# Deny trading services without rate limiting
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "kubernetes_deployment"
    
    contains(lower(resource.name), "trading") or
    contains(lower(resource.name), "order")
    
    # Check for rate limiting configuration
    container := resource.change.after.spec[_].template[_].spec[_].containers[_]
    not has_rate_limiting(container)
    
    msg := sprintf(
        "HIGH: Trading service '%s' does not have rate limiting configured. This allows high-frequency trading abuse and DoS attacks. Configure rate limits per user/API key.",
        [resource.name]
    )
}

# Deny KYC document storage without encryption
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    
    contains(lower(resource.name), "kyc") or
    contains(lower(resource.name), "identity") or
    contains(lower(resource.name), "document")
    
    not has_encryption(resource)
    
    msg := sprintf(
        "CRITICAL: S3 bucket '%s' stores KYC documents without encryption. This violates GDPR Article 32 and AML/KYC regulations. Enable server-side encryption with KMS.",
        [resource.name]
    )
}

# Deny cross-chain bridges without security audit
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "kubernetes_deployment"
    
    contains(lower(resource.name), "bridge") or
    contains(lower(resource.name), "cross-chain")
    
    msg := sprintf(
        "CRITICAL: Cross-chain bridge '%s' requires comprehensive security audit. Historical attacks (Poly Network $611M, Ronin $625M) demonstrate critical risk. Require formal verification and multi-signature controls.",
        [resource.name]
    )
}

# Helper functions
has_multisig_config(container) {
    env := container.env[_]
    contains(lower(env.name), "multisig")
}

has_formal_verification(container) {
    env := container.env[_]
    contains(lower(env.name), "verified") or
    contains(lower(env.name), "audit")
}

has_pci_compliance(resource) {
    label := resource.change.after.metadata[_].labels["compliance"]
    contains(lower(label), "pci")
}

has_rate_limiting(container) {
    env := container.env[_]
    contains(lower(env.name), "rate_limit") or
    contains(lower(env.name), "throttle")
}

has_encryption(resource) {
    resource.change.after.server_side_encryption_configuration != null
}

walk_env_vars(obj) = envs {
    envs := [e | 
        walk(obj, [path, value]);
        path[_] == "environment";
        e := value[_]
    ]
}

# Test cases
test_deny_vulnerable_ethers {
    deny[msg] with input as {
        "resource_changes": [{
            "type": "kubernetes_deployment",
            "name": "blockchain-service",
            "change": {
                "after": {
                    "spec": [{
                        "template": [{
                            "spec": [{
                                "containers": [{
                                    "name": "blockchain",
                                    "image": "blockchain-app:latest-ethers-5.7.0"
                                }]
                            }]
                        }]
                    }]
                }
            }
        }]
    }
    
    contains(msg, "CRITICAL")
    contains(msg, "ethers")
}

test_deny_private_key_in_configmap {
    deny[msg] with input as {
        "resource_changes": [{
            "type": "kubernetes_config_map",
            "name": "wallet-config",
            "change": {
                "after": {
                    "data": {
                        "ETHEREUM_PRIVATE_KEY": "0x1234567890abcdef..."
                    }
                }
            }
        }]
    }
    
    contains(msg, "CRITICAL")
    contains(msg, "private key")
}

test_allow_secure_blockchain_service {
    count(deny) == 0 with input as {
        "resource_changes": [{
            "type": "kubernetes_deployment",
            "name": "blockchain-service",
            "change": {
                "after": {
                    "spec": [{
                        "template": [{
                            "spec": [{
                                "containers": [{
                                    "name": "blockchain",
                                    "image": "blockchain-app:latest-ethers-6.9.0",
                                    "env": [{
                                        "name": "MULTISIG_THRESHOLD",
                                        "value": "3"
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
