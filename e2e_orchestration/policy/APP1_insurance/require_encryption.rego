package terraform.insurance.encryption

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# METADATA
# title: Require Encryption at Rest and in Transit
# description: Enforces encryption for all data storage and transmission
# custom:
#   severity: critical
#   compliance: ["HIPAA 164.312(a)(2)(iv)", "HIPAA 164.312(e)(1)", "PCI-DSS 3.4", "PCI-DSS 4.1"]
#   remediation: "Enable encryption at rest and require TLS 1.2+ for all connections"

# Deny S3 buckets without encryption
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    not has_encryption(resource)
    
    msg := sprintf(
        "CRITICAL: S3 bucket '%s' does not have encryption at rest enabled. This violates HIPAA 164.312(a)(2)(iv) and PCI-DSS 3.4. Enable server_side_encryption_configuration with AES256 or aws:kms.",
        [resource.name]
    )
}

# Deny EBS volumes without encryption
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_ebs_volume"
    not resource.change.after.encrypted
    
    msg := sprintf(
        "CRITICAL: EBS volume '%s' is not encrypted. This violates HIPAA 164.312(a)(2)(iv). Set encrypted = true.",
        [resource.name]
    )
}

# Deny RDS instances without encryption
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    not resource.change.after.storage_encrypted
    
    msg := sprintf(
        "CRITICAL: RDS instance '%s' does not have storage encryption enabled. This violates HIPAA 164.312(a)(2)(iv) and PCI-DSS 3.4. Set storage_encrypted = true.",
        [resource.name]
    )
}

# Deny load balancers without TLS
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_lb_listener"
    resource.change.after.protocol == "HTTP"
    
    msg := sprintf(
        "CRITICAL: Load balancer listener '%s' uses HTTP instead of HTTPS. This violates HIPAA 164.312(e)(1) and PCI-DSS 4.1. Use protocol = 'HTTPS' with valid SSL certificate.",
        [resource.name]
    )
}

# Deny TLS versions below 1.2
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_lb_listener"
    
    policy := resource.change.after.ssl_policy
    not is_secure_tls_policy(policy)
    
    msg := sprintf(
        "HIGH: Load balancer listener '%s' uses insecure TLS policy '%s'. This violates PCI-DSS 4.1. Use ELBSecurityPolicy-TLS-1-2-2017-01 or later.",
        [resource.name, policy]
    )
}

# Deny ElastiCache without encryption in transit
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_elasticache_replication_group"
    not resource.change.after.transit_encryption_enabled
    
    msg := sprintf(
        "HIGH: ElastiCache replication group '%s' does not have transit encryption enabled. This violates HIPAA 164.312(e)(1). Set transit_encryption_enabled = true.",
        [resource.name]
    )
}

# Deny ElastiCache without encryption at rest
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_elasticache_replication_group"
    not resource.change.after.at_rest_encryption_enabled
    
    msg := sprintf(
        "HIGH: ElastiCache replication group '%s' does not have at-rest encryption enabled. This violates HIPAA 164.312(a)(2)(iv). Set at_rest_encryption_enabled = true.",
        [resource.name]
    )
}

# Deny SNS topics without encryption
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_sns_topic"
    not resource.change.after.kms_master_key_id
    
    msg := sprintf(
        "MEDIUM: SNS topic '%s' does not have KMS encryption enabled. Enable kms_master_key_id for sensitive notifications.",
        [resource.name]
    )
}

# Deny SQS queues without encryption
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_sqs_queue"
    not resource.change.after.kms_master_key_id
    
    msg := sprintf(
        "MEDIUM: SQS queue '%s' does not have KMS encryption enabled. Enable kms_master_key_id for sensitive messages.",
        [resource.name]
    )
}

# Deny Kubernetes secrets without etcd encryption
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "kubernetes_secret"
    contains(lower(resource.name), "patient") or
    contains(lower(resource.name), "medical") or
    contains(lower(resource.name), "phi")
    
    msg := sprintf(
        "HIGH: Kubernetes Secret '%s' contains PHI. Ensure etcd encryption at rest is enabled at cluster level. This is required by HIPAA 164.312(a)(2)(iv).",
        [resource.name]
    )
}

# Helper functions
has_encryption(resource) {
    resource.change.after.server_side_encryption_configuration != null
}

has_encryption(resource) {
    resource.change.after.server_side_encryption_configuration[_].rule[_].apply_server_side_encryption_by_default != null
}

is_secure_tls_policy(policy) {
    secure_policies := [
        "ELBSecurityPolicy-TLS-1-2-2017-01",
        "ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
        "ELBSecurityPolicy-FS-1-2-2019-08",
        "ELBSecurityPolicy-FS-1-2-Res-2019-08",
        "ELBSecurityPolicy-TLS13-1-2-2021-06"
    ]
    
    policy == secure_policies[_]
}

# Test cases
test_deny_unencrypted_s3 {
    deny[msg] with input as {
        "resource_changes": [{
            "type": "aws_s3_bucket",
            "name": "patient-documents",
            "change": {
                "after": {
                    "bucket": "patient-documents"
                }
            }
        }]
    }
    
    contains(msg, "CRITICAL")
    contains(msg, "encryption")
}

test_deny_http_listener {
    deny[msg] with input as {
        "resource_changes": [{
            "type": "aws_lb_listener",
            "name": "web-listener",
            "change": {
                "after": {
                    "protocol": "HTTP",
                    "port": 80
                }
            }
        }]
    }
    
    contains(msg, "CRITICAL")
    contains(msg, "HTTP")
}

test_allow_encrypted_s3 {
    count(deny) == 0 with input as {
        "resource_changes": [{
            "type": "aws_s3_bucket",
            "name": "patient-documents",
            "change": {
                "after": {
                    "bucket": "patient-documents",
                    "server_side_encryption_configuration": [{
                        "rule": [{
                            "apply_server_side_encryption_by_default": {
                                "sse_algorithm": "aws:kms",
                                "kms_master_key_id": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
                            }
                        }]
                    }]
                }
            }
        }]
    }
}
