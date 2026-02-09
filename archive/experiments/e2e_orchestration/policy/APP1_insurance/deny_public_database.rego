package terraform.insurance.database

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# METADATA
# title: Deny Public Database Exposure
# description: Prevents PostgreSQL and other databases from being exposed to the internet
# custom:
#   severity: critical
#   compliance: ["HIPAA 164.312(a)(1)", "SOC2 CC6.1", "PCI-DSS 1.3"]
#   remediation: "Restrict security group ingress to VPC CIDR blocks only"

# Deny databases exposed via LoadBalancer
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "kubernetes_service"
    resource.change.after.spec[_].type == "LoadBalancer"
    contains(lower(resource.name), "db")
    
    msg := sprintf(
        "CRITICAL: Database service '%s' exposed via LoadBalancer. This violates HIPAA 164.312(a)(1). Use ClusterIP and restrict access via NetworkPolicy.",
        [resource.name]
    )
}

# Deny RDS instances without encryption
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    not resource.change.after.storage_encrypted
    
    msg := sprintf(
        "CRITICAL: RDS instance '%s' does not have encryption at rest enabled. This violates HIPAA 164.312(a)(2)(iv) and PCI-DSS 3.4. Enable storage_encrypted = true.",
        [resource.name]
    )
}

# Deny security groups allowing 0.0.0.0/0 on database ports
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    rule := resource.change.after.ingress[_]
    
    # Check for common database ports
    db_ports := [5432, 3306, 1433, 27017, 6379]
    rule.from_port in db_ports
    
    # Check for public access
    cidr := rule.cidr_blocks[_]
    cidr == "0.0.0.0/0"
    
    msg := sprintf(
        "CRITICAL: Security group '%s' allows public access (0.0.0.0/0) on database port %d. This violates HIPAA 164.312(e)(1) and SOC2 CC6.1. Restrict to VPC CIDR only.",
        [resource.name, rule.from_port]
    )
}

# Deny RDS instances in public subnets
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    resource.change.after.publicly_accessible == true
    
    msg := sprintf(
        "CRITICAL: RDS instance '%s' has publicly_accessible = true. This violates HIPAA 164.312(a)(1). Set publicly_accessible = false and use VPN/bastion for access.",
        [resource.name]
    )
}

# Deny databases without backup retention
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    resource.change.after.backup_retention_period < 7
    
    msg := sprintf(
        "HIGH: RDS instance '%s' has backup retention period of %d days (< 7 days required). This violates SOC2 CC9.1 and HIPAA 164.308(a)(7)(ii)(A). Set backup_retention_period >= 7.",
        [resource.name, resource.change.after.backup_retention_period]
    )
}

# Deny PostgreSQL without SSL enforcement
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    resource.change.after.engine == "postgres"
    
    # Check if SSL is not enforced
    params := resource.change.after.parameter_group_name
    not contains(params, "ssl")
    
    msg := sprintf(
        "HIGH: PostgreSQL instance '%s' does not enforce SSL connections. This violates HIPAA 164.312(e)(1) and PCI-DSS 4.1. Create parameter group with rds.force_ssl = 1.",
        [resource.name]
    )
}

# Warn about databases without automated patching
warn[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    resource.change.after.auto_minor_version_upgrade == false
    
    msg := sprintf(
        "MEDIUM: RDS instance '%s' has auto_minor_version_upgrade disabled. This increases vulnerability exposure. Enable automated patching for security updates.",
        [resource.name]
    )
}

# Deny databases without monitoring
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    resource.change.after.enabled_cloudwatch_logs_exports == null
    
    msg := sprintf(
        "MEDIUM: RDS instance '%s' does not export logs to CloudWatch. This violates SOC2 CC7.2 and HIPAA 164.312(b). Enable postgresql, upgrade logs.",
        [resource.name]
    )
}

# Deny databases in default VPC
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    contains(resource.change.after.db_subnet_group_name, "default")
    
    msg := sprintf(
        "HIGH: RDS instance '%s' is in default VPC/subnet group. This violates security best practices. Create dedicated VPC with private subnets.",
        [resource.name]
    )
}

# Test cases for policy validation
test_deny_public_database {
    deny[msg] with input as {
        "resource_changes": [{
            "type": "aws_security_group",
            "name": "patients-db-sg",
            "change": {
                "after": {
                    "ingress": [{
                        "from_port": 5432,
                        "to_port": 5432,
                        "cidr_blocks": ["0.0.0.0/0"]
                    }]
                }
            }
        }]
    }
    
    contains(msg, "CRITICAL")
    contains(msg, "0.0.0.0/0")
    contains(msg, "5432")
}

test_deny_unencrypted_rds {
    deny[msg] with input as {
        "resource_changes": [{
            "type": "aws_db_instance",
            "name": "patients-db",
            "change": {
                "after": {
                    "storage_encrypted": false
                }
            }
        }]
    }
    
    contains(msg, "CRITICAL")
    contains(msg, "encryption")
}

test_allow_secure_database {
    count(deny) == 0 with input as {
        "resource_changes": [{
            "type": "aws_db_instance",
            "name": "patients-db",
            "change": {
                "after": {
                    "storage_encrypted": true,
                    "publicly_accessible": false,
                    "backup_retention_period": 7,
                    "auto_minor_version_upgrade": true,
                    "enabled_cloudwatch_logs_exports": ["postgresql", "upgrade"]
                }
            }
        }]
    }
}
