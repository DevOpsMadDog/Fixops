# APP1: Insurance Quote Platform - Threat & Attack Matrix

## STRIDE Analysis

### Spoofing
| Threat | Attack Vector | Affected Component | Mitigation | Test |
|--------|--------------|-------------------|------------|------|
| User impersonation | Stolen JWT tokens | auth-service | Short-lived tokens, refresh rotation, MFA | JWT expiration test, token theft simulation |
| API key spoofing | Hardcoded Stripe key in logs | payment-service | Secrets management, log sanitization | Secret scanning test |
| Database credential theft | Weak password policy | customers-db | Strong passwords, certificate auth, rotation | Credential strength test |

### Tampering
| Threat | Attack Vector | Affected Component | Mitigation | Test |
|--------|--------------|-------------------|------------|------|
| SQL injection | Unsanitized input in quote queries | quote-service | Parameterized queries, ORM | SQL injection fuzzing |
| Prototype pollution | lodash 4.17.20 vulnerability | quote-service | Upgrade to 4.17.21, input validation | Prototype pollution exploit test |
| Medical record modification | Insufficient access controls | customers-db | Row-level security, audit logging | Unauthorized modification test |

### Repudiation
| Threat | Attack Vector | Affected Component | Mitigation | Test |
|--------|--------------|-------------------|------------|------|
| Quote manipulation denial | Missing audit logs | quote-service | Comprehensive audit logging, immutable logs | Audit log completeness test |
| Payment dispute | Insufficient transaction logging | payment-service | Stripe webhook logging, reconciliation | Transaction audit test |

### Information Disclosure
| Threat | Attack Vector | Affected Component | Mitigation | Test |
|--------|--------------|-------------------|------------|------|
| PII/PHI exposure | Public database service | customers-db | VPC isolation, private subnets | Network exposure scan |
| SSN leakage | Insufficient encryption | customers-db | Encryption at rest, field-level encryption | Encryption validation test |
| Medical history exposure | Overly permissive CORS | api | Strict CORS policy, origin validation | CORS policy test |

### Denial of Service
| Threat | Attack Vector | Affected Component | Mitigation | Test |
|--------|--------------|-------------------|------------|------|
| Quote API flooding | No rate limiting | quote-service | Rate limiting, WAF | Load test, rate limit validation |
| Database connection exhaustion | Connection pool misconfiguration | customers-db | Connection pooling, timeouts | Connection pool stress test |
| HTTP/2 rapid reset | CVE-2023-44487 in Node.js | api | Upgrade Node.js, HTTP/2 limits | HTTP/2 attack simulation |

### Elevation of Privilege
| Threat | Attack Vector | Affected Component | Mitigation | Test |
|--------|--------------|-------------------|------------|------|
| Admin access via JWT bypass | CVE-2024-7348 in jsonwebtoken | auth-service | Upgrade JWT library, signature validation | JWT bypass test |
| Database privilege escalation | Overprivileged IAM role | customers-db | Least privilege IAM, role separation | IAM privilege test |
| Container escape | Privileged containers | infra | Non-root containers, security contexts | Container security scan |

## LINDDUN Analysis

### Linkability
| Privacy Threat | Attack Vector | Data at Risk | Mitigation | Test |
|----------------|--------------|--------------|------------|------|
| Cross-quote correlation | User ID in logs | Quote history, medical conditions | Pseudonymization, log minimization | Log analysis test |
| Session tracking | Persistent session IDs | User behavior patterns | Session rotation, short lifetimes | Session tracking test |

### Identifiability
| Privacy Threat | Attack Vector | Data at Risk | Mitigation | Test |
|----------------|--------------|--------------|------------|------|
| PII in error messages | Verbose error responses | SSN, DOB, medical history | Generic error messages, sanitization | Error message scan |
| Medical record re-identification | Insufficient anonymization | Patient medical history | K-anonymity, differential privacy | Re-identification test |

### Non-repudiation
| Privacy Threat | Attack Vector | Data at Risk | Mitigation | Test |
|----------------|--------------|--------------|------------|------|
| Excessive audit logging | Detailed user activity logs | User behavior, medical queries | Log retention policies, anonymization | Audit log review |

### Detectability
| Privacy Threat | Attack Vector | Data at Risk | Mitigation | Test |
|----------------|--------------|--------------|------------|------|
| Medical condition inference | Quote amount patterns | Health status | Noise injection, range bucketing | Pattern analysis test |
| High-risk customer detection | Quote rejection patterns | Medical conditions | Uniform response times, generic messages | Timing analysis test |

### Disclosure of Information
| Privacy Threat | Attack Vector | Data at Risk | Mitigation | Test |
|----------------|--------------|--------------|------------|------|
| Database backup exposure | Unencrypted S3 backups | All PII/PHI | Backup encryption, access controls | Backup security test |
| CloudWatch log exposure | PII in application logs | SSN, medical history | Log sanitization, encryption | Log content scan |

### Unawareness
| Privacy Threat | Attack Vector | Data at Risk | Mitigation | Test |
|----------------|--------------|--------------|------------|------|
| Unclear data usage | Missing privacy notices | User consent | Privacy policy, consent management | Consent flow test |
| Third-party data sharing | Stripe integration | Payment information | Data processing agreements, transparency | Third-party audit |

### Non-compliance
| Privacy Threat | Regulation | Requirement | Current Gap | Remediation |
|----------------|-----------|-------------|-------------|-------------|
| HIPAA violation | 164.312(a)(2)(iv) | Encryption at rest | RDS not encrypted | Enable RDS encryption |
| PCI-DSS violation | Req-3.4 | Secure key storage | Hardcoded Stripe key | Move to Secrets Manager |
| SOC2 violation | CC6.1 | Logical access controls | Public database | VPC isolation, security groups |

## Attack Scenarios (Backtesting)

### Scenario 1: Log4Shell-style RCE (Dec 2021)
- **Vulnerability**: CVE-2025-0001 (pg RCE) similar to Log4Shell
- **Attack**: Malicious SQL query triggers RCE in PostgreSQL driver
- **Impact**: Full database compromise, PII/PHI exfiltration
- **Detection**: FixOps KEV correlation, EPSS score 0.89
- **Remediation**: Emergency patch to pg@8.11.3, WAF rules

### Scenario 2: Stripe API Key Exposure (Jun 2023)
- **Vulnerability**: Hardcoded credentials in source code
- **Attack**: GitHub repository leak exposes production Stripe key
- **Impact**: Unauthorized payment processing, financial fraud
- **Detection**: FixOps SAST scan, secret detection
- **Remediation**: Key rotation, Secrets Manager migration

### Scenario 3: SQL Injection via Quote Form (Mar 2024)
- **Vulnerability**: Unsanitized input in quote-service
- **Attack**: SQL injection via quote form parameters
- **Impact**: Database access, PII/PHI extraction
- **Detection**: FixOps SARIF correlation with design context
- **Remediation**: Parameterized queries, input validation

### Scenario 4: HIPAA Breach via Public Database (Aug 2024)
- **Vulnerability**: PostgreSQL exposed via LoadBalancer
- **Attack**: Internet scan discovers public database port
- **Impact**: HIPAA breach, regulatory fines, reputation damage
- **Detection**: FixOps CNAPP findings, compliance mapping
- **Remediation**: VPC isolation, security group lockdown

## Compliance Control Mapping

| Control Framework | Control ID | Requirement | Implementation | Evidence |
|-------------------|-----------|-------------|----------------|----------|
| HIPAA | 164.312(a)(1) | Access control | IAM, RBAC, MFA | IAM policies, audit logs |
| HIPAA | 164.312(a)(2)(iv) | Encryption at rest | RDS encryption | Encryption status |
| PCI-DSS | Req-3.4 | Protect stored cardholder data | Tokenization, encryption | Stripe integration |
| PCI-DSS | Req-6.2 | Security patches | Vulnerability management | Patch status |
| SOC2 | CC6.1 | Logical access controls | Authentication, authorization | Access control tests |
| SOC2 | CC7.2 | System monitoring | Logging, alerting | CloudWatch logs |
| ISO27001 | A.9.2.3 | User access management | IAM, least privilege | Access reviews |
| ISO27001 | A.13.1.3 | Network segregation | VPC, security groups | Network diagram |

## Test Coverage Matrix

| Threat Category | Test Type | Tool | Coverage | Pass Criteria |
|----------------|-----------|------|----------|---------------|
| Spoofing | JWT validation | Custom script | 100% | All expired/invalid tokens rejected |
| Tampering | SQL injection | SQLMap | 100% | No successful injections |
| Repudiation | Audit logging | Log analysis | 100% | All actions logged |
| Information Disclosure | Network scan | Nmap | 100% | No public database ports |
| DoS | Load testing | k6 | 100% | Rate limits enforced |
| Privilege Escalation | IAM audit | AWS IAM Access Analyzer | 100% | Least privilege validated |
| Privacy | PII detection | Custom scanner | 100% | No PII in logs |
