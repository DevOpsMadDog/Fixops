# FixOps Non-Functional Requirements

## Document Information
- **Version**: 1.0.0
- **Last Updated**: 2024-11-21
- **Status**: Draft

## 1. Performance Requirements

### 1.1 Response Time
- **API Endpoints**:
  - List operations: < 200ms (p95)
  - Create/Update operations: < 500ms (p95)
  - Complex queries (search, analytics): < 1s (p95)
  - Pipeline execution: < 30s for standard workload
  
- **CLI Commands**:
  - List operations: < 1s
  - Create/Update operations: < 2s
  - Search operations: < 3s

### 1.2 Throughput
- **Concurrent Requests**: Support 100 concurrent API requests
- **Rate Limiting**: 60 requests/minute per API key (configurable)
- **Burst Capacity**: 10 requests immediate burst, then rate limit

### 1.3 Resource Utilization
- **Memory**: < 2GB per worker process under normal load
- **CPU**: < 1 core per worker under normal load
- **Database**: < 10GB for 10,000 applications with full history
- **Evidence Storage**: ~100MB per 1,000 decisions

## 2. Scalability Requirements

### 2.1 Data Volume
- **Applications**: Support 10,000+ applications without degradation
- **Services**: Support 50,000+ microservices
- **API Endpoints**: Support 100,000+ API endpoint registrations
- **CVEs**: Support 300,000+ CVE records (current EPSS catalog size)
- **Findings**: Support 1M+ security findings

### 2.2 User Load
- **Concurrent Users**: Support 100+ concurrent users
- **API Clients**: Support 50+ concurrent API clients
- **CLI Sessions**: Support 20+ concurrent CLI sessions

### 2.3 Horizontal Scaling
- **Stateless Design**: API services must be stateless for horizontal scaling
- **Database Sharding**: Support for database read replicas
- **Cache Layer**: Redis for session and frequently accessed data

## 3. Reliability Requirements

### 3.1 Availability
- **Uptime Target**: 99.9% (8.76 hours downtime/year)
- **Planned Maintenance Windows**: < 4 hours/month
- **Recovery Time Objective (RTO)**: < 1 hour
- **Recovery Point Objective (RPO)**: < 15 minutes

### 3.2 Fault Tolerance
- **Database Failures**: Automatic failover to replica
- **API Service Failures**: Health checks with automatic restart
- **External Service Failures**: Graceful degradation (LLM fallback to deterministic mode)
- **Rate Limit Failures**: Circuit breaker pattern for external APIs

### 3.3 Data Integrity
- **ACID Transactions**: All database operations transactional
- **Checksums**: SHA256 for all artifacts and evidence bundles
- **Backup**: Daily automated backups with 30-day retention
- **Evidence Signing**: RSA-SHA256 cryptographic signing for non-repudiation

## 4. Security Requirements

### 4.1 Authentication
- **API Key Management**: 256-bit random keys with bcrypt hashing
- **JWT Tokens**: RS256 signing with 2-hour expiration
- **Key Rotation**: Support for seamless key rotation
- **MFA**: (Future) Multi-factor authentication for sensitive operations

### 4.2 Authorization
- **RBAC**: Role-based access control with 4 roles (admin, security_analyst, developer, viewer)
- **Principle of Least Privilege**: Default deny, explicit allow
- **Audit Trail**: All access logged with user, timestamp, action
- **Team-Based Access**: Users can be organized into teams for collaborative work

### 4.3 Data Protection
- **Encryption at Rest**: Evidence bundles encrypted with Fernet (AES-128)
- **Encryption in Transit**: TLS 1.3 for all API communications
- **Secrets Management**: Environment variables, never in code or logs
- **Sensitive Data Redaction**: API keys, tokens redacted in logs

### 4.4 Security Headers
- **X-Content-Type-Options**: nosniff
- **X-Frame-Options**: DENY
- **X-XSS-Protection**: 1; mode=block
- **Strict-Transport-Security**: max-age=31536000; includeSubDomains
- **Content-Security-Policy**: default-src 'self'

### 4.5 Vulnerability Management
- **Dependency Scanning**: Automated scanning on every PR
- **SAST**: Static analysis with flake8, mypy, bandit
- **Secrets Detection**: Pre-commit hooks to prevent secrets in commits
- **CVE Monitoring**: Automated alerts for vulnerable dependencies

## 5. Maintainability Requirements

### 5.1 Code Quality
- **Test Coverage**: > 80% line coverage
- **Type Hints**: 100% of public APIs
- **Linting**: Black, isort, flake8 passing on all code
- **Documentation**: All public functions documented with docstrings

### 5.2 Logging
- **Structured Logging**: JSON format with consistent fields
- **Log Levels**: DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Correlation IDs**: UUID per request for distributed tracing
- **Sensitive Data**: Never log secrets, tokens, or PII

### 5.3 Monitoring
- **Metrics**: Prometheus-compatible metrics
- **Health Checks**: /health and /ready endpoints
- **Error Tracking**: Sentry or equivalent for error aggregation
- **Performance Profiling**: APM integration for bottleneck identification

### 5.4 Deployment
- **Automated CI/CD**: GitHub Actions for all deployments
- **Canary Deployments**: Gradual rollout with automated rollback
- **Blue-Green Deployments**: Zero-downtime deployments
- **Database Migrations**: Alembic for schema versioning

## 6. Usability Requirements

### 6.1 API Design
- **RESTful Conventions**: Standard HTTP methods and status codes
- **Consistent Naming**: snake_case for JSON, kebab-case for URLs
- **Pagination**: Offset-based with total count
- **Error Messages**: Descriptive with actionable guidance

### 6.2 CLI Design
- **Intuitive Commands**: Verb-noun pattern (e.g., `inventory list`)
- **Help Text**: Comprehensive --help for all commands
- **Output Formats**: JSON and human-readable table formats
- **Exit Codes**: 0 for success, 1 for errors, 2 for usage errors

### 6.3 Documentation
- **API Documentation**: OpenAPI/Swagger with examples
- **CLI Documentation**: Man pages and online guides
- **Architecture Diagrams**: Mermaid or PlantUML diagrams
- **Runbooks**: Step-by-step guides for common operations

## 7. Compatibility Requirements

### 7.1 Platform Support
- **Operating Systems**: Linux (Ubuntu 20.04+), macOS 12+
- **Python Versions**: 3.10, 3.11, 3.12
- **Browsers** (Future UI): Chrome 90+, Firefox 88+, Safari 14+

### 7.2 API Versioning
- **Version in URL**: /api/v1/, /api/v2/
- **Backward Compatibility**: Minimum 12 months for deprecated endpoints
- **Deprecation Warnings**: HTTP headers for deprecated features

### 7.3 Data Formats
- **Input**: JSON, SARIF, CycloneDX SBOM, SPDX, CSV
- **Output**: JSON (default), CSV, SARIF, PDF (reports)
- **Timestamps**: ISO8601 with UTC timezone
- **UUIDs**: Version 4 (random)

## 8. Compliance Requirements

### 8.1 Regulatory Standards
- **SOC2 Type II**: Annual audit with evidence retention
- **ISO 27001**: Information security management
- **PCI-DSS**: Payment card data security (if applicable)
- **GDPR**: EU data protection (user data handling)

### 8.2 Audit Requirements
- **Audit Logs**: 7-year retention for compliance evidence
- **Tamper-Evident**: Cryptographic signing of evidence bundles
- **Access Logs**: Who accessed what, when, from where
- **Change Logs**: All configuration changes tracked

### 8.3 Data Residency
- **Regional Deployment**: Support for EU, US, APAC regions
- **Data Transfer**: Encrypted inter-region transfers
- **Data Deletion**: GDPR right-to-erasure compliance

## 9. Capacity Planning

### 9.1 Growth Projections
- **Year 1**: 1,000 applications, 10,000 findings/month
- **Year 2**: 5,000 applications, 50,000 findings/month
- **Year 3**: 10,000 applications, 100,000 findings/month

### 9.2 Storage Requirements
- **Database**: 1GB/1000 applications (with full history)
- **Evidence Storage**: 10MB/1000 decisions
- **Logs**: 100MB/day (compressed)

### 9.3 Network Bandwidth
- **Ingress**: 100GB/month for artifact uploads
- **Egress**: 50GB/month for evidence downloads
- **API Traffic**: 10M requests/month

## 10. Disaster Recovery

### 10.1 Backup Strategy
- **Frequency**: Daily full backups, hourly incremental
- **Retention**: 30 days rolling, 12 monthly snapshots, 7 annual
- **Location**: Multi-region with 3-2-1 rule (3 copies, 2 media, 1 offsite)

### 10.2 Recovery Procedures
- **Database Restore**: < 2 hours for full restore
- **Evidence Restore**: < 1 hour for specific bundle
- **Configuration Restore**: < 30 minutes
- **Disaster Recovery Drills**: Quarterly testing

## 11. Performance Benchmarks

### 11.1 API Latency (p95)
- GET /api/v1/inventory/applications: < 200ms
- POST /api/v1/inventory/applications: < 500ms
- GET /api/v1/inventory/search: < 1s
- POST /api/v1/pipeline/run: < 30s

### 11.2 Database Query Performance
- Simple SELECT: < 10ms
- Complex JOIN: < 100ms
- Full-text search: < 500ms
- Aggregation queries: < 2s

### 11.3 CLI Performance
- fixops inventory list: < 1s
- fixops inventory create: < 2s
- fixops users list: < 1s
- fixops teams list: < 1s
- fixops policies list: < 1s
- fixops analytics dashboard: < 2s
- fixops analytics findings: < 1s
- fixops integrations list: < 1s
- fixops demo: < 60s
- fixops pipeline run: < 90s

## 12. Success Metrics

### 12.1 Key Performance Indicators (KPIs)
- **API Response Time**: p95 < 500ms
- **Error Rate**: < 0.1% of requests
- **Uptime**: > 99.9%
- **Test Coverage**: > 80%
- **Security Scan**: 0 critical vulnerabilities

### 12.2 User Satisfaction
- **CLI Usability**: > 4.5/5 user rating
- **API Documentation**: > 4.0/5 completeness rating
- **Support Response Time**: < 24 hours for critical issues

## 13. Phase 3 Specific Requirements

### 13.1 Analytics Performance
- **Dashboard Overview**: < 500ms for aggregated metrics
- **Trend Queries**: < 1s for 30-day time series
- **Top Risks Calculation**: < 300ms for top 10 risks
- **MTTR Calculation**: < 200ms for mean time to remediation
- **Custom Queries**: < 2s for complex aggregations

### 13.2 Analytics Data Retention
- **Findings**: 2 years of historical data
- **Decisions**: 2 years of decision history
- **Metrics**: 1 year of time-series metrics
- **Aggregated Data**: 5 years of monthly summaries

### 13.3 Integration Management
- **Connection Testing**: < 5s timeout for external service tests
- **Sync Operations**: < 30s for full integration sync
- **Retry Logic**: 3 retries with exponential backoff
- **Circuit Breaker**: Open after 5 consecutive failures

### 13.4 Analytics Scalability
- **Findings Volume**: Support 1M+ findings without degradation
- **Decisions Volume**: Support 500K+ decisions
- **Metrics Volume**: Support 10M+ metric data points
- **Query Performance**: Maintain < 1s response time at scale

### 13.5 Integration Security
- **Secret Storage**: Integration credentials encrypted at rest
- **Secret Redaction**: Secrets never returned in API responses (unless explicitly requested with proper auth)
- **Connection Validation**: All integration configs validated before storage
- **Audit Logging**: All integration operations logged with user context

## 14. Phase 4 Specific Requirements

### 14.1 Report Generation Performance
- **Report Generation**: < 10s for standard reports (security summary, compliance)
- **Large Reports**: < 30s for reports with >1000 findings
- **PDF Generation**: < 5s for PDF rendering
- **HTML Generation**: < 2s for HTML rendering
- **CSV Export**: < 3s for CSV generation
- **SARIF Export**: < 5s for SARIF 2.1.0 export

### 14.2 Report Storage & Retention
- **Report Files**: 90 days retention for generated reports
- **Report Metadata**: 2 years retention for report records
- **Scheduled Reports**: Indefinite retention for schedules
- **Report Templates**: Version-controlled with change history
- **File Size Limits**: 100MB max per report file

### 14.3 Report Scheduling
- **Cron Validation**: Validate cron expressions before accepting
- **Schedule Execution**: < 1 minute deviation from scheduled time
- **Concurrent Reports**: Support 10 concurrent report generations
- **Retry Logic**: 3 retries with exponential backoff for failed generations
- **Email Delivery**: < 5 minutes for report email delivery (when implemented)

### 14.4 Audit Log Performance
- **Log Ingestion**: < 50ms to write audit log entry
- **Log Query**: < 500ms for filtered audit log queries
- **User Activity**: < 300ms to retrieve user activity logs
- **Decision Trail**: < 1s for decision audit trail queries
- **Bulk Export**: < 10s to export 10,000 audit logs

### 14.5 Audit Log Retention
- **Audit Logs**: 7 years retention for compliance
- **User Activity**: 2 years retention for user actions
- **Policy Changes**: 5 years retention for policy modifications
- **Decision Trail**: 3 years retention for decision history
- **Compliance Events**: 7 years retention for compliance-related events

### 14.6 Audit Log Security
- **Immutability**: Audit logs cannot be modified or deleted
- **Integrity**: Cryptographic hashing for audit log integrity
- **Access Control**: Audit logs only accessible by admin and security_analyst roles
- **Sensitive Data**: PII and secrets redacted in audit logs
- **Tamper Detection**: Alert on any attempted audit log tampering

### 14.7 Compliance Framework Support
- **Framework Coverage**: Support 5+ major frameworks (NIST 800-53, ISO 27001, PCI-DSS, SOC2, HIPAA)
- **Control Mapping**: < 100ms to retrieve control mappings
- **Gap Analysis**: < 2s to calculate compliance gaps
- **Status Calculation**: < 1s to calculate framework compliance percentage
- **Report Generation**: < 15s to generate compliance report

### 14.8 Workflow Performance
- **Workflow Execution**: < 5s for simple workflows (1-3 steps)
- **Complex Workflows**: < 30s for workflows with 10+ steps
- **Workflow Creation**: < 500ms to create workflow
- **Workflow Update**: < 500ms to update workflow
- **History Query**: < 1s to retrieve workflow execution history

### 14.9 Workflow Scalability
- **Concurrent Executions**: Support 50 concurrent workflow executions
- **Workflow Volume**: Support 1,000+ workflows without degradation
- **Execution History**: Retain 10,000+ executions per workflow
- **Step Complexity**: Support workflows with up to 50 steps
- **Trigger Evaluation**: < 100ms to evaluate workflow triggers

### 14.10 Workflow Reliability
- **Execution Success Rate**: > 99% successful executions
- **Error Handling**: Graceful failure with detailed error messages
- **Retry Logic**: Configurable retry with exponential backoff
- **Timeout Protection**: Configurable timeouts per workflow step
- **State Persistence**: Workflow state persisted for recovery

### 14.11 CLI Performance (Phase 4)
- **fixops reports list**: < 1s
- **fixops reports generate**: < 15s (includes generation time)
- **fixops reports get**: < 500ms
- **fixops audit logs**: < 1s
- **fixops audit frameworks**: < 500ms
- **fixops audit controls**: < 1s
- **fixops workflows list**: < 1s
- **fixops workflows create**: < 2s
- **fixops workflows execute**: < 10s (includes execution time)
- **fixops workflows history**: < 1s

### 14.12 Data Integrity
- **Report Checksums**: SHA-256 checksums for all generated reports
- **Audit Log Hashing**: Cryptographic hashing for audit log chains
- **Workflow State**: Atomic state transitions with rollback capability
- **Database Transactions**: ACID compliance for all database operations
- **Backup Verification**: Monthly verification of backup integrity
