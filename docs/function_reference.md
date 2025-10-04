# FixOps Enterprise Function Reference

## Module: `api.v1.business_context`
Business Context Integration API
Connects to Jira, Confluence, and other business systems

- Function `get_jira_context(ticket_id, current_user)`: Get business context from Jira ticket
- Function `get_confluence_context(page_id, current_user)`: Get threat model and requirements from Confluence
- Function `enrich_business_context(request, current_user)`: Enrich security findings with business context
- Function `_assess_business_impact(service_name)`: Assess business impact based on service name
- Function `_assess_data_sensitivity(service_name)`: Assess data sensitivity level
- Function `_get_compliance_requirements(service_name)`: Get applicable compliance requirements
- Function `_assess_stakeholder_impact(service_name, environment)`: Assess which stakeholders are impacted

## Module: `api.v1.business_context_enhanced`
Business Context API - FixOps YAML and OTM Support
Handles business context upload and SSVC conversion

- Function `upload_business_context(file, service_name, format_type)`: Upload business context in FixOps YAML or OTM format
- Function `get_sample_context(format_type, service_name)`: Get sample business context files for download
- Function `get_supported_formats()`: Get supported business context formats and their descriptions
- Function `validate_business_context(content, format_type)`: Validate business context without storing

## Module: `api.v1.cicd`
FixOps CI/CD Integration API
Optimized endpoints for CI/CD pipeline integration

- Class `CICDDecisionRequest`: Optimized request format for CI/CD pipelines
- Class `CICDDecisionResponse`: Optimized response format for CI/CD pipelines
- Function `make_cicd_decision(request, x_pipeline_id, x_correlation_id)`: Make security decision for CI/CD pipeline
- Function `_extract_sarif_findings(sarif_data)`: Extract security findings from SARIF format
- Function `_extract_sca_findings(sca_data)`: Extract findings from SCA tools (Snyk, etc.)
- Function `_extract_dast_findings(dast_data)`: Extract findings from DAST tools
- Function `_map_sarif_severity(level)`: Map SARIF severity levels
- Function `_map_dast_severity(risk_desc)`: Map DAST risk levels
- Function `_extract_sarif_location(result)`: Extract file location from SARIF result
- Function `_get_recommended_actions(decision_result)`: Get CI/CD recommended actions based on decision
- Function `_get_blocking_issues(decision_result, security_findings)`: Get specific issues that caused blocking
- Function `_get_compliance_status(decision_result)`: Get compliance status for bank requirements
- Function `_get_notification_requirements(decision_result, request)`: Determine notification requirements

## Module: `api.v1.decisions`
FixOps Decision & Verification API Endpoints
Provides decision engine operations and metrics

- Class `DecisionRequest`: No documentation provided.
- Class `DecisionResponse`: No documentation provided.
- Function `make_security_decision(request)`: Make a security decision based on context and intelligence
- Function `get_decision_metrics()`: Get decision engine performance metrics and status
- Function `get_recent_decisions(limit)`: Get recent pipeline decisions with full context
- Function `get_ssdlc_stage_data(current_user)`: Get SSDLC stage data ingestion status
- Function `get_core_components_status(current_user)`: Get Decision & Verification Core components status with real data
- Function `get_evidence_record(evidence_id, current_user)`: Get immutable evidence record from Evidence Lake

## Module: `api.v1.docs`
Serve documentation markdown files via API for easy linking from UI

- Function `get_doc(name)`: No documentation provided.

## Module: `api.v1.enhanced`
FixOps Enhanced API - Multi-LLM Decision Engine
Advanced security decision API with GPT-4, Claude, Gemini integration

- Class `EnhancedAnalysisModel`: No documentation provided.
- Class `EnhancedConsensus`: No documentation provided.
- Class `EnhancedStandardResponse`: No documentation provided.
- Class `EnhancedSignals`: No documentation provided.
- Class `EnhancedDecisionRequest`: No documentation provided.
- Function `enhanced_analysis_standard(request)`: Returns standardized multi-LLM analysis schema:
- Function `enhanced_signals(verdict, confidence)`: No documentation provided.
- Class `CapabilitiesResponse`: No documentation provided.
- Function `get_enhanced_capabilities()`: No documentation provided.
- Class `CompareLLMsRequest`: No documentation provided.
- Function `compare_llm_analyses(payload)`: No documentation provided.

## Module: `api.v1.feeds`
External feeds endpoints (EPSS, KEV) using FeedsService

- Function `feeds_status()`: No documentation provided.
- Function `epss_refresh()`: No documentation provided.
- Function `kev_refresh()`: No documentation provided.
- Function `download_feed(feed)`: No documentation provided.

## Module: `api.v1.marketplace`
FixOps Marketplace API (productionized stub)
Browse, purchase, contribute, update, download; file-backed persistence

- Function `_serialize_item(item)`: No documentation provided.
- Class `MarketplaceSearchRequest`: No documentation provided.
- Class `ContentContributionRequest`: No documentation provided.
- Class `RatingRequest`: No documentation provided.
- Function `browse_marketplace(content_type, compliance_frameworks, ssdlc_stages, pricing_model, organization_type, limit)`: No documentation provided.
- Function `get_recommendations(organization_type, compliance_requirements)`: No documentation provided.
- Function `contribute_content(contribution, file, author, organization)`: No documentation provided.
- Function `update_content(item_id, patch)`: No documentation provided.
- Function `rate_content(item_id, rating_request)`: No documentation provided.
- Function `purchase_content(item_id, purchaser, organization)`: No documentation provided.
- Function `download_content(token)`: No documentation provided.
- Function `get_contributors(author, organization, limit)`: No documentation provided.
- Function `get_stage_compliance_content(stage, frameworks)`: No documentation provided.
- Function `get_marketplace_stats()`: No documentation provided.

## Module: `api.v1.monitoring`
Monitoring and health check API endpoints

- Function `health_check()`: System health check
- Function `get_metrics(current_user)`: Get system metrics

## Module: `api.v1.oss_tools`
OSS Tools Integration API Endpoints

- Class `ScanRequest`: No documentation provided.
- Class `PolicyEvalRequest`: No documentation provided.
- Function `get_oss_status()`: Get status of all OSS tools
- Function `run_comprehensive_scan(request, background_tasks)`: Run comprehensive security scan using multiple OSS tools
- Function `run_trivy_scan(request)`: Run Trivy vulnerability scan
- Function `run_grype_scan(request)`: Run Grype vulnerability scan
- Function `verify_sigstore_signature(request, public_key)`: Verify container signatures using Sigstore
- Function `evaluate_policy(request)`: Evaluate security policy using OPA
- Function `list_policies()`: List available OPA policies
- Function `list_supported_tools()`: List all supported OSS tools and their capabilities

## Module: `api.v1.policy`
Policy evaluation endpoints for CI/CD gates (SSVC-aware)

- Class `GateRequest`: No documentation provided.
- Class `GateResponse`: No documentation provided.
- Function `evaluate_gate(req)`: No documentation provided.

## Module: `api.v1.processing_layer`
Processing Layer API endpoints for testing the architecture components

- Class `ProcessingRequest`: No documentation provided.
- Class `SSVCTestRequest`: No documentation provided.
- Function `get_processing_layer_status()`: Get status of Processing Layer components
- Function `test_bayesian_prior_mapping(request)`: Test Bayesian Prior Mapping component
- Function `test_markov_transitions()`: Test Markov Transition Matrix Builder component
- Function `test_ssvc_fusion(bayesian_request)`: Test SSVC + Probabilistic Fusion Logic component
- Function `test_sarif_vulnerability_handling()`: Test SARIF-Based Non-CVE Vulnerability Handling component
- Function `test_full_processing_pipeline(bayesian_request)`: Test the complete Processing Layer pipeline
- Function `get_missing_oss_status()`: Get status of missing OSS tools that were not initially implemented
- Function `test_missing_oss_tools()`: Test all the missing OSS tools with sample data

## Module: `api.v1.production_readiness`
Production Readiness API
Shows what's required to enable production mode functionality

- Function `get_production_readiness()`: Get detailed status of what's required for production mode
- Function `get_production_requirements()`: Get detailed production requirements with setup instructions

## Module: `api.v1.sample_data_demo`
End-to-End Sample Data Demo
Complete demonstration of FixOps process with real sample data
Shows data transformation at each stage

- Function `get_sample_data()`: Real sample data that would come from various security tools
- Function `run_complete_demo()`: Run complete end-to-end demo showing data transformation at each stage
- Function `_demo_input_parsing(sample_data)`: Stage 1: Input Layer - Parse SARIF/SBOM with OSS tools
- Function `_demo_processing_layer(sample_data)`: Stage 2: Processing Layer - All OSS components
- Function `_demo_decision_layer(sample_data)`: Stage 3: Decision Layer - Apply organization thresholds
- Function `_demo_output_layer(sample_data)`: Stage 4: Output Layer - Generate human explanations and evidence
- Function `_demo_cicd_integration()`: Stage 5: CI/CD Integration - Show pipeline integration

## Module: `api.v1.scans`
FixOps Enterprise - File Upload and Scan Ingestion API
Handles SARIF, SBOM, IBOM, CSV, JSON security scan files

- Function `upload_scan_file(file, service_name, environment, scan_type, db)`: Upload and process security scan files (single-shot, non-chunked)
- Function `init_chunked_upload(file_name, total_size, scan_type, service_name, environment)`: Initialize chunked upload
- Function `upload_chunk(upload_id, chunk_index, total_chunks, chunk)`: Upload a chunk
- Function `complete_chunked_upload(upload_id)`: Complete chunked upload and process file
- Function `_parse_ibom(content)`: Parse IBOM format
- Function `_parse_csv(content)`: Parse CSV format

## Module: `api.v1.system`
System status and diagnostics endpoints

- Function `system_status()`: No documentation provided.

## Module: `api.v1.system_mode`
System Mode Management API
Handles switching between demo and production modes

- Class `ModeToggleRequest`: No documentation provided.
- Class `ModeToggleResponse`: No documentation provided.
- Function `get_current_mode()`: Get current system mode and readiness status
- Function `toggle_system_mode(request)`: Toggle between demo and production modes
- Function `get_production_requirements()`: Get detailed production setup requirements

## Module: `cli.main`
FixOps Enterprise CLI - CI/CD Integration Tool
High-performance command-line interface for DevSecOps automation

- Class `FixOpsCLI`: FixOps CLI for CI/CD pipeline integration
  - Method `__init__(self)`: No documentation provided.
  - Method `initialize(self)`: Initialize CLI components
  - Method `cleanup(self)`: Cleanup resources
  - Method `ingest_scan_results(self, args)`: Ingest security scan results from CI/CD pipeline
  - Method `policy_check(self, args)`: Evaluate security policies for CI/CD gates
  - Method `make_decision(self, args)`: Make security decision for CI/CD pipeline
  - Method `get_evidence(self, args)`: Retrieve evidence record from Evidence Lake
  - Method `correlation_analysis(self, args)`: Analyze finding correlations for noise reduction
  - Method `health_check(self, args)`: Perform system health check for CI/CD monitoring
  - Method `_parse_sarif(self, sarif_content)`: Parse SARIF format scan results
  - Method `_get_or_create_service(self, service_name, environment, repository_url)`: Get or create service record
  - Method `_process_findings_batch(self, findings_data, service, scanner_type, scanner_name)`: Process a batch of findings for performance
  - Method `_create_policy_context(self, finding, service)`: Create policy context from finding and service
  - Method `_get_findings_for_fix_generation(self, **kwargs)`: Get findings for fix generation
  - Method `_get_findings_for_correlation(self, **kwargs)`: Get findings for correlation analysis
  - Method `_get_service_by_id(self, service_id)`: Get service by ID
  - Method `_generate_pr_patches(self, fixes, output_dir)`: Generate pull request patches from fixes
  - Method `_create_finding_from_data(self, finding_data)`: Create a SecurityFinding from finding data
- Function `create_parser()`: Create argument parser for CLI
- Function `main()`: Main CLI entry point with mode handling

## Module: `config.settings`
Enterprise configuration management with environment-based settings

- Class `Settings`: Application settings with enterprise security and performance configuration
  - Method `parse_list_fields(cls, v)`: No documentation provided.
- Function `get_settings()`: Get cached application settings

## Module: `core.exceptions`
Enterprise exception handling with security and compliance features

- Class `FixOpsException`: Base exception for FixOps application
  - Method `__init__(self, message, error_code, status_code, details)`: No documentation provided.
- Class `AuthenticationError`: Authentication related errors
  - Method `__init__(self, message, details)`: No documentation provided.
- Class `AuthorizationError`: Authorization related errors
  - Method `__init__(self, message, details)`: No documentation provided.
- Class `ValidationError`: Data validation errors
  - Method `__init__(self, message, details)`: No documentation provided.
- Class `NotFoundError`: Resource not found errors
  - Method `__init__(self, message, details)`: No documentation provided.
- Class `ConflictError`: Resource conflict errors
  - Method `__init__(self, message, details)`: No documentation provided.
- Class `RateLimitError`: Rate limiting errors
  - Method `__init__(self, message, details)`: No documentation provided.
- Class `ServiceUnavailableError`: Service unavailable errors
  - Method `__init__(self, message, details)`: No documentation provided.
- Class `DatabaseError`: Database related errors
  - Method `__init__(self, message, details)`: No documentation provided.
- Class `CacheError`: Cache related errors
  - Method `__init__(self, message, details)`: No documentation provided.
- Class `SecurityError`: Security related errors
  - Method `__init__(self, message, details)`: No documentation provided.
- Class `ComplianceError`: Compliance related errors
  - Method `__init__(self, message, details)`: No documentation provided.
- Function `log_exception_security_event(request, exception, user_id)`: Log security-relevant exceptions for monitoring
- Function `create_error_response(error_code, message, status_code, details, request_id)`: Create standardized error response
- Function `setup_exception_handlers(app)`: Setup global exception handlers for the FastAPI application
- Class `SecurityViolationDetector`: Detect potential security violations in exceptions
  - Method `is_suspicious_exception(cls, exception)`: Check if exception contains suspicious patterns
  - Method `extract_security_context(cls, exception, request)`: Extract security context from exception and request

## Module: `core.middleware`
Enterprise middleware for performance, security, and monitoring

- Class `PerformanceMiddleware`: Performance monitoring and optimization middleware
  - Method `dispatch(self, request, call_next)`: No documentation provided.
- Class `SecurityHeadersMiddleware`: Add enterprise security headers
  - Method `dispatch(self, request, call_next)`: No documentation provided.
- Class `RateLimitMiddleware`: Distributed rate limiting with Redis
  - Method `dispatch(self, request, call_next)`: No documentation provided.
  - Method `_get_client_ip(self, request)`: Extract client IP considering proxy headers
  - Method `_is_rate_limited(self, client_ip, path)`: Check if client is rate limited using sliding window
- Class `CompressionMiddleware`: Response compression for performance optimization
  - Method `dispatch(self, request, call_next)`: No documentation provided.
  - Method `_should_compress(self, request, response)`: Determine if response should be compressed
- Class `AuditLoggingMiddleware`: Enterprise audit logging for compliance
  - Method `dispatch(self, request, call_next)`: No documentation provided.
  - Method `_get_client_ip(self, request)`: Extract client IP for audit logging

## Module: `core.security`
Enterprise-grade security components with zero-trust architecture

- Class `SecurityManager`: Enterprise security manager with zero-trust principles
  - Method `initialize(cls)`: Initialize security components
  - Method `_get_encryption_key(cls)`: Get or generate encryption key for sensitive data
  - Method `encrypt_sensitive_data(cls, data)`: Encrypt sensitive data (PII, credentials, etc.)
  - Method `decrypt_sensitive_data(cls, encrypted_data)`: Decrypt sensitive data
- Class `PasswordManager`: Enterprise password management with advanced security
  - Method `hash_password(password)`: Hash password with bcrypt (enterprise-grade)
  - Method `verify_password(plain_password, hashed_password)`: Verify password against hash
  - Method `generate_secure_password(length)`: Generate cryptographically secure password
- Class `MFAManager`: Multi-Factor Authentication management
  - Method `setup_totp(user_id, user_email)`: Setup Time-based One-Time Password (TOTP) for user
  - Method `verify_totp(secret, code, valid_window)`: Verify TOTP code
  - Method `verify_backup_code(user_id, code)`: Verify backup code (one-time use)
- Class `JWTManager`: JWT token management with enterprise security
  - Method `create_access_token(data)`: Create JWT access token with security claims
  - Method `create_refresh_token(user_id)`: Create refresh token for token renewal
  - Method `verify_token(token)`: Verify and decode JWT token
- Class `RBACManager`: Role-Based Access Control management
  - Method `check_permission(cls, user_id, permission)`: Check if user has specific permission
  - Method `_get_user_roles(cls, user_id)`: Get user roles from database
- Function `get_current_user(credentials)`: Get current authenticated user from JWT token
- Function `require_permission(permission)`: Dependency factory to require specific permission

## Module: `db.migrations.__init__`

## Module: `db.migrations.env`
Alembic environment configuration for FixOps Enterprise

- Function `get_database_url()`: Get database URL from environment or config
- Function `run_migrations_offline()`: Run migrations in 'offline' mode.
- Function `do_run_migrations(connection)`: Run migrations with connection
- Function `run_async_migrations()`: Run migrations in async mode
- Function `run_migrations_online()`: Run migrations in 'online' mode.

## Module: `db.migrations.versions.001_initial_schema`
Initial database schema for FixOps Enterprise
Migration: 001

- Function `upgrade()`: Create initial enterprise schema
- Function `downgrade()`: Drop initial schema

## Module: `db.session`
Enterprise database session management with connection pooling and performance optimization

- Class `DatabaseManager`: Enterprise database manager with connection pooling and health monitoring
  - Method `initialize(cls)`: Initialize database engine with enterprise configuration
  - Method `_setup_event_handlers(cls)`: Setup database event handlers for monitoring and optimization
  - Method `get_session(cls)`: Get database session from pool
  - Method `get_session_context(cls)`: Get database session with automatic cleanup
  - Method `health_check(cls)`: Health check for database connectivity
  - Method `close(cls)`: Close database engine and cleanup connections
- Function `get_db()`: FastAPI dependency to get database session

## Module: `main`
FixOps Blended Enterprise Platform
Main application entry point with 299μs hot path optimization

- Function `lifespan(app)`: Application lifecycle management with proper startup/shutdown
- Function `warm_performance_caches()`: Pre-warm caches for hot path performance
- Function `health_check()`: Kubernetes liveness probe endpoint
- Function `readiness_check()`: Kubernetes readiness probe endpoint
- Function `prometheus_metrics()`: Prometheus metrics endpoint for bank monitoring
- Function `performance_tracking(request, call_next)`: Track performance metrics for all requests

## Module: `models.base`
Base model with common fields and enterprise patterns

- Class `BaseModel`: Base model with common enterprise fields and functionality
  - Method `to_dict(self)`: Convert model to dictionary for API responses
  - Method `update_from_dict(self, data)`: Update model from dictionary with validation
  - Method `get_table_name(cls)`: Get table name for this model
  - Method `__repr__(self)`: No documentation provided.
- Class `AuditMixin`: Mixin for enhanced audit logging
- Class `SoftDeleteMixin`: Mixin for soft delete functionality
  - Method `soft_delete(self, deleted_by)`: Perform soft delete
  - Method `restore(self)`: Restore from soft delete
- Class `EncryptedFieldMixin`: Mixin for handling encrypted sensitive fields
  - Method `set_encrypted_field(self, field_name, value)`: Set encrypted field using SecurityManager
  - Method `get_encrypted_field(self, field_name)`: Get decrypted field value

## Module: `models.base_sqlite`
SQLite-compatible base model with common fields and enterprise patterns

- Class `BaseModel`: Base model with common enterprise fields and functionality (SQLite compatible)
  - Method `to_dict(self)`: Convert model to dictionary for API responses
  - Method `update_from_dict(self, data)`: Update model from dictionary with validation
  - Method `get_table_name(cls)`: Get table name for this model
  - Method `__repr__(self)`: No documentation provided.
- Class `AuditMixin`: Mixin for enhanced audit logging
- Class `SoftDeleteMixin`: Mixin for soft delete functionality
  - Method `soft_delete(self, deleted_by)`: Perform soft delete
  - Method `restore(self)`: Restore from soft delete
- Class `EncryptedFieldMixin`: Mixin for handling encrypted sensitive fields
  - Method `set_encrypted_field(self, field_name, value)`: Set encrypted field using SecurityManager
  - Method `get_encrypted_field(self, field_name)`: Get decrypted field value

## Module: `models.security`
Security-related models for FixOps Enterprise
Findings, Vulnerabilities, Incidents, Services, Policies

- Class `SeverityLevel`: No documentation provided.
- Class `ScannerType`: No documentation provided.
- Class `FindingStatus`: No documentation provided.
- Class `DataClassification`: No documentation provided.
- Class `Environment`: No documentation provided.
- Class `PolicyDecision`: No documentation provided.
- Class `IncidentStatus`: No documentation provided.
- Class `Service`: Service registry with business context and security metadata
- Class `SecurityFinding`: Security findings from various scanners with enriched context
- Class `FindingCorrelation`: Correlation between multiple findings to reduce noise
- Class `SecurityIncident`: Security incidents created from findings or external sources
- Class `PolicyRule`: Security policy rules for automated decision making
- Class `PolicyDecisionLog`: Log of policy decisions for audit and compliance
- Class `VulnerabilityIntelligence`: Vulnerability intelligence and threat data
- Class `ComplianceEvidence`: Compliance evidence and attestations

## Module: `models.security_sqlite`
SQLite-compatible security models for FixOps Enterprise
Findings, Vulnerabilities, Incidents, Services, Policies

- Class `SeverityLevel`: No documentation provided.
- Class `ScannerType`: No documentation provided.
- Class `FindingStatus`: No documentation provided.
- Class `DataClassification`: No documentation provided.
- Class `Environment`: No documentation provided.
- Class `PolicyDecision`: No documentation provided.
- Class `IncidentStatus`: No documentation provided.
- Class `Service`: Service registry with business context and security metadata (SQLite compatible)
  - Method `get_data_classification(self)`: Get data classification as list
  - Method `set_data_classification(self, classifications)`: Set data classification from list
  - Method `get_dependencies(self)`: Get dependencies as list
  - Method `set_dependencies(self, deps)`: Set dependencies from list
  - Method `get_tech_stack(self)`: Get tech stack as dictionary
  - Method `set_tech_stack(self, stack)`: Set tech stack from dictionary
- Class `SecurityFinding`: Security findings from various scanners with enriched context (SQLite compatible)
  - Method `get_evidence(self)`: Get evidence as dictionary
  - Method `set_evidence(self, evidence_data)`: Set evidence from dictionary
- Class `FindingCorrelation`: Correlation between multiple findings to reduce noise (SQLite compatible)
- Class `SecurityIncident`: Security incidents created from findings or external sources (SQLite compatible)
  - Method `get_related_findings(self)`: Get related findings as list
  - Method `set_related_findings(self, findings)`: Set related findings from list
- Class `PolicyRule`: Security policy rules for automated decision making (SQLite compatible)
  - Method `get_environments(self)`: Get environments as list
  - Method `set_environments(self, envs)`: Set environments from list
  - Method `get_data_classifications(self)`: Get data classifications as list
  - Method `set_data_classifications(self, classifications)`: Set data classifications from list
- Class `PolicyDecisionLog`: Log of policy decisions for audit and compliance (SQLite compatible)
  - Method `get_input_context(self)`: Get input context as dictionary
  - Method `set_input_context(self, context)`: Set input context from dictionary
- Class `VulnerabilityIntelligence`: Vulnerability intelligence and threat data (SQLite compatible)
- Class `ComplianceEvidence`: Compliance evidence and attestations (SQLite compatible)
  - Method `get_evidence_data(self)`: Get evidence data as dictionary
  - Method `set_evidence_data(self, data)`: Set evidence data from dictionary

## Module: `models.user`
Enterprise user model with security, compliance, and RBAC

- Class `UserStatus`: No documentation provided.
- Class `UserRole`: No documentation provided.
- Class `User`: Enterprise user model with comprehensive security features
  - Method `full_name(self)`: Get user's full name
  - Method `is_admin(self)`: Check if user has admin role
  - Method `is_locked(self)`: Check if account is currently locked
  - Method `has_role(self, role)`: Check if user has specific role
  - Method `add_role(self, role)`: Add role to user
  - Method `remove_role(self, role)`: Remove role from user
  - Method `set_mfa_secret(self, secret)`: Set encrypted MFA secret
  - Method `get_mfa_secret(self)`: Get decrypted MFA secret
  - Method `increment_failed_logins(self)`: Increment failed login counter and lock account if needed
  - Method `reset_failed_logins(self)`: Reset failed login counter on successful login
  - Method `record_login(self, ip_address)`: Record successful login
  - Method `to_dict(self, include_sensitive)`: Convert to dict with optional sensitive data exclusion
- Class `UserSession`: User session tracking for security monitoring
  - Method `is_expired(self)`: Check if session is expired
  - Method `is_valid(self)`: Check if session is valid
- Class `UserAuditLog`: Comprehensive audit logging for compliance

## Module: `models.user_sqlite`
SQLite-compatible user model with security, compliance, and RBAC

- Class `UserStatus`: No documentation provided.
- Class `UserRole`: No documentation provided.
- Class `User`: Enterprise user model with comprehensive security features (SQLite compatible)
  - Method `full_name(self)`: Get user's full name
  - Method `is_admin(self)`: Check if user has admin role
  - Method `is_locked(self)`: Check if account is currently locked
  - Method `get_roles(self)`: Get user roles as list
  - Method `set_roles(self, roles)`: Set user roles from list
  - Method `has_role(self, role)`: Check if user has specific role
  - Method `add_role(self, role)`: Add role to user
  - Method `remove_role(self, role)`: Remove role from user
  - Method `set_mfa_secret(self, secret)`: Set encrypted MFA secret
  - Method `get_mfa_secret(self)`: Get decrypted MFA secret
  - Method `increment_failed_logins(self)`: Increment failed login counter and lock account if needed
  - Method `reset_failed_logins(self)`: Reset failed login counter on successful login
  - Method `record_login(self, ip_address)`: Record successful login
  - Method `to_dict(self, include_sensitive)`: Convert to dict with optional sensitive data exclusion
- Class `UserSession`: User session tracking for security monitoring (SQLite compatible)
  - Method `is_expired(self)`: Check if session is expired
  - Method `is_valid(self)`: Check if session is valid
- Class `UserAuditLog`: Comprehensive audit logging for compliance (SQLite compatible)
  - Method `get_details(self)`: Get details as dictionary
  - Method `set_details(self, details)`: Set details from dictionary

## Module: `schemas.user`
User-related Pydantic schemas for API request/response validation

- Class `UserRole`: No documentation provided.
- Class `UserStatus`: No documentation provided.
- Class `LoginRequest`: Login request with optional MFA code
- Class `LoginResponse`: Login response with JWT tokens and user info
- Class `RefreshTokenRequest`: Refresh token request
- Class `MFASetupResponse`: MFA setup response with QR code and backup codes
- Class `UserBase`: Base user schema with common fields
- Class `UserCreate`: User creation schema
  - Method `validate_password(cls, v)`: Validate password strength
- Class `UserUpdate`: User update schema
- Class `UserResponse`: User response schema (excludes sensitive data)
- Class `UserListResponse`: Paginated user list response
- Class `UserSession`: User session information
- Class `ChangePasswordRequest`: Password change request
  - Method `validate_new_password(cls, v)`: Validate new password strength
- Class `ResetPasswordRequest`: Password reset request
- Class `ResetPasswordConfirm`: Password reset confirmation
  - Method `validate_new_password(cls, v)`: Validate new password strength
- Class `UserAuditLogEntry`: User audit log entry
- Class `SecurityEventRequest`: Security event reporting
- Class `UserPreferences`: User preferences
- Class `ProfileUpdateRequest`: Profile update request
- Class `RolePermission`: Role permission definition
- Class `RoleDefinition`: Role definition with permissions

## Module: `services.advanced_llm_engine`
Enhanced Decision Engine - Multi-LLM Analysis and Consensus
Provides advanced security decision making with multiple AI models

- Class `LLMProvider`: No documentation provided.
- Class `LLMAnalysisResult`: No documentation provided.
- Class `MultiLLMResult`: No documentation provided.
- Class `AdvancedLLMEngine`: Advanced LLM Engine for multi-model consensus analysis
  - Method `__init__(self)`: No documentation provided.
  - Method `initialize(self)`: Initialize the advanced LLM engine - required by enhanced_decision_engine
  - Method `_initialize_llm_client(self)`: Initialize LLM client for multi-model analysis
  - Method `get_supported_llms(self)`: Get supported LLM providers and their capabilities
  - Method `enhanced_security_analysis(self, context, security_findings)`: Perform enhanced security analysis using multiple LLMs
  - Method `_analyze_with_llm(self, provider, context, findings)`: Analyze with a specific LLM provider
  - Method `_build_analysis_prompt(self, context, findings)`: Build analysis prompt for LLM
  - Method `_parse_llm_response(self, response)`: Parse LLM response into structured data
  - Method `_generate_demo_analysis(self, provider, context, findings)`: Generate demo analysis for providers
  - Method `_generate_consensus(self, analyses)`: Generate consensus from multiple LLM analyses

## Module: `services.business_context_processor`
FixOps Business Context Schema
Supports SSVC design-time business context and OTM integration

- Class `SSVCBusinessContext`: SSVC-compliant business context for FixOps decisions
- Class `OTMContext`: Open Threat Model (OTM) integration context
- Class `FixOpsContextProcessor`: Process and convert business context formats for FixOps Decision Engine
  - Method `__init__(self)`: No documentation provided.
  - Method `process_fixops_yaml(self, yaml_content)`: Process fixops.yaml format business context
  - Method `process_otm_json(self, json_content)`: Convert OTM (Open Threat Model) format to FixOps SSVC context
  - Method `_convert_otm_to_ssvc(self, otm)`: Convert OTM threat model to SSVC business context
  - Method `_analyze_exploitation(self, threats)`: Analyze OTM threats to determine exploitation level
  - Method `_analyze_exposure(self, components, trust_zones)`: Analyze exposure level from OTM components and trust zones
  - Method `_analyze_utility(self, threats, mitigations)`: Analyze utility/automatable from threats and mitigations
  - Method `_analyze_safety_impact(self, threats, project)`: Determine safety impact from OTM threat analysis
  - Method `_analyze_mission_impact(self, threats, project)`: Determine mission impact from OTM analysis
  - Method `_determine_criticality(self, threats, components)`: Determine business criticality from OTM analysis
  - Method `_extract_data_classification(self, components, data_flows)`: Extract data classification from OTM components and data flows
  - Method `_check_internet_exposure(self, components, trust_zones)`: Check if system has internet exposure
  - Method `_extract_compliance(self, project)`: Extract compliance requirements from OTM project
  - Method `_generate_attack_surface(self, components, data_flows)`: Generate attack surface analysis from OTM data
  - Method `_identify_attack_vectors(self, components, data_flows)`: Identify potential attack vectors from OTM
  - Method `generate_sample_fixops_yaml(self, service_name)`: Generate sample fixops.yaml for business context
  - Method `generate_sample_otm_json(self, service_name)`: Generate sample OTM JSON for threat modeling

## Module: `services.cache_service`
Enterprise Redis cache service with high-performance optimization

- Class `CacheService`: High-performance Redis cache service with enterprise features
  - Method `__init__(self)`: No documentation provided.
  - Method `initialize(cls)`: Initialize Redis connection pool with enterprise configuration
  - Method `get_instance(cls)`: Get singleton instance of CacheService
  - Method `close(cls)`: Close Redis connections
  - Method `ping(self)`: Health check for Redis connectivity
  - Method `set(self, key, value, ttl, nx)`: Set key-value pair with optional TTL (optimized for performance)
  - Method `get(self, key, default)`: Get value by key with automatic deserialization
  - Method `delete(self, key)`: Delete key from cache
  - Method `exists(self, key)`: Check if key exists in cache
  - Method `expire(self, key, ttl)`: Set TTL for existing key
  - Method `ttl(self, key)`: Get remaining TTL for key (-1 = no expiry, -2 = key doesn't exist)
  - Method `increment(self, key, amount)`: Increment counter (atomic operation)
  - Method `decrement(self, key, amount)`: Decrement counter (atomic operation)
  - Method `set_hash(self, key, mapping, ttl)`: Set hash map with optional TTL
  - Method `get_hash(self, key, field)`: Get hash field or entire hash
  - Method `add_to_set(self, key, *values, ttl=)`: Add values to set
  - Method `get_set_members(self, key)`: Get all members of a set
  - Method `is_in_set(self, key, value)`: Check if value is in set
  - Method `push_to_list(self, key, *values, ttl=, left=)`: Push values to list (left or right)
  - Method `get_list_range(self, key, start, end)`: Get range of list elements
  - Method `get_cache_stats(self)`: Get cache performance statistics
- Function `get_cache()`: Get cache service instance
- Function `cache_result(key_prefix, ttl)`: Decorator to cache function results

## Module: `services.compliance_engine`
FixOps Compliance Engine - maps risk-adjusted findings to framework posture.

- Class `ComplianceEngine`: Evaluate compliance posture using FixOps risk tiers.
  - Method `__init__(self)`: No documentation provided.
  - Method `evaluate(self, frameworks, findings, business_context)`: Evaluate one or more frameworks returning a mapping of results.
  - Method `_evaluate_framework(self, framework, findings, business_context)`: Evaluate a single framework using FixOps severity tiers.
  - Method `_determine_status(self, threshold, highest_fixops)`: No documentation provided.
  - Method `_normalize_severity(self, severity)`: No documentation provided.
  - Method `_max_severity(self, current, other)`: No documentation provided.

## Module: `services.correlation_engine`
FixOps Correlation Engine - Core intelligence for noise reduction and finding correlation
Performance-optimized for 299μs hot path operations with AI-powered insights

- Class `CorrelationResult`: Result of correlation analysis
- Class `CorrelationEngine`: High-performance correlation engine for security findings
  - Method `__init__(self)`: No documentation provided.
  - Method `_initialize_llm(self)`: Initialize LLM for advanced correlation analysis
  - Method `correlate_finding(self, finding_id, force_refresh)`: Correlate a single finding with existing findings
  - Method `batch_correlate_findings(self, finding_ids)`: Batch correlate multiple findings for efficiency
  - Method `_get_finding_optimized(self, session, finding_id)`: Get finding with optimized query for hot path performance
  - Method `_correlate_by_fingerprint(self, session, finding)`: Correlate findings by exact fingerprint match - fastest correlation
  - Method `_correlate_by_location(self, session, finding)`: Correlate findings by file/location proximity
  - Method `_correlate_by_pattern(self, session, finding)`: Correlate findings by rule pattern and scanner type
  - Method `_correlate_by_root_cause(self, session, finding)`: Correlate findings by potential root cause analysis
  - Method `_correlate_by_vulnerability(self, session, finding)`: Correlate findings by CVE/CWE vulnerability taxonomy
  - Method `_select_best_correlation(self, correlation_results)`: Select the best correlation result based on confidence and noise reduction
  - Method `_store_correlation(self, session, correlation)`: Store correlation result in database for persistence
  - Method `get_correlation_stats(self)`: Get correlation engine performance statistics
  - Method `calculate_noise_reduction(self, time_window_hours)`: Calculate noise reduction metrics over time window
  - Method `ai_enhanced_correlation(self, finding_id, context_findings)`: Use AI to provide enhanced correlation insights and recommendations
- Function `correlate_finding_async(finding_id)`: Async wrapper for correlation engine
- Function `batch_correlate_async(finding_ids)`: Async wrapper for batch correlation

## Module: `services.decision_engine`
FixOps Decision & Verification Engine - Dual Mode Implementation
Supports both Demo Mode (simulated data) and Production Mode (real integrations)

- Class `DecisionOutcome`: No documentation provided.
- Class `DecisionContext`: Context data for decision making
- Class `DecisionResult`: Result of decision engine processing
- Class `DecisionEngine`: FixOps Decision & Verification Engine - Dual Mode
  - Method `__init__(self)`: No documentation provided.
  - Method `initialize(self)`: Initialize decision engine components based on mode
  - Method `_initialize_demo_mode(self)`: Initialize with simulated data for demo/showcase
  - Method `_initialize_production_mode(self)`: Initialize with real integrations for production
  - Method `_initialize_real_vector_db(self)`: Initialize real Vector DB with security patterns
  - Method `_initialize_real_jira(self)`: Initialize real Jira integration
  - Method `_initialize_real_confluence(self)`: Initialize real Confluence integration
  - Method `_initialize_real_threat_intel(self)`: Initialize real threat intelligence feeds
  - Method `_initialize_oss_tools(self)`: Initialize OSS tools integration for real scanning and policy evaluation
  - Method `make_decision(self, context)`: Make a security decision based on mode (demo vs production)
  - Method `_make_demo_decision(self, context, start_time)`: Make decision using simulated data (demo mode)
  - Method `_make_production_decision(self, context, start_time)`: Make decision using real Processing Layer integration (production mode)
  - Method `_real_context_enrichment(self, context)`: Real business context enrichment using actual integrations
  - Method `_fetch_real_jira_context(self, service_name)`: Fetch real business context from Jira
  - Method `_fetch_real_confluence_context(self, service_name)`: Fetch real threat model from Confluence
  - Method `_real_llm_enrichment(self, context, base_context)`: Real LLM-based context enrichment using Emergent LLM
  - Method `get_decision_metrics(self)`: Get decision engine metrics with mode indicator
  - Method `_create_error_decision(self, context, start_time, error)`: Create error decision result
  - Method `_real_vector_db_lookup(self, context, enriched_context)`: Real vector database lookup for security patterns
  - Method `_real_golden_regression_validation(self, context)`: Real golden regression validation using historical decisions.
  - Method `_real_policy_evaluation(self, context, enriched_context)`: Real policy evaluation using OPA and custom policies
  - Method `_fallback_policy_evaluation(self, context, enriched_context)`: Fallback policy evaluation when OPA is not available
  - Method `_real_sbom_criticality_assessment(self, context)`: Real SBOM criticality assessment using Trivy/Grype
  - Method `_real_consensus_checking(self, knowledge_results, regression_results, policy_results, criticality_assessment)`: Real consensus checking across all analysis components
  - Method `_real_final_decision(self, consensus_result)`: Real final decision based on consensus and risk tolerance
  - Method `_real_evidence_generation(self, context, decision, consensus_result)`: Real evidence generation using Evidence Lake for immutable storage
  - Method `get_recent_decisions(self, limit)`: Get recent decisions from database or cache
  - Method `get_ssdlc_stage_data(self)`: Get SSDLC stage data with real database queries
  - Method `_use_processing_layer(self, context)`: Use Processing Layer for integrated architecture components
  - Method `_effective_severity(self, finding)`: No documentation provided.
  - Method `_extract_exploitation_level(self, context)`: Extract exploitation level from context for SSVC
  - Method `_extract_exposure_level(self, context)`: Extract exposure level from context for SSVC
  - Method `_extract_utility_level(self, context)`: Extract utility level from context for SSVC
  - Method `_extract_safety_impact(self, context)`: Extract safety impact from context for SSVC
  - Method `_extract_mission_impact(self, context)`: Extract mission impact from context for SSVC
- Function `_get_service_type(service_name)`: Classify service type for metrics
- Function `_assess_business_impact(service_name)`: Assess business impact for metrics

## Module: `services.enhanced_decision_engine`
FixOps Enhanced Decision Engine 
Multi-LLM powered decision engine with advanced security intelligence

- Class `EnhancedDecisionEngine`: Enhanced decision engine with multi-LLM intelligence and marketplace integration
  - Method `__init__(self)`: No documentation provided.
  - Method `initialize(self)`: Initialize enhanced decision engine
  - Method `_load_enhanced_capabilities(self)`: Load enhanced security capabilities
  - Method `make_enhanced_decision(self, service_name, environment, business_context, security_findings, compliance_requirements)`: Make enhanced security decision using multi-LLM analysis
  - Method `_enhance_context_with_marketplace(self, service_name, environment, business_context, compliance_requirements)`: Enhance context using marketplace intelligence
  - Method `_perform_mitre_analysis(self, security_findings, llm_result)`: Enhanced MITRE ATT&CK analysis
  - Method `_calculate_business_risk_amplification(self, techniques)`: Calculate business risk amplification based on MITRE techniques
  - Method `_perform_compliance_analysis(self, security_findings, compliance_requirements, llm_result)`: Enhanced compliance analysis
  - Method `_generate_enhanced_decision(self, llm_result, mitre_analysis, compliance_analysis, context)`: Generate final enhanced decision with all intelligence
  - Method `_generate_enhanced_evidence(self, decision, llm_result, mitre_analysis, compliance_analysis)`: Generate enhanced evidence record
  - Method `_create_enhanced_fallback_decision(self, service_name, environment, error)`: Create enhanced fallback decision on error
  - Method `get_enhanced_metrics(self)`: Get enhanced decision engine metrics

## Module: `services.evidence_lake`
Evidence Lake - Immutable audit records storage
Stores decision evidence with cryptographic signatures

- Class `EvidenceLake`: Immutable evidence storage with cryptographic integrity
  - Method `store_evidence(evidence_record)`: Store immutable evidence record with signature
  - Method `retrieve_evidence(evidence_id)`: Retrieve evidence record and verify integrity
  - Method `get_evidence_summary()`: Get Evidence Lake summary statistics

## Module: `services.feeds_service`
EPSS/KEV feeds ingestion service with file-based persistence
- Stores latest snapshots under /app/data/feeds
- Provides counts and timestamps for UI badges
- Scheduled daily refresh when enabled

- Class `FeedStatus`: No documentation provided.
- Class `FeedsService`: No documentation provided.
  - Method `fetch_json(url)`: No documentation provided.
  - Method `_write(path, payload)`: No documentation provided.
  - Method `_read(path)`: No documentation provided.
  - Method `refresh_epss(cls)`: No documentation provided.
  - Method `refresh_kev(cls)`: No documentation provided.
  - Method `status(cls, enabled_epss, enabled_kev)`: No documentation provided.
  - Method `scheduler(cls, settings)`: Daily scheduler for EPSS/KEV refresh (if enabled)

## Module: `services.fix_engine`
FixOps Fix Engine - Provides automated fix recommendations and remediation

- Class `FixRecommendation`: Fix recommendation data structure
- Class `FixEngine`: Fix Engine for automated remediation recommendations
  - Method `__init__(self)`: No documentation provided.
  - Method `initialize(self)`: Initialize the fix engine
  - Method `get_fix_recommendations(self, finding_id, context)`: Get fix recommendations for a security finding
  - Method `apply_automated_fix(self, fix_id)`: Apply an automated fix
  - Method `validate_fix(self, fix_id)`: Validate that a fix was applied correctly

## Module: `services.golden_regression_store`
Golden regression dataset loader for historical validation results.

- Function `_log(method, message, **kwargs)`: Log helper compatible with structlog and stdlib logging.
- Class `RegressionCase`: Represents a single historical regression validation case.
  - Method `from_dict(cls, payload)`: Create a regression case from a raw payload.
  - Method `to_response(self)`: Convert to a serializable representation for API responses.
- Class `RegressionCaseResult`: Detailed outcome for a single regression case.
  - Method `to_dict(self)`: No documentation provided.
- Class `GoldenRegressionStore`: Loads and queries historical regression validation cases.
  - Method `__init__(self, dataset_path)`: No documentation provided.
  - Method `get_instance(cls, dataset_path)`: Return a singleton instance, reloading if a new dataset path is provided.
  - Method `reset_instance(cls)`: Reset the singleton instance (useful for tests).
  - Method `lookup_cases(self, service_name, cve_ids)`: Return cases that match the provided service or CVE identifiers.
  - Method `load_cases(self)`: Return the raw case payloads as loaded from disk.
  - Method `evaluate(self, decision_engine, initialize_engine=)`: Replay every regression case and capture real outcomes.
  - Method `iter_case_ids(self)`: Yield case identifiers for convenience.
  - Method `_load_dataset(self)`: Load regression cases from the dataset file.
  - Method `_build_context(self, context, case_id)`: Convert persisted context into a decision context instance.
  - Method `_normalise_expected(self, expected)`: No documentation provided.
  - Method `_serialise_decision_result(self, result)`: Convert a decision result into serialisable primitives.
  - Method `_predict_decision(self, case)`: Heuristic decision used when the real engine is unavailable.
  - Method `_calculate_delta(self, expected, actual, match)`: No documentation provided.
  - Method `_default_dataset_path()`: No documentation provided.

## Module: `services.knowledge_graph`
Knowledge Graph Construction
Purpose: Link components, vulnerabilities, and context
Uses CTINexus for entity extraction and graph visualization

- Class `NoPathError`: Fallback exception mirroring networkx.NetworkXNoPath.
- Class `SecurityEntity`: Security entity for knowledge graph
- Class `SecurityRelation`: Relationship between security entities
- Class `CTINexusEntityExtractor`: REAL CTINexus-inspired entity extraction using LLM-based in-context learning
  - Method `__init__(self)`: No documentation provided.
  - Method `_initialize_llm_client(self)`: Initialize LLM client for CTINexus-style entity extraction
  - Method `_load_cybersecurity_ontology(self)`: Load cybersecurity ontology for CTINexus entity extraction
  - Method `_load_demonstration_examples(self)`: Load demonstration examples for in-context learning as per CTINexus
  - Method `extract_entities(self, scan_data)`: Extract security entities using REAL CTINexus LLM-based approach
  - Method `_ctinexus_llm_extraction(self, scan_data)`: Real CTINexus LLM-based entity and relation extraction
  - Method `_prepare_cti_text(self, scan_data)`: Prepare cyber threat intelligence text from scan data for CTINexus
  - Method `_create_ctinexus_prompt(self, cti_text)`: Create CTINexus-style prompt with in-context learning demonstrations
  - Method `_parse_ctinexus_response(self, response)`: Parse CTINexus LLM response into SecurityEntity objects
  - Method `_fallback_pattern_extraction(self, scan_data)`: Fallback pattern-based extraction when LLM unavailable
  - Method `_extract_from_sarif(self, sarif_data)`: Extract entities from SARIF data
  - Method `_extract_from_sbom(self, sbom_data)`: Extract entities from SBOM data
  - Method `_extract_from_findings(self, findings)`: Extract entities from security findings
  - Method `_extract_file_location(self, sarif_result)`: Extract file location from SARIF result
  - Method `_extract_cwe(self, sarif_result)`: Extract CWE ID from SARIF result
  - Method `_extract_owasp(self, sarif_result)`: Extract OWASP category from SARIF result
- Class `KnowledgeGraphBuilder`: Knowledge Graph Construction and Management
  - Method `__init__(self)`: No documentation provided.
  - Method `_add_node(self, entity)`: No documentation provided.
  - Method `_add_edge(self, relation)`: No documentation provided.
  - Method `_number_of_nodes(self)`: No documentation provided.
  - Method `_number_of_edges(self)`: No documentation provided.
  - Method `_iter_nodes(self, data)`: No documentation provided.
  - Method `_degree(self, node_id)`: No documentation provided.
  - Method `_node_data(self, node_id)`: No documentation provided.
  - Method `_neighbors(self, node_id)`: No documentation provided.
  - Method `_has_path(self, source, target)`: No documentation provided.
  - Method `_shortest_path(self, source, target, return_path)`: No documentation provided.
  - Method `_weakly_connected_components(self)`: No documentation provided.
  - Method `_connected_components(self)`: No documentation provided.
  - Method `_density(self)`: No documentation provided.
  - Method `_average_clustering(self)`: No documentation provided.
  - Method `_degree_centrality(self)`: No documentation provided.
  - Method `_betweenness_centrality(self)`: No documentation provided.
  - Method `build_graph(self, scan_data, context_data)`: Build knowledge graph from scan data and context
  - Method `_infer_relationships(self, entities)`: Infer relationships between entities
  - Method `_entities_related(self, entity1, entity2)`: Check if two entities are related
  - Method `_component_belongs_to_service(self, component, service)`: Check if component belongs to service
  - Method `_analyze_graph(self)`: Analyze graph structure and metrics
  - Method `_find_critical_paths(self)`: Find critical attack paths in the graph
  - Method `_calculate_path_risk(self, path)`: Calculate risk score for a path
  - Method `_identify_risk_clusters(self)`: Identify clusters of related risks
  - Method `_calculate_cluster_risk(self, nodes)`: Calculate risk level for a cluster
  - Method `_generate_recommendations(self)`: Generate security recommendations based on graph analysis

## Module: `services.llm_explanation_engine`
LLM Explanation Engine
Purpose: Generate human-readable summaries of complex technical findings
Uses models from Awesome-LLM4Cybersecurity for security domain expertise

- Class `ExplanationRequest`: Request for generating explanation
- Class `GeneratedExplanation`: Generated explanation result
- Class `CybersecurityLLMEngine`: Specialized LLM engine for cybersecurity explanations
  - Method `__init__(self)`: No documentation provided.
  - Method `_load_awesome_llm4cybersecurity_models(self)`: Load model configurations from Awesome-LLM4Cybersecurity repository
  - Method `_initialize_cybersecurity_llm(self)`: Initialize LLM client optimized for cybersecurity from Awesome-LLM4Cybersecurity
  - Method `_load_cybersecurity_prompts(self)`: Load cybersecurity-specific prompt templates
  - Method `_load_domain_knowledge(self)`: Load cybersecurity domain knowledge base
- Class `LLMExplanationEngine`: Main LLM Explanation Engine
  - Method `__init__(self)`: No documentation provided.
  - Method `generate_explanation(self, request)`: Generate human-readable explanation for technical security data
  - Method `_call_llm(self, prompt, context_type)`: Call LLM with Awesome-LLM4Cybersecurity optimized parameters
  - Method `_parse_llm_response(self, llm_response, request)`: Parse LLM response into structured explanation
  - Method `_extract_sections(self, response)`: Extract structured sections from LLM response
  - Method `_identify_section(self, line)`: Identify section type from header line
  - Method `_extract_key_points(self, response)`: Extract key points from response
  - Method `_extract_recommendations(self, response)`: Extract actionable recommendations
  - Method `_extract_risk_implications(self, technical_data)`: Extract or generate risk implications
  - Method `_calculate_explanation_confidence(self, response, request)`: Calculate confidence score for the generated explanation
  - Method `_generate_fallback_explanation(self, request)`: Generate fallback explanation when LLM is unavailable
  - Method `_generate_error_explanation(self, request, error)`: Generate error explanation when generation fails
  - Method `_generate_cache_key(self, request)`: Generate cache key for explanation request
  - Method `explain_vulnerability_findings(self, findings, audience)`: Convenience method for explaining vulnerability findings
  - Method `explain_decision_outcome(self, decision_data, audience)`: Convenience method for explaining decision outcomes
  - Method `explain_risk_assessment(self, risk_data, audience)`: Convenience method for explaining risk assessments

## Module: `services.marketplace`
Marketplace service with file persistence and validation (enterprise-ready stub)
- In-memory index plus JSON snapshots under /app/data/marketplace
- UUID-only IDs, simple versioning and purchase records
- Tokenized download links (HMAC) without app-level auth

- Class `QAStatus`: No documentation provided.
- Class `ContributorProfile`: No documentation provided.
  - Method `to_dict(self)`: No documentation provided.
  - Method `from_dict(cls, data)`: No documentation provided.
- Class `ContentType`: No documentation provided.
- Class `PricingModel`: No documentation provided.
- Class `MarketplaceItemModel`: No documentation provided.
- Class `MarketplaceItem`: No documentation provided.
- Class `MarketplaceService`: No documentation provided.
  - Method `__init__(self, secret)`: No documentation provided.
  - Method `initialize(self)`: No documentation provided.
  - Method `_load(self)`: No documentation provided.
  - Method `_persist(self)`: No documentation provided.
  - Method `_seed_items(self)`: No documentation provided.
  - Method `_validate_content(self, content)`: No documentation provided.
  - Method `_run_automated_validation(self, content, artifact)`: No documentation provided.
  - Method `_contributor_key(self, author, organization)`: No documentation provided.
  - Method `_get_or_create_profile(self, author, organization)`: No documentation provided.
  - Method `_recalculate_reputation(self, profile)`: No documentation provided.
  - Method `_sign_token(self, purchase_id, expires_in_minutes)`: No documentation provided.
  - Method `_verify_token(self, token)`: No documentation provided.
  - Method `_get_all_marketplace_items(self)`: No documentation provided.
  - Method `search_marketplace(self, content_type=, compliance_frameworks=, ssdlc_stages=, pricing_model=, organization_type=)`: No documentation provided.
  - Method `get_recommended_content(self, organization_type=, compliance_requirements=)`: No documentation provided.
  - Method `contribute_content(self, content, author, organization)`: No documentation provided.
  - Method `update_content(self, item_id, patch)`: No documentation provided.
  - Method `purchase_content(self, item_id, purchaser, organization)`: No documentation provided.
  - Method `rate_content(self, item_id, rating, reviewer)`: No documentation provided.
  - Method `get_contributor_metrics(self, author, organization)`: No documentation provided.
  - Method `get_quality_summary(self)`: No documentation provided.
  - Method `get_item(self, item_id)`: No documentation provided.
  - Method `download_by_token(self, token)`: No documentation provided.
  - Method `get_compliance_content_for_stage(self, stage, frameworks)`: No documentation provided.

## Module: `services.metrics`
Prometheus metrics for FixOps

- Class `FixOpsMetrics`: No documentation provided.
  - Method `get_metrics()`: No documentation provided.
  - Method `record_request(endpoint, method, status, duration)`: No documentation provided.
  - Method `record_decision(verdict)`: No documentation provided.
  - Method `record_upload(scan_type)`: No documentation provided.

## Module: `services.missing_oss_integrations`
Missing OSS Tools Integration
Implements the remaining OSS components from the architecture table:
- python-ssvc for SSVC Prep
- lib4sbom for SBOM parsing  
- sarif-tools for SARIF conversion
- pomegranate for alternative Bayesian modeling

- Function `_mean(values)`: No documentation provided.
- Class `SSVCFramework`: Real SSVC Framework Integration using python-ssvc library
  - Method `__init__(self)`: No documentation provided.
  - Method `_initialize_ssvc(self)`: Initialize real SSVC framework
  - Method `evaluate_ssvc_decision(self, vulnerability_data)`: Evaluate SSVC decision using real framework
  - Method `_calculate_ssvc_recommendation(self, decision_points)`: Calculate SSVC recommendation based on decision points
  - Method `_calculate_priority(self, decision_points)`: Calculate priority level
- Class `SBOMParser`: Real SBOM Parser using lib4sbom library
  - Method `__init__(self)`: No documentation provided.
  - Method `_initialize_lib4sbom(self)`: Initialize real lib4sbom library
  - Method `parse_sbom(self, sbom_data, sbom_format)`: Parse SBOM using real lib4sbom library with detailed validation
  - Method `_validate_sbom_structure(self, sbom_dict)`: Validate SBOM structure according to CycloneDX/SPDX standards
  - Method `_parse_component_detailed(self, component, index)`: Parse individual component with detailed validation and enrichment
  - Method `_parse_purl(self, purl)`: Parse Package URL according to PURL specification
  - Method `_parse_supplier(self, supplier_data)`: Parse supplier information
  - Method `_parse_licenses(self, licenses_data)`: Parse license information with SPDX ID validation
  - Method `_parse_hashes(self, hashes_data)`: Parse cryptographic hashes
  - Method `_parse_external_references(self, external_refs)`: Parse external references
  - Method `_calculate_component_risk(self, name, version, component_type, external_refs)`: Calculate risk indicators for a component
  - Method `_extract_dependencies(self, sbom_dict)`: Extract dependency relationships
  - Method `_detect_circular_deps(self, dep_graph)`: Detect circular dependencies in the dependency graph
  - Method `_calculate_vulnerability_exposure(self, components)`: Calculate overall vulnerability exposure of the SBOM
  - Method `generate_sbom(self, components, output_format)`: Generate SBOM using lib4sbom
- Class `SARIFProcessor`: Real SARIF Processing using sarif-tools library
  - Method `__init__(self)`: No documentation provided.
  - Method `_initialize_sarif_tools(self)`: Initialize real sarif-tools library
  - Method `process_sarif(self, sarif_data)`: Process existing SARIF data with detailed validation and enrichment
  - Method `convert_to_sarif(self, scan_results, tool_name)`: Convert scan results to SARIF format with detailed structure
  - Method `_validate_sarif_structure(self, sarif_dict)`: Validate SARIF structure according to SARIF 2.1.0 specification
  - Method `_validate_sarif_run(self, run, run_index)`: Validate individual SARIF run
  - Method `_extract_tool_info(self, tool_data)`: Extract tool information from SARIF run
  - Method `_process_sarif_result(self, result, rules, tool_info)`: Process individual SARIF result with detailed extraction
  - Method `_extract_primary_location(self, locations)`: Extract primary location from SARIF locations array
  - Method `_extract_security_metadata(self, result, rule_info, properties)`: Extract security-specific metadata
  - Method `_generate_result_fingerprint(self, result)`: Generate unique fingerprint for SARIF result
  - Method `_create_sarif_rule(self, finding, rule_id)`: Create detailed SARIF rule from finding
  - Method `_create_sarif_artifact(self, file_path)`: Create SARIF artifact entry
  - Method `_create_detailed_sarif_result(self, finding, rule_id, artifact_index)`: Create detailed SARIF result
  - Method `_analyze_sarif_findings(self, findings)`: Analyze processed SARIF findings for insights
  - Method `_generate_sarif_statistics(self, findings)`: Generate comprehensive statistics from SARIF findings
  - Method `_map_level_to_severity(self, level)`: Map SARIF level to severity
  - Method `_severity_to_numeric(self, severity)`: Convert severity to numeric score
  - Method `_calculate_result_rank(self, finding)`: Calculate numerical rank for SARIF result
  - Method `_get_mime_type(self, file_path)`: Get MIME type for file path
  - Method `_get_file_type(self, file_path)`: Get file type category
  - Method `_map_severity_to_level(self, severity)`: Map severity to SARIF level
- Class `PomegranateEngine`: Alternative Bayesian Engine using pomegranate library
  - Method `__init__(self)`: No documentation provided.
  - Method `_initialize_pomegranate(self)`: Initialize pomegranate library
  - Method `create_bayesian_network(self, vulnerability_data)`: Create Bayesian network using pomegranate
  - Method `_calculate_pomegranate_probabilities(self, vulnerability_data)`: Calculate risk probabilities using pomegranate approach
- Class `MissingOSSIntegrationService`: Service that orchestrates all the missing OSS tool integrations
  - Method `__init__(self)`: No documentation provided.
  - Method `get_integration_status(self)`: Get status of all missing OSS integrations
  - Method `comprehensive_analysis(self, scan_data)`: Run comprehensive analysis using all missing OSS tools

## Module: `services.oss_integrations`
OSS Toolchain Integrations for FixOps
Implements actual integrations with open source security tools

- Class `TrivyScanner`: Integration with Trivy vulnerability scanner
  - Method `__init__(self)`: No documentation provided.
  - Method `_get_version(self)`: No documentation provided.
  - Method `scan_image(self, image)`: Scan container image for vulnerabilities
- Class `OPAPolicyEngine`: Integration with Open Policy Agent (OPA)
  - Method `__init__(self)`: No documentation provided.
  - Method `_get_version(self)`: No documentation provided.
  - Method `evaluate_policy(self, policy_name, input_data)`: Evaluate security policy using OPA
- Class `SigstoreVerifier`: Integration with Sigstore for supply chain security
  - Method `__init__(self)`: No documentation provided.
  - Method `_get_version(self)`: No documentation provided.
  - Method `verify_signature(self, image, public_key)`: Verify container image signatures using cosign
- Class `GrypeScanner`: Integration with Grype vulnerability scanner
  - Method `__init__(self)`: No documentation provided.
  - Method `_get_version(self)`: No documentation provided.
  - Method `scan_target(self, target, output_format)`: Scan target for vulnerabilities using Grype
- Class `OSSIntegrationService`: Centralized service for managing OSS tool integrations
  - Method `__init__(self)`: No documentation provided.
  - Method `get_status(self)`: Get status of all OSS tools
  - Method `comprehensive_scan(self, target, image_type)`: Run comprehensive security scan using multiple tools
- Function `create_default_policies()`: Create default security policies for OPA

## Module: `services.policy_engine`
FixOps Policy Engine - High-performance policy evaluation with OPA/Rego support
Enterprise-grade decision automation with 299μs hot path performance and AI-powered insights

- Class `PolicyDecision`: No documentation provided.
- Class `PolicyContext`: Context for policy evaluation
  - Method `__post_init__(self)`: No documentation provided.
- Class `PolicyEvaluationResult`: Result of policy evaluation
- Class `PolicyEngine`: High-performance policy engine with multiple evaluation strategies
  - Method `__init__(self)`: No documentation provided.
  - Method `_initialize_llm(self)`: Initialize LLM for advanced policy analysis
  - Method `evaluate_policy(self, context)`: Evaluate policies for given context
  - Method `batch_evaluate_policies(self, contexts)`: Batch evaluate policies for multiple contexts
  - Method `_build_cache_key(self, context)`: Build deterministic cache key from context
  - Method `_get_applicable_policies(self, context)`: Get policies applicable to the given context with performance optimization
  - Method `_is_policy_applicable(self, policy, context)`: Check if policy is applicable to context
  - Method `_evaluate_single_policy(self, policy, context)`: Evaluate a single policy rule
  - Method `_evaluate_python_rule(self, policy, context)`: Evaluate Python-based policy rule
  - Method `_evaluate_json_rule(self, policy, context)`: Evaluate JSON-based policy rule
  - Method `_evaluate_rego_rule(self, policy, context)`: Evaluate OPA/Rego policy rule (simplified implementation)
  - Method `_combine_policy_results(self, evaluation_results, start_time)`: Combine multiple policy evaluation results into final decision
  - Method `_log_policy_decision(self, context, result, policies)`: Log policy decision for audit and compliance
  - Method `get_policy_stats(self)`: Get policy engine performance and usage statistics
- Function `evaluate_policy_async(context)`: Async wrapper for policy evaluation
- Function `batch_evaluate_policies_async(contexts)`: Async wrapper for batch policy evaluation

## Module: `services.processing_layer`
FixOps Processing Layer Implementation
Based on the architecture documentation showing specific components:
- Bayesian Prior Mapping (Custom)
- Markov Transition Matrix Builder (Custom)
- SSVC + Probabilistic Fusion Logic (Custom)  
- SARIF-Based Non-CVE Vulnerability Handling (Custom)
- Knowledge Graph Construction
- LLM Explanation Engine

- Function `_mean(values)`: Lightweight mean helper that avoids hard dependency on numpy.
- Function `_variance(values)`: Population variance helper compatible with single-value lists.
- Class `SSVCContext`: SSVC context for Bayesian prior mapping
- Class `MarkovState`: States for Markov transition modeling
- Class `SARIFVulnerability`: Non-CVE vulnerability from SARIF analysis
- Class `BayesianPriorMapping`: Bayesian Prior Mapping (Custom)
  - Method `__init__(self)`: No documentation provided.
  - Method `_initialize_network(self)`: Initialize Bayesian network with SSVC variables
  - Method `compute_priors(self, ssvc_context)`: Compute Bayesian priors based on SSVC context
  - Method `_heuristic_priors(self, ssvc_context)`: Fallback heuristic when Bayesian network unavailable
- Class `MarkovTransitionMatrixBuilder`: Markov Transition Matrix Builder using REAL mchmm library
  - Method `__init__(self)`: No documentation provided.
  - Method `_build_real_markov_model(self)`: Build real Markov model using mchmm library
  - Method `predict_state_evolution(self, current_states)`: Predict vulnerability state evolution using REAL mchmm library
  - Method `_calculate_transition_probs(self, current_state_idx, state)`: Calculate transition probabilities using real mchmm adjusted for EPSS/KEV
  - Method `_adjust_transitions_fallback(self, state)`: Fallback transition adjustment when mchmm unavailable
  - Method `_calculate_model_confidence(self, predictions)`: Calculate overall model confidence based on data quality
- Class `SSVCProbabilisticFusion`: SSVC + Probabilistic Fusion Logic (Custom)
  - Method `__init__(self)`: No documentation provided.
  - Method `fuse_decisions(self, ssvc_context, bayesian_priors, markov_predictions)`: Fuse SSVC decisions with probabilistic outputs
  - Method `_compute_ssvc_score(self, context)`: Compute deterministic SSVC score
  - Method `_extract_markov_risk(self, markov_predictions)`: Extract risk indicator from Markov predictions
  - Method `_fusion_algorithm(self, ssvc_score, bayesian_risk, markov_risk)`: Fusion algorithm combining all risk components
  - Method `_risk_to_decision(self, risk_score)`: Convert composite risk score to decision
  - Method `_calculate_fusion_confidence(self, ssvc, bayesian, markov)`: Calculate confidence in fusion result
  - Method `_generate_fusion_explanation(self, decision, risk_score)`: Generate human-readable explanation
- Class `SARIFVulnerabilityHandler`: SARIF-Based Non-CVE Vulnerability Handling (Custom)
  - Method `__init__(self)`: No documentation provided.
  - Method `_initialize_cwe_mapping(self)`: Initialize CWE to risk score mapping
  - Method `_initialize_owasp_mapping(self)`: Initialize OWASP category to risk score mapping
  - Method `process_sarif_findings(self, sarif_data)`: Process SARIF JSON and extract non-CVE vulnerabilities
  - Method `_extract_vulnerability(self, result)`: Extract vulnerability from SARIF result
  - Method `_extract_cwe(self, result)`: Extract CWE ID from SARIF result
  - Method `_extract_owasp(self, result)`: Extract OWASP category from SARIF result
  - Method `_calculate_confidence(self, result, cwe_id, owasp_category)`: Calculate confidence score for vulnerability
  - Method `_cluster_vulnerabilities(self, vulnerabilities)`: Cluster similar vulnerabilities for shared risk profiles
  - Method `_assess_clustered_risks(self, clusters)`: Assess risk for clustered vulnerabilities
  - Method `_calculate_cluster_risk(self, cluster)`: Calculate risk score for a vulnerability cluster
  - Method `_calculate_risk_distribution(self, clusters)`: Calculate distribution of risk levels
  - Method `_extract_tool_info(self, sarif_data)`: Extract information about tools used to generate SARIF
- Class `ProcessingLayer`: Main Processing Layer orchestrator that coordinates all components
  - Method `__init__(self)`: No documentation provided.
  - Method `process_security_context(self, ssvc_context, markov_states, sarif_data)`: Main processing pipeline that coordinates all components
  - Method `_initialize_additional_components(self)`: Initialize Knowledge Graph and LLM Explanation Engine

## Module: `services.real_opa_engine`
Real OPA (Open Policy Agent) Engine for Production Mode
- Demo Mode: Uses local rego evaluation
- Production Mode: Connects to real OPA server and evaluates policies

- Class `OPAEngine`: Base OPA Engine interface
  - Method `evaluate_policy(self, policy_name, input_data)`: Evaluate a policy with input data
  - Method `health_check(self)`: Check if OPA engine is healthy
- Class `DemoOPAEngine`: Demo OPA Engine with local rego evaluation
  - Method `__init__(self)`: No documentation provided.
  - Method `_load_demo_policies(self)`: Load demo policies for local evaluation
  - Method `evaluate_policy(self, policy_name, input_data)`: Evaluate policy using demo logic
  - Method `_evaluate_vulnerability_policy(self, input_data)`: Demo vulnerability policy evaluation
  - Method `_evaluate_sbom_policy(self, input_data)`: Demo SBOM policy evaluation
  - Method `health_check(self)`: Demo health check always returns True
- Class `ProductionOPAEngine`: Production OPA Engine with real OPA server
  - Method `__init__(self, opa_url)`: No documentation provided.
  - Method `_initialize_client(self)`: Initialize OPA client
  - Method `evaluate_policy(self, policy_name, input_data)`: Evaluate policy using real OPA server
  - Method `_evaluate_with_client(self, policy_name, input_data)`: Evaluate using OPA Python client
  - Method `_evaluate_with_http(self, policy_name, input_data)`: Evaluate using HTTP requests to OPA server
  - Method `health_check(self)`: Check if OPA server is healthy
- Class `OPAEngineFactory`: Factory for creating OPA engines based on mode
  - Method `create(settings)`: Create OPA engine based on demo mode setting
- Function `get_opa_engine()`: Get singleton OPA engine instance
- Function `evaluate_vulnerability_policy(vulnerabilities)`: Evaluate vulnerability policy
- Function `evaluate_sbom_policy(sbom_present, sbom_valid, sbom_data)`: Evaluate SBOM policy

## Module: `services.risk_scorer`
Context-aware risk scoring utilities for FixOps.

- Class `ContextualRiskScorer`: Apply business context aware adjustments to scanner findings.
  - Method `apply(self, findings, business_context)`: Return findings with context-aware risk adjustments applied.
  - Method `_adjust_finding(self, finding, business_context)`: No documentation provided.
  - Method `_calculate_adjustment(self, business_context)`: No documentation provided.
  - Method `_normalize_severity(self, severity)`: No documentation provided.
  - Method `_severity_index(self, severity)`: No documentation provided.

## Module: `services.sbom_parser`
SBOM parser service with optional lib4sbom integration.
Falls back to direct JSON parsing if lib4sbom is unavailable.

- Function `parse_sbom(content)`: No documentation provided.
- Function `_extract_findings_from_cyclonedx(sbom)`: No documentation provided.

## Module: `services.vector_store`
Real Vector Store Implementation with ChromaDB for Production Mode
- Demo Mode: Uses in-memory fallback with mock data
- Production Mode: Uses ChromaDB with real embeddings and similarity search

- Class `VectorRecord`: No documentation provided.
- Class `VectorStore`: No documentation provided.
  - Method `initialize(self)`: Initialize the vector store
  - Method `upsert(self, records)`: No documentation provided.
  - Method `search(self, embedding, top_k)`: No documentation provided.
  - Method `add_security_patterns(self, patterns)`: Add security patterns to vector store
  - Method `search_security_patterns(self, query_text, top_k)`: Search for similar security patterns
  - Method `_generate_embedding(self, text)`: Generate embedding for text - implement in subclasses
- Class `DemoVectorStore`: Demo mode with in-memory storage and mock embeddings
  - Method `__init__(self)`: No documentation provided.
  - Method `initialize(self)`: Initialize with demo security patterns
  - Method `upsert(self, records)`: Store records in memory for demo
  - Method `search(self, embedding, top_k)`: Demo cosine similarity search in memory
  - Method `_generate_embedding(self, text)`: Generate mock embedding for demo mode
- Class `ChromaDBVectorStore`: Production mode with real ChromaDB and embeddings
  - Method `__init__(self)`: No documentation provided.
  - Method `initialize(self)`: Initialize ChromaDB client and collection
  - Method `_initialize_embeddings(self)`: Initialize sentence transformers for embeddings
  - Method `_load_initial_patterns(self)`: Load initial security patterns into ChromaDB
  - Method `upsert(self, records)`: Store records in ChromaDB
  - Method `search(self, embedding, top_k)`: Search ChromaDB with embedding vector
  - Method `_generate_embedding(self, text)`: Generate real embedding using sentence transformers
  - Method `_fallback_embedding(self, text)`: Fallback embedding generation using hash
- Class `VectorStoreFactory`: Factory for creating vector store instances based on mode
  - Method `create(settings)`: Create vector store based on demo mode setting
- Function `get_vector_store()`: Get singleton vector store instance

## Module: `utils.crypto`
Enterprise cryptographic utilities and secure token generation

- Function `generate_secure_token(length)`: Generate cryptographically secure random token
- Function `generate_secure_password(length)`: Generate cryptographically secure password with mixed character types
- Function `generate_api_key(prefix, length)`: Generate API key with prefix for identification
- Function `hash_sensitive_data(data, salt)`: Hash sensitive data with salt for secure storage
- Function `verify_sensitive_data(data, stored_hash, salt)`: Verify sensitive data against stored hash
- Function `generate_encryption_key()`: Generate encryption key for Fernet symmetric encryption
- Function `encrypt_data(data, key)`: Encrypt data using Fernet symmetric encryption
- Function `decrypt_data(encrypted_data, key)`: Decrypt data using Fernet symmetric encryption
- Function `generate_checksum(data)`: Generate SHA-256 checksum for data integrity verification
- Function `verify_checksum(data, expected_checksum)`: Verify data integrity using checksum
- Function `generate_hmac_signature(data, secret_key)`: Generate HMAC signature for message authentication
- Function `verify_hmac_signature(data, signature, secret_key)`: Verify HMAC signature for message authentication
- Class `SecureTokenManager`: Manager for secure token operations with enterprise features
  - Method `__init__(self, secret_key)`: No documentation provided.
  - Method `generate_signed_token(self, payload, expiry_minutes)`: Generate signed token with payload and expiry
  - Method `verify_signed_token(self, token)`: Verify signed token and return payload if valid
  - Method `generate_hmac_signature(self, data, secret_key)`: Generate HMAC signature
  - Method `verify_hmac_signature(self, data, signature, secret_key)`: Verify HMAC signature
- Function `secure_compare(a, b)`: Timing-safe string comparison to prevent timing attacks
- Function `generate_nonce(length)`: Generate cryptographic nonce for one-time use
- Function `generate_salt(length)`: Generate cryptographic salt for password hashing

## Module: `utils.logger`
Enterprise structured logging with compliance and security features

- Function `setup_structured_logging()`: Configure structured logging for enterprise compliance
- Function `log_security_event(action, user_id, ip_address, user_agent, resource, resource_id, details, success, error_message)`: Log security events for audit compliance
- Class `PerformanceLogger`: Logger for performance monitoring and optimization
  - Method `log_hot_path_performance(endpoint, latency_us, user_id, additional_context)`: Log hot path performance metrics
  - Method `log_database_performance(operation, duration_ms, table, additional_context)`: Log database operation performance
  - Method `log_cache_performance(operation, cache_hit, duration_us, key)`: Log cache operation performance
- Class `ComplianceLogger`: Logger for compliance and regulatory requirements
  - Method `log_data_access(user_id, data_type, operation, record_ids, justification, ip_address)`: Log data access for compliance (GDPR, HIPAA, etc.)
  - Method `log_admin_action(admin_user_id, action, target_user_id, changes, ip_address)`: Log administrative actions for audit trails
  - Method `log_config_change(user_id, config_type, old_value, new_value, ip_address)`: Log configuration changes for security compliance
