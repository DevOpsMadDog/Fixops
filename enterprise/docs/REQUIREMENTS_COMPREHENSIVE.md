# FixOps Enterprise - Functional & Non-Functional Requirements

## Executive Summary

FixOps is an Enterprise DevSecOps Decision & Verification Engine that provides AI-powered security decision automation for CI/CD pipelines. It delivers ALLOW/BLOCK/DEFER decisions with evidence and confidence scores using multi-LLM consensus, Bayesian/Markov modeling, and SSVC framework compliance.

**Unique Value Proposition**: First multi-LLM consensus engine for DevSecOps with 299μs hot path performance and immutable evidence lake for enterprise audit compliance.

---

## Functional Requirements

### FR-001: Multi-Modal Scan Ingestion
- **Description**: Ingest security scans from multiple sources and formats
- **Acceptance Criteria**:
  - Support SARIF, SBOM (CycloneDX/SPDX), CSV, JSON formats
  - Chunked file upload for large files (max 100MB)
  - File validation and format detection
  - Progress tracking and resume capability
- **Priority**: HIGH
- **Dependencies**: FastAPI file upload, async processing

### FR-002: Business Context Integration
- **Description**: Inject business context for enhanced decision accuracy
- **Acceptance Criteria**:
  - Support FixOps.yaml native format with SSVC factors
  - Support OTM.json (Open Threat Model) with automatic SSVC conversion
  - SSVC.yaml pure CISA/SEI format support
  - Business criticality, data classification, compliance mapping
- **Priority**: HIGH
- **Dependencies**: SSVC framework, threat model parsing

### FR-003: Multi-LLM Consensus Engine
- **Description**: AI-powered consensus decision making using multiple models
- **Acceptance Criteria**:
  - GPT-5, Claude, Gemini integration with Emergent LLM
  - Disagreement analysis and confidence scoring
  - Individual model analysis tracking
  - Consensus algorithm with weighted voting
- **Priority**: HIGH
- **Dependencies**: Emergent LLM API, model orchestration

### FR-004: Processing Layer Architecture
- **Description**: Sophisticated vulnerability analysis using advanced algorithms
- **Acceptance Criteria**:
  - Bayesian Prior Mapping using pgmpy/pomegranate
  - Markov Transition Matrix Builder using mchmm
  - SSVC Probabilistic Fusion Logic
  - SARIF-Based Non-CVE Vulnerability Handling
  - Knowledge Graph Construction using NetworkX
- **Priority**: HIGH
- **Dependencies**: pgmpy, mchmm, pomegranate, NetworkX

### FR-005: Decision & Verification Engine
- **Description**: Core decision engine producing ALLOW/BLOCK/DEFER outcomes
- **Acceptance Criteria**:
  - Decision context processing (service, environment, findings)
  - Evidence generation with cryptographic integrity
  - Confidence scoring and consensus validation
  - Performance tracking and hot path optimization
- **Priority**: CRITICAL
- **Dependencies**: All processing components

### FR-006: Policy Engine Integration
- **Description**: Policy evaluation using OPA/Rego for compliance
- **Acceptance Criteria**:
  - OPA server integration for policy evaluation
  - Vulnerability and SBOM policy templates
  - Compliance framework mapping (NIST, SOC2, PCI)
  - Policy decision logging and audit
- **Priority**: HIGH
- **Dependencies**: OPA server, rego policies

### FR-007: Evidence Lake
- **Description**: Immutable audit trail for compliance and forensics
- **Acceptance Criteria**:
  - Cryptographic evidence integrity (SHA256)
  - 7-year retention for SOX/PCI compliance
  - Evidence retrieval and verification
  - Audit log integration
- **Priority**: HIGH
- **Dependencies**: Database storage, cryptographic signing

### FR-008: CI/CD Integration
- **Description**: Command-line interface for pipeline automation
- **Acceptance Criteria**:
  - CLI commands: ingest, make-decision, health, get-evidence
  - Exit codes for pipeline gating (0=ALLOW, 1=BLOCK, 2=DEFER)
  - JSON output for automation integration
  - Performance optimization for CI/CD speed
- **Priority**: HIGH
- **Dependencies**: Typer CLI framework, async processing

### FR-009: Vector Database Integration
- **Description**: Similarity search for security pattern matching
- **Acceptance Criteria**:
  - ChromaDB integration with sentence transformers
  - Security pattern storage and retrieval
  - Similarity search with confidence scoring
  - Pattern database initialization and management
- **Priority**: MEDIUM
- **Dependencies**: ChromaDB, sentence-transformers

### FR-010: External Feed Integration
- **Description**: Threat intelligence enrichment from external sources
- **Acceptance Criteria**:
  - EPSS (Exploit Prediction Scoring System) integration
  - KEV (Known Exploited Vulnerabilities) feed
  - Automated feed refresh and caching
  - Threat intelligence correlation
- **Priority**: MEDIUM
- **Dependencies**: External API access, scheduled tasks

---

## Non-Functional Requirements

### NFR-001: Performance
- **Hot Path Latency**: < 299μs for critical decision paths
- **Decision Latency**: < 2 seconds for complete multi-LLM analysis
- **Throughput**: Support 1000+ decisions per hour
- **Scalability**: Horizontal scaling with Kubernetes
- **Memory**: < 2GB per instance under normal load

### NFR-002: Reliability & Availability
- **Uptime**: 99.9% SLA (8.77 hours downtime/year max)
- **Fault Tolerance**: Graceful degradation when external services unavailable
- **Data Durability**: 99.999999999% (11 9's) for evidence records
- **Backup**: Automated daily backups with point-in-time recovery
- **Disaster Recovery**: < 4 hour RTO, < 1 hour RPO

### NFR-003: Security
- **Authentication**: OAuth2/OIDC integration capability
- **Authorization**: Role-based access control (RBAC)
- **Encryption**: TLS 1.3 for transit, AES-256 for rest
- **Secrets Management**: Kubernetes secrets integration
- **Audit**: Comprehensive audit logging for all decisions
- **Compliance**: SOX, PCI DSS, SOC2, HIPAA compatible

### NFR-004: Scalability
- **Horizontal Scaling**: Stateless design for multi-replica deployment
- **Database**: MongoDB/PostgreSQL clustering support
- **Cache**: Redis clustering for high availability
- **Load Balancing**: Support for multiple backend instances
- **Auto-scaling**: HPA integration for demand-based scaling

### NFR-005: Monitoring & Observability
- **Metrics**: Prometheus integration with custom metrics
- **Logging**: Structured logging with correlation IDs
- **Tracing**: OpenTelemetry integration
- **Dashboards**: Grafana dashboard templates
- **Alerting**: Critical system alerts and thresholds

### NFR-006: Deployment & Operations
- **Containerization**: Docker containers with minimal attack surface
- **Kubernetes**: Native K8s deployment with Helm charts
- **Environment**: Support for dev/staging/production environments
- **Configuration**: Environment-based configuration management
- **Rolling Updates**: Zero-downtime deployments

### NFR-007: Data Management
- **Persistence**: SQLite for development, PostgreSQL for production
- **Backup**: Automated backup with encryption
- **Retention**: Configurable data retention policies
- **Migration**: Database schema migration support
- **Performance**: Optimized queries and indexing

### NFR-008: Integration
- **API**: RESTful API with OpenAPI documentation
- **Webhooks**: Event-driven integration support
- **CLI**: Full-featured command-line interface
- **SDK**: Python SDK for programmatic access
- **Standards**: SSVC, SARIF, CycloneDX compliance

---

## Production Dependencies

### Critical Dependencies (Required for Production)
1. **EMERGENT_LLM_KEY**: Multi-LLM consensus functionality
2. **OPA_SERVER**: Policy evaluation (docker run -p 8181:8181 openpolicyagent/opa:latest run --server)
3. **DATABASE_URL**: Production database (PostgreSQL recommended)

### Optional Dependencies (Enhanced Functionality)
1. **JIRA_CREDENTIALS**: Business context enrichment
2. **CONFLUENCE_CREDENTIALS**: Threat model integration  
3. **PGVECTOR_DSN**: Vector database for pattern matching
4. **THREAT_INTEL_API_KEY**: External threat intelligence

### Demo Mode
- **Zero Dependencies**: Complete functionality with simulated data
- **Self-Contained**: No external API keys or servers required
- **Showcase Ready**: Professional demonstration capability

---

## Architecture Overview

### Core Components
1. **Decision Engine**: Central orchestrator with dual-mode support
2. **Processing Layer**: Bayesian + Markov + SSVC + Knowledge Graph
3. **Multi-LLM Engine**: AI consensus with disagreement analysis
4. **Policy Engine**: OPA integration with compliance validation
5. **Evidence Lake**: Immutable audit trail with cryptographic integrity
6. **Vector Store**: ChromaDB for security pattern similarity search

### Data Flow
```
Scan Upload → Business Context → Processing Layer → Multi-LLM Analysis → Policy Evaluation → Decision + Evidence
```

### Technology Stack
- **Backend**: FastAPI, SQLAlchemy, async/await
- **Frontend**: React, Vite, Tailwind CSS
- **Database**: SQLite (dev), PostgreSQL (prod)
- **Cache**: Redis
- **AI**: Emergent LLM, pgmpy, mchmm, pomegranate
- **Policy**: OPA/Rego
- **Vector**: ChromaDB + sentence-transformers

---

## Success Criteria

### Business Success
- **Cost Avoidance**: $15K per prevented security incident
- **Time Savings**: 18 hours developer time saved per week
- **ROI**: 6-month payback period typical
- **False Positive Reduction**: 78% vs traditional SAST/SCA tools

### Technical Success  
- **Performance**: Maintain 299μs hot path latency
- **Accuracy**: 94%+ multi-LLM consensus accuracy
- **Reliability**: 99.9% uptime achievement
- **Compliance**: 100% SSVC framework adherence

### User Success
- **Adoption**: Seamless CI/CD integration
- **Usability**: Intuitive enterprise UI for all roles
- **Trust**: Transparent decision reasoning and evidence
- **Support**: Comprehensive documentation and examples

---

**Last Updated**: 2024-10-02  
**Version**: 1.0  
**Status**: Production Ready (with dependencies)