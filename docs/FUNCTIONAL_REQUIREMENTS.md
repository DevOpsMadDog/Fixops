# FixOps Functional Requirements

## Core Pipeline (16 endpoints)
- Health check and status endpoints
- Artifact ingestion (SARIF, SBOM, CVE feeds)
- Pipeline orchestration and decision making
- Evidence bundle generation
- Analytics and feedback collection

## Phase 1: Inventory Management (15 endpoints)
- Application inventory CRUD operations
- Service inventory management
- Component tracking
- API endpoint discovery
- Security posture tracking

## Phase 2: User & Team Management (22 endpoints)
- User authentication and JWT token management
- User CRUD operations with 4-role RBAC (admin, security_analyst, developer, viewer)
- Team management and membership
- Policy management with validation and testing
- Policy violation tracking

## Phase 3: Analytics & Integrations (24 endpoints)
- Security dashboard with overview, trends, top risks
- Finding management and querying
- Decision history tracking
- MTTR, coverage, ROI, and noise reduction metrics
- Integration management (Jira, Confluence, Slack, etc.)
- Integration testing and sync operations

## Phase 4: Reports, Audit, Workflows (26 endpoints)
- Report generation (PDF, HTML, JSON, CSV, SARIF)
- Report scheduling and templates
- Audit log querying and user activity tracking
- Compliance framework management
- Compliance gap analysis and reporting
- Workflow orchestration and execution history

## Phase 5: Enterprise Features (22 endpoints)
- SSO/SAML authentication configuration
- Secrets detection and scanning
- IaC scanning (Terraform, CloudFormation, Kubernetes, Ansible, Helm)
- Bulk operations (findings, policies, integrations)
- IDE extension support (diagnostics, quick fixes, code actions)

## Phase 6: Pentagi Integration (12 endpoints)

### Pen Test Request Management (6 endpoints)
1. **GET /api/v1/pentagi/requests** - List pen test requests
   - Query params: finding_id, status, limit, offset
   - Returns: Paginated list of requests with status and priority

2. **POST /api/v1/pentagi/requests** - Create pen test request
   - Body: finding_id, target_url, vulnerability_type, test_case, priority
   - Returns: Created request with generated ID

3. **GET /api/v1/pentagi/requests/{id}** - Get pen test request
   - Returns: Full request details including metadata

4. **PUT /api/v1/pentagi/requests/{id}** - Update pen test request
   - Body: status, pentagi_job_id, metadata updates
   - Returns: Updated request

5. **POST /api/v1/pentagi/requests/{id}/start** - Start pen test
   - Triggers Pentagi execution for the request
   - Returns: Updated request with running status

6. **POST /api/v1/pentagi/requests/{id}/cancel** - Cancel pen test
   - Cancels running Pentagi test
   - Returns: Updated request with cancelled status

### Pen Test Results (3 endpoints)
1. **GET /api/v1/pentagi/results** - List pen test results
   - Query params: finding_id, exploitability, limit, offset
   - Returns: Paginated list of results with exploitability levels

2. **POST /api/v1/pentagi/results** - Create pen test result
   - Body: request_id, finding_id, exploitability, exploit_successful, evidence, steps_taken, artifacts, confidence_score
   - Returns: Created result with generated ID

3. **GET /api/v1/pentagi/results/by-request/{request_id}** - Get result by request
   - Returns: Result associated with specific request

### Pentagi Configuration (5 endpoints)
1. **GET /api/v1/pentagi/configs** - List Pentagi configurations
   - Query params: limit, offset
   - Returns: Paginated list of configurations

2. **POST /api/v1/pentagi/configs** - Create Pentagi configuration
   - Body: name, pentagi_url, api_key, enabled, max_concurrent_tests, timeout_seconds, auto_trigger, target_environments
   - Returns: Created configuration (API key masked)

3. **GET /api/v1/pentagi/configs/{id}** - Get Pentagi configuration
   - Returns: Full configuration details (API key masked)

4. **PUT /api/v1/pentagi/configs/{id}** - Update Pentagi configuration
   - Body: Any configuration fields to update
   - Returns: Updated configuration

5. **DELETE /api/v1/pentagi/configs/{id}** - Delete Pentagi configuration
   - Returns: Deletion confirmation

**Total API Surface: 137 endpoints** (16 core + 121 from Phases 1-6)

## Key Design Principles

### Severity vs Exploitability Separation
- **Severity**: CVSS-based score (1-10) representing vulnerability impact
- **Exploitability**: Pentagi-validated level representing actual exploitability
  - confirmed_exploitable: Successfully exploited in controlled environment
  - likely_exploitable: High confidence of exploitability
  - unexploitable: Cannot be exploited in current configuration
  - blocked: Exploit attempts blocked by security controls
  - inconclusive: Test results unclear or incomplete

### Priority Calculation
- Exploitability boosts priority without replacing severity
- Example: "Medium Severity + Confirmed Exploitable" → High Priority
- Findings display both dimensions clearly in UX

### Integration Points
1. **Pipeline Orchestrator** - Step 4.6 (after historical correlation)
2. **Correlation Engine** - Feed exploit patterns back for improved correlation
3. **Evidence Hub** - Store pen test results as cryptographically signed evidence
4. **Vector Store** - Index successful exploits for similarity matching
5. **Run History Store** - Track exploitation outcomes alongside existing outcomes
6. **SSDLC Evaluator** - Trigger pen tests at design/dev/build/staging/production stages
