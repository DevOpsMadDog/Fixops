# FixOps Functional Requirements

## Document Information
- **Version**: 1.0.0
- **Last Updated**: 2024-11-21
- **Status**: Draft

## 1. Overview

FixOps is a security decision automation platform with multi-LLM consensus, advanced risk forecasting, and compliance frameworks. This document specifies the functional requirements for all API endpoints and CLI commands.

## 2. API Endpoint Inventory

### 2.1 Application & Service Inventory APIs (15 endpoints)

#### 2.1.1 List Applications
- **Endpoint**: `GET /api/v1/inventory/applications`
- **Purpose**: List all registered applications with pagination
- **Authentication**: Required (API key)
- **Request Parameters**:
  - `limit` (query, optional): Results per page (1-1000, default: 100)
  - `offset` (query, optional): Pagination offset (default: 0)
- **Response**: 200 OK
  ```json
  {
    "items": [
      {
        "id": "uuid",
        "name": "string",
        "description": "string",
        "criticality": "critical|high|medium|low",
        "status": "active|deprecated|archived",
        "owner_team": "string",
        "repository_url": "string",
        "environment": "string",
        "tags": ["string"],
        "metadata": {},
        "created_at": "ISO8601",
        "updated_at": "ISO8601"
      }
    ],
    "total": 0,
    "limit": 100,
    "offset": 0
  }
  ```
- **Error Responses**:
  - 401: Unauthorized (missing or invalid API key)
  - 429: Too Many Requests (rate limit exceeded)

#### 2.1.2 Create Application
- **Endpoint**: `POST /api/v1/inventory/applications`
- **Purpose**: Register a new application in the inventory
- **Authentication**: Required (API key)
- **Request Body**:
  ```json
  {
    "name": "string (required, 1-255 chars)",
    "description": "string (required)",
    "criticality": "critical|high|medium|low (required)",
    "status": "active|deprecated|archived (optional, default: active)",
    "owner_team": "string (optional)",
    "repository_url": "string (optional)",
    "environment": "string (optional, default: production)",
    "tags": ["string"] (optional),
    "metadata": {} (optional)
  }
  ```
- **Response**: 201 Created
  ```json
  {
    "id": "uuid",
    "name": "string",
    ...
  }
  ```
- **Error Responses**:
  - 400: Bad Request (validation error)
  - 401: Unauthorized
  - 409: Conflict (duplicate name)

#### 2.1.3 Get Application
- **Endpoint**: `GET /api/v1/inventory/applications/{id}`
- **Purpose**: Get detailed information about a specific application
- **Authentication**: Required
- **Path Parameters**:
  - `id` (required): Application UUID
- **Response**: 200 OK (same schema as create response)
- **Error Responses**:
  - 404: Not Found (application doesn't exist)

#### 2.1.4 Update Application
- **Endpoint**: `PUT /api/v1/inventory/applications/{id}`
- **Purpose**: Update application details
- **Authentication**: Required
- **Request Body**: Same as create, all fields optional
- **Response**: 200 OK
- **Error Responses**:
  - 404: Not Found
  - 400: Bad Request

#### 2.1.5 Delete Application
- **Endpoint**: `DELETE /api/v1/inventory/applications/{id}`
- **Purpose**: Archive an application (soft delete)
- **Authentication**: Required
- **Response**: 204 No Content
- **Error Responses**:
  - 404: Not Found

#### 2.1.6 List Application Components
- **Endpoint**: `GET /api/v1/inventory/applications/{id}/components`
- **Purpose**: List all software components (libraries, packages) for an application
- **Authentication**: Required
- **Response**: 200 OK
  ```json
  {
    "application_id": "uuid",
    "components": [
      {
        "id": "uuid",
        "name": "string",
        "version": "string",
        "type": "library|package|framework",
        "license": "string",
        "source_url": "string",
        "created_at": "ISO8601"
      }
    ]
  }
  ```

#### 2.1.7 List Application APIs
- **Endpoint**: `GET /api/v1/inventory/applications/{id}/apis`
- **Purpose**: List all API endpoints exposed by an application
- **Authentication**: Required
- **Response**: 200 OK

#### 2.1.8 Get Application Dependencies
- **Endpoint**: `GET /api/v1/inventory/applications/{id}/dependencies`
- **Purpose**: Get dependency graph showing relationships between applications
- **Authentication**: Required
- **Response**: 200 OK with graph structure

#### 2.1.9 List Services
- **Endpoint**: `GET /api/v1/inventory/services`
- **Purpose**: List all microservices with pagination
- **Authentication**: Required
- **Response**: 200 OK

#### 2.1.10 Create Service
- **Endpoint**: `POST /api/v1/inventory/services`
- **Purpose**: Register a new microservice
- **Authentication**: Required
- **Response**: 201 Created

#### 2.1.11 Get Service
- **Endpoint**: `GET /api/v1/inventory/services/{id}`
- **Purpose**: Get service details
- **Authentication**: Required
- **Response**: 200 OK

#### 2.1.12 List APIs
- **Endpoint**: `GET /api/v1/inventory/apis`
- **Purpose**: List all API endpoints across all services
- **Authentication**: Required
- **Response**: 200 OK

#### 2.1.13 Create API
- **Endpoint**: `POST /api/v1/inventory/apis`
- **Purpose**: Register a new API endpoint
- **Authentication**: Required
- **Response**: 201 Created

#### 2.1.14 Get API Security
- **Endpoint**: `GET /api/v1/inventory/apis/{id}/security`
- **Purpose**: Get security posture analysis for an API endpoint
- **Authentication**: Required
- **Response**: 200 OK
  ```json
  {
    "api_id": "uuid",
    "security_score": 85,
    "vulnerabilities": [],
    "compliance_status": "compliant|non-compliant"
  }
  ```

#### 2.1.15 Search Inventory
- **Endpoint**: `GET /api/v1/inventory/search`
- **Purpose**: Search across all inventory types
- **Authentication**: Required
- **Request Parameters**:
  - `q` (query, required): Search query (min 1 char)
  - `limit` (query, optional): Results per page (1-1000, default: 100)
- **Response**: 200 OK
  ```json
  {
    "applications": [],
    "services": [],
    "apis": [],
    "components": []
  }
  ```

### 2.2 Team & User Management APIs (12 endpoints)

[To be implemented in Phase 2]

- `GET /api/v1/users` - List users
- `POST /api/v1/users` - Create user
- `GET /api/v1/users/{id}` - Get user
- `PUT /api/v1/users/{id}` - Update user
- `DELETE /api/v1/users/{id}` - Deactivate user
- `GET /api/v1/teams` - List teams
- `POST /api/v1/teams` - Create team
- `GET /api/v1/teams/{id}` - Get team
- `PUT /api/v1/teams/{id}` - Update team
- `GET /api/v1/teams/{id}/members` - List team members
- `POST /api/v1/teams/{id}/members` - Add member
- `DELETE /api/v1/teams/{id}/members/{user_id}` - Remove member

### 2.3 Policy Management APIs (10 endpoints)

[To be implemented in Phase 2]

### 2.4 Dashboard & Analytics APIs (12 endpoints)

[To be implemented in Phase 3]

### 2.5 Integration Management APIs (8 endpoints)

[To be implemented in Phase 3]

### 2.6 Reporting & Export APIs (8 endpoints)

[To be implemented in Phase 4]

### 2.7 Audit & Compliance APIs (10 endpoints)

[To be implemented in Phase 4]

### 2.8 Workflow & Automation APIs (5 endpoints)

[To be implemented in Phase 4]

## 3. CLI Commands

### 3.1 Inventory Commands

#### 3.1.1 List Applications
```bash
fixops inventory list [--limit N] [--offset N] [--format table|json]
```
- Lists all applications with pagination
- Default format: table
- Returns exit code 0 on success

#### 3.1.2 Create Application
```bash
fixops inventory create \
  --name "App Name" \
  --description "Description" \
  --criticality critical|high|medium|low \
  [--environment production] \
  [--owner-team "Team Name"] \
  [--repo-url "https://..."]
```
- Creates new application
- Prints application ID and JSON on success
- Returns exit code 0 on success, 1 on failure

#### 3.1.3 Get Application
```bash
fixops inventory get <id> [--format table|json]
```
- Gets application details by ID
- Default format: json
- Returns exit code 0 if found, 1 if not found

#### 3.1.4 Update Application
```bash
fixops inventory update <id> \
  [--name "New Name"] \
  [--description "New Description"] \
  [--criticality critical|high|medium|low] \
  [--status active|deprecated|archived]
```
- Updates application fields
- Only specified fields are updated
- Returns exit code 0 on success

#### 3.1.5 Delete Application
```bash
fixops inventory delete <id> --confirm
```
- Deletes application (requires --confirm flag)
- Returns exit code 0 on success, 1 on failure

#### 3.1.6 Search Inventory
```bash
fixops inventory search <query> [--limit N]
```
- Searches across all inventory types
- Returns JSON with results
- Returns exit code 0 on success

## 4. Business Rules

### 4.1 Application Management
- Application names must be unique within an environment
- Criticality levels affect risk scoring and decision thresholds
- Status transitions: active → deprecated → archived
- Archived applications cannot be modified (only restored)

### 4.2 Authentication & Authorization
- All API endpoints require valid API key in X-API-Key header
- CLI commands use FIXOPS_API_TOKEN environment variable
- Rate limiting: 60 requests/minute per API key (configurable)

### 4.3 Data Validation
- UUIDs generated server-side for all new entities
- Timestamps in ISO8601 format with UTC timezone
- Tags limited to 50 per entity
- Metadata JSON limited to 10KB per entity

### 4.4 Pagination
- Default limit: 100 items
- Maximum limit: 1000 items
- Offset-based pagination (consider cursor-based for Phase 2)

## 5. Integration Points

### 5.1 Existing FixOps Components
- **Evidence Generation**: Application criticality affects evidence bundle metadata
- **Risk Assessment**: Application environment (internet-facing, internal) affects exposure multipliers
- **Compliance Mapping**: Application inventory enables compliance coverage reporting
- **Policy Automation**: Applications can be linked to Jira projects for automated ticket creation

### 5.2 External Systems
- **SBOM Ingestion**: Automatically populates components when SBOM uploaded
- **SARIF Ingestion**: Links findings to applications for contextualized risk assessment
- **CI/CD Integration**: API can be called from pipeline to register/update applications

## 6. Future Enhancements

### Phase 2 (Users, Teams, Policies)
- RBAC with role-based permissions
- Team-based application ownership
- Policy CRUD with validation

### 2.4 Dashboard & Analytics APIs (12 endpoints)

#### 2.4.1 Get Dashboard Overview
- **Endpoint**: `GET /api/v1/analytics/dashboard/overview`
- **Purpose**: Get comprehensive security posture overview
- **Authentication**: Required (API key)
- **Response**: 200 OK
  ```json
  {
    "total_findings": 0,
    "open_findings": 0,
    "critical_findings": 0,
    "high_findings": 0,
    "findings_by_severity": {
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 0,
      "info": 0
    },
    "findings_by_status": {
      "open": 0,
      "in_progress": 0,
      "resolved": 0,
      "false_positive": 0,
      "accepted_risk": 0
    },
    "total_decisions": 0,
    "decisions_by_outcome": {
      "block": 0,
      "alert": 0,
      "allow": 0,
      "review": 0
    }
  }
  ```

#### 2.4.2 Get Dashboard Trends
- **Endpoint**: `GET /api/v1/analytics/dashboard/trends`
- **Purpose**: Get time-series trend data for security metrics
- **Authentication**: Required
- **Request Parameters**:
  - `days` (query, optional): Number of days to include (default: 30)
- **Response**: 200 OK
  ```json
  {
    "period_days": 30,
    "findings_trend": [
      {"date": "2024-11-01", "count": 10, "critical": 2, "high": 5}
    ],
    "resolution_trend": [
      {"date": "2024-11-01", "resolved": 5, "mttr_hours": 24.5}
    ]
  }
  ```

#### 2.4.3 Get Top Risks
- **Endpoint**: `GET /api/v1/analytics/dashboard/top-risks`
- **Purpose**: Get highest priority security risks
- **Authentication**: Required
- **Request Parameters**:
  - `limit` (query, optional): Number of risks to return (default: 10)
- **Response**: 200 OK
  ```json
  {
    "risks": [
      {
        "finding_id": "uuid",
        "title": "string",
        "severity": "critical",
        "cvss_score": 9.8,
        "epss_score": 0.95,
        "exploitable": true,
        "application_id": "uuid",
        "risk_score": 95.0
      }
    ]
  }
  ```

#### 2.4.4 Get Compliance Status
- **Endpoint**: `GET /api/v1/analytics/dashboard/compliance-status`
- **Purpose**: Get compliance framework status
- **Authentication**: Required
- **Response**: 200 OK
  ```json
  {
    "frameworks": [
      {
        "name": "SOC2",
        "coverage": 85.5,
        "passing_controls": 34,
        "total_controls": 40,
        "failing_controls": 6
      }
    ]
  }
  ```

#### 2.4.5 Query Findings
- **Endpoint**: `GET /api/v1/analytics/findings`
- **Purpose**: Query findings with filtering and pagination
- **Authentication**: Required
- **Request Parameters**:
  - `severity` (query, optional): Filter by severity
  - `status` (query, optional): Filter by status
  - `application_id` (query, optional): Filter by application
  - `limit` (query, optional): Results per page (default: 100)
  - `offset` (query, optional): Pagination offset (default: 0)
- **Response**: 200 OK (array of Finding objects)

#### 2.4.6 Create Finding
- **Endpoint**: `POST /api/v1/analytics/findings`
- **Purpose**: Create a new security finding
- **Authentication**: Required
- **Request Body**:
  ```json
  {
    "rule_id": "string (required)",
    "severity": "critical|high|medium|low|info (required)",
    "status": "open|in_progress|resolved|false_positive|accepted_risk (required)",
    "title": "string (required)",
    "description": "string (required)",
    "source": "string (required)",
    "application_id": "string (optional)",
    "service_id": "string (optional)",
    "cve_id": "string (optional)",
    "cvss_score": "float (optional)",
    "epss_score": "float (optional)",
    "exploitable": "boolean (optional)",
    "metadata": {} (optional)
  }
  ```
- **Response**: 201 Created

#### 2.4.7 Get Finding
- **Endpoint**: `GET /api/v1/analytics/findings/{id}`
- **Purpose**: Get detailed finding information
- **Authentication**: Required
- **Response**: 200 OK
- **Error Responses**: 404 Not Found

#### 2.4.8 Update Finding
- **Endpoint**: `PUT /api/v1/analytics/findings/{id}`
- **Purpose**: Update finding status or details
- **Authentication**: Required
- **Request Body**: Same as create, all fields optional
- **Response**: 200 OK

#### 2.4.9 Query Decisions
- **Endpoint**: `GET /api/v1/analytics/decisions`
- **Purpose**: Query decision history with filtering
- **Authentication**: Required
- **Request Parameters**:
  - `finding_id` (query, optional): Filter by finding
  - `outcome` (query, optional): Filter by outcome
  - `limit` (query, optional): Results per page (default: 100)
  - `offset` (query, optional): Pagination offset (default: 0)
- **Response**: 200 OK (array of Decision objects)

#### 2.4.10 Create Decision
- **Endpoint**: `POST /api/v1/analytics/decisions`
- **Purpose**: Record a security decision
- **Authentication**: Required
- **Request Body**:
  ```json
  {
    "finding_id": "string (required)",
    "outcome": "block|alert|allow|review (required)",
    "confidence": "float 0-1 (required)",
    "reasoning": "string (required)",
    "llm_votes": {} (optional),
    "policy_matched": "string (optional)"
  }
  ```
- **Response**: 201 Created

#### 2.4.11 Get MTTR
- **Endpoint**: `GET /api/v1/analytics/mttr`
- **Purpose**: Calculate mean time to remediation
- **Authentication**: Required
- **Response**: 200 OK
  ```json
  {
    "mttr_hours": 24.5,
    "mttr_days": 1.02,
    "sample_size": 150
  }
  ```

#### 2.4.12 Get Coverage Metrics
- **Endpoint**: `GET /api/v1/analytics/coverage`
- **Purpose**: Get security coverage metrics
- **Authentication**: Required
- **Response**: 200 OK
  ```json
  {
    "total_findings": 500,
    "scanned_applications": 25,
    "total_applications": 30,
    "coverage_percentage": 83.3,
    "scan_types": {
      "SAST": 200,
      "DAST": 150,
      "SCA": 150
    }
  }
  ```

#### 2.4.13 Get ROI Calculations
- **Endpoint**: `GET /api/v1/analytics/roi`
- **Purpose**: Calculate return on investment metrics
- **Authentication**: Required
- **Response**: 200 OK
  ```json
  {
    "total_findings": 500,
    "critical_blocked": 25,
    "estimated_prevented_cost": 1060000.0,
    "currency": "USD",
    "avg_breach_cost": 4240000,
    "critical_breach_probability": 0.15
  }
  ```

#### 2.4.14 Get Noise Reduction
- **Endpoint**: `GET /api/v1/analytics/noise-reduction`
- **Purpose**: Calculate noise reduction metrics
- **Authentication**: Required
- **Response**: 200 OK
  ```json
  {
    "total_findings": 500,
    "false_positives": 150,
    "noise_reduction_percentage": 30.0,
    "signal_to_noise_ratio": 2.33
  }
  ```

#### 2.4.15 Custom Query
- **Endpoint**: `POST /api/v1/analytics/custom-query`
- **Purpose**: Execute custom analytics query
- **Authentication**: Required
- **Request Body**:
  ```json
  {
    "type": "findings|decisions|metrics",
    "filters": {},
    "aggregations": []
  }
  ```
- **Response**: 200 OK

#### 2.4.16 Export Analytics
- **Endpoint**: `GET /api/v1/analytics/export`
- **Purpose**: Export analytics data in various formats
- **Authentication**: Required
- **Request Parameters**:
  - `format` (query, required): Export format (json|csv)
  - `data_type` (query, required): Data type to export (findings|decisions|metrics)
- **Response**: 200 OK

### 2.5 Integration Management APIs (8 endpoints)

#### 2.5.1 List Integrations
- **Endpoint**: `GET /api/v1/integrations`
- **Purpose**: List all configured integrations
- **Authentication**: Required (API key)
- **Request Parameters**:
  - `integration_type` (query, optional): Filter by type
  - `limit` (query, optional): Results per page (default: 100)
  - `offset` (query, optional): Pagination offset (default: 0)
- **Response**: 200 OK
  ```json
  {
    "items": [
      {
        "id": "uuid",
        "name": "string",
        "integration_type": "jira|confluence|slack|github|gitlab|pagerduty",
        "status": "active|inactive|error",
        "config": {},
        "last_sync_at": "ISO8601",
        "last_sync_status": "string",
        "created_at": "ISO8601",
        "updated_at": "ISO8601"
      }
    ],
    "total": 0,
    "limit": 100,
    "offset": 0
  }
  ```

#### 2.5.2 Create Integration
- **Endpoint**: `POST /api/v1/integrations`
- **Purpose**: Add a new integration
- **Authentication**: Required
- **Request Body**:
  ```json
  {
    "name": "string (required)",
    "integration_type": "jira|confluence|slack|github|gitlab|pagerduty (required)",
    "status": "active|inactive (optional, default: active)",
    "config": {} (required)
  }
  ```
- **Response**: 201 Created

#### 2.5.3 Get Integration
- **Endpoint**: `GET /api/v1/integrations/{id}`
- **Purpose**: Get integration details
- **Authentication**: Required
- **Response**: 200 OK
- **Error Responses**: 404 Not Found

#### 2.5.4 Update Integration
- **Endpoint**: `PUT /api/v1/integrations/{id}`
- **Purpose**: Update integration configuration
- **Authentication**: Required
- **Request Body**: Same as create, all fields optional
- **Response**: 200 OK

#### 2.5.5 Delete Integration
- **Endpoint**: `DELETE /api/v1/integrations/{id}`
- **Purpose**: Remove an integration
- **Authentication**: Required
- **Response**: 204 No Content

#### 2.5.6 Test Integration
- **Endpoint**: `POST /api/v1/integrations/{id}/test`
- **Purpose**: Test integration connection
- **Authentication**: Required
- **Response**: 200 OK
  ```json
  {
    "integration_id": "uuid",
    "success": true,
    "message": "string",
    "details": {}
  }
  ```

#### 2.5.7 Get Sync Status
- **Endpoint**: `GET /api/v1/integrations/{id}/sync-status`
- **Purpose**: Get integration sync status
- **Authentication**: Required
- **Response**: 200 OK
  ```json
  {
    "integration_id": "uuid",
    "last_sync_at": "ISO8601",
    "last_sync_status": "string",
    "status": "active"
  }
  ```

#### 2.5.8 Trigger Sync
- **Endpoint**: `POST /api/v1/integrations/{id}/sync`
- **Purpose**: Manually trigger integration sync
- **Authentication**: Required
- **Response**: 200 OK
  ```json
  {
    "integration_id": "uuid",
    "sync_triggered": true,
    "sync_time": "ISO8601",
    "message": "string"
  }
  ```

### Phase 4 (Reports, Audit, Workflows)
- Scheduled report generation
- Comprehensive audit trail
- Workflow orchestration engine

## 7. Success Criteria

### Phase 1 (Complete)
- All 15 inventory endpoints functional and tested
- CLI commands working for all inventory operations
- Comprehensive test coverage (>80%)
- Documentation complete and accurate

### Phase 2 (Complete)
- All 22 user/team/policy endpoints functional and tested
- JWT authentication and bcrypt password hashing implemented
- RBAC with 4 roles (admin, security_analyst, developer, viewer)
- CLI commands for users, teams, and policies

### Phase 3 (Complete)
- All 20 analytics/integration endpoints functional and tested
- Dashboard overview, trends, top risks, compliance status
- Finding and decision tracking with MTTR calculation
- Integration management with connection testing
- CLI commands for analytics queries and integration management

### General Requirements
- Zero critical security vulnerabilities
- Performance: <200ms response time for list operations
- Scalability: Support 10,000+ applications without degradation
- Test coverage: >80% for all new code
- All code passes lint, format, and type checks
