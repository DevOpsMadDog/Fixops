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

### Phase 3 (Analytics, Integrations)
- Time-series analytics for security trends
- Integration health monitoring
- Custom dashboard configuration

### Phase 4 (Reports, Audit, Workflows)
- Scheduled report generation
- Comprehensive audit trail
- Workflow orchestration engine

## 7. Success Criteria

- All 15 Phase 1 endpoints functional and tested
- CLI commands working for all inventory operations
- Comprehensive test coverage (>80%)
- Documentation complete and accurate
- Zero critical security vulnerabilities
- Performance: <200ms response time for list operations
- Scalability: Support 10,000+ applications without degradation
