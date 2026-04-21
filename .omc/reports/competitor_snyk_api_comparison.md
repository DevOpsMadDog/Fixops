# Snyk API vs. ALDECI API — Competitive Comparison

**Date:** 2026-04-17
**Author:** Executor agent (competitive research)
**Scope:** Snyk REST API + V1 API endpoint inventory vs. ALDECI supply chain, SBOM, and vulnerability API surface
**Prior art:** `competitor_snyk_analysis.md` (UI comparison, same date)

---

## 1. Snyk API Overview

### 1.1 API Variants

Snyk exposes three distinct API layers:

| API | Base URL | Status | Purpose |
|-----|----------|--------|---------|
| REST API | `https://api.snyk.io/rest/` | GA (recommended) | Modern JSON:API, versioned by date |
| V1 API | `https://snyk.io/api/v1/` | Legacy (maintained) | Older endpoints, broader coverage of scan/test operations |
| OAuth2 API | `https://app.snyk.io/oauth2/` | GA | Token exchange for Snyk Apps |

### 1.2 Authentication

| Method | Use Case |
|--------|----------|
| API Token (Bearer) | Standard programmatic access — `Authorization: token <API_TOKEN>` |
| Personal Access Token (PAT) | User-scoped token for user-level endpoints |
| OAuth2 Client Credentials | Snyk Apps and third-party integrations |
| Service Accounts | Org-level or Group-level machine accounts with RBAC roles |

### 1.3 API Design Characteristics

- **Versioning**: Date-based (`?version=2024-10-15`). Each endpoint documents the GA date and last-updated date.
- **Pagination**: Cursor-based (`starting_after`, `ending_before`) on list endpoints.
- **Response format**: JSON:API envelope (`data`, `attributes`, `relationships`, `links`, `meta`).
- **Rate limits**: Not publicly documented (enterprise contracts set org-specific limits).
- **Webhooks**: V1 webhook registration (`POST /org/{org_id}/webhooks`) for scan-complete events.

---

## 2. Snyk API Endpoint Inventory

Full enumeration of all documented endpoints across both REST and V1 APIs.

### 2.1 Access Management

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| GET | `/self/access_requests` | REST (beta) | List pending access requests |
| GET | `/self/apps` | REST | List user-authorized apps |
| DELETE | `/self/apps/{app_id}` | REST | Revoke app |
| GET | `/self/apps/{app_id}/sessions` | REST | List active OAuth sessions |
| DELETE | `/self/apps/{app_id}/sessions/{session_id}` | REST | Revoke session |
| GET | `/self/apps/installs` | REST | List installed user apps |
| DELETE | `/self/apps/installs/{install_id}` | REST | Revoke app install |

### 2.2 Apps (Snyk Apps Platform)

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| POST | `/orgs/{org_id}/apps/creations` | REST | Create new Snyk App |
| GET | `/orgs/{org_id}/apps/creations` | REST | List org-created apps |
| PATCH | `/orgs/{org_id}/apps/creations/{app_id}` | REST | Update app attributes |
| GET | `/orgs/{org_id}/apps/creations/{app_id}` | REST | Get app by ID |
| DELETE | `/orgs/{org_id}/apps/creations/{app_id}` | REST | Delete app |
| POST/PATCH/DELETE | `/orgs/{org_id}/apps/creations/{app_id}/secrets` | REST | Manage client secrets |
| POST | `/orgs/{org_id}/apps/installs` | REST | Install app to org |
| GET | `/orgs/{org_id}/apps/installs` | REST | List installed org apps |
| DELETE | `/orgs/{org_id}/apps/installs/{install_id}` | REST | Revoke org app auth |
| POST/PATCH/DELETE | `/orgs/{org_id}/apps/installs/{install_id}/secrets` | REST | Manage install secrets |
| POST | `/groups/{group_id}/apps/installs` | REST | Install app to group |
| GET | `/groups/{group_id}/apps/installs` | REST | List group apps |
| DELETE | `/groups/{group_id}/apps/installs/{install_id}` | REST | Revoke group app auth |
| POST/PATCH/DELETE | `/groups/{group_id}/apps/installs/{install_id}/secrets` | REST | Group install secrets |

### 2.3 Audit Logs

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| POST | `/orgs/{org_id}/audit_logs/search` | REST | Search org audit logs |
| POST | `/groups/{group_id}/audit_logs/search` | REST | Search group audit logs |

### 2.4 Cloud (IaC / CSPM)

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| GET | `/orgs/{org_id}/cloud/environments` | REST (beta) | List cloud environments |
| POST | `/orgs/{org_id}/cloud/environments` | REST (beta) | Create environment |
| DELETE | `/orgs/{org_id}/cloud/environments/{environment_id}` | REST (beta) | Delete environment |
| PATCH | `/orgs/{org_id}/cloud/environments/{environment_id}` | REST (beta) | Update environment |
| POST | `/orgs/{org_id}/cloud/permissions` | REST (beta) | Generate cloud provider permissions |
| GET | `/orgs/{org_id}/cloud/resources` | REST (beta) | List cloud resources |
| GET | `/orgs/{org_id}/cloud/scans` | REST (beta) | List scans |
| POST | `/orgs/{org_id}/cloud/scans` | REST (beta) | Trigger cloud scan |
| GET | `/orgs/{org_id}/cloud/scans/{scan_id}` | REST (beta) | Get scan details |

### 2.5 Collections

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| POST | `/orgs/{org_id}/collections` | REST | Create collection |
| GET | `/orgs/{org_id}/collections` | REST | List collections |
| PATCH | `/orgs/{org_id}/collections/{collection_id}` | REST | Edit collection |
| GET | `/orgs/{org_id}/collections/{collection_id}` | REST | Get collection |
| DELETE | `/orgs/{org_id}/collections/{collection_id}` | REST | Delete collection |
| POST | `/orgs/{org_id}/collections/{collection_id}/relationships/projects` | REST | Add projects to collection |
| GET | `/orgs/{org_id}/collections/{collection_id}/relationships/projects` | REST | Get collection projects |
| DELETE | `/orgs/{org_id}/collections/{collection_id}/relationships/projects` | REST | Remove projects |

### 2.6 Container Images

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| GET | `/orgs/{org_id}/container_images` | REST | List container images |
| GET | `/orgs/{org_id}/container_images/{image_id}` | REST | Get container image |
| GET | `/orgs/{org_id}/container_images/{image_id}/relationships/image_target_refs` | REST | List image target refs |

### 2.7 Custom Base Images

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| POST | `/custom_base_images` | REST | Create custom base image |
| GET | `/custom_base_images` | REST | List custom base images |
| PATCH | `/custom_base_images/{id}` | REST | Update |
| GET | `/custom_base_images/{id}` | REST | Get |
| DELETE | `/custom_base_images/{id}` | REST | Delete |

### 2.8 Dependencies

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| GET | `/org/{org_id}/dependencies` | V1 | List all org dependencies |

### 2.9 Groups

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| GET | `/groups` | REST (beta) | Get all groups |
| GET | `/groups/{group_id}` | REST (beta) | Get group |
| GET | `/groups/{group_id}/sso_connections` | REST (beta) | Get SSO connections |
| GET | `/groups/{group_id}/sso_connections/{sso_id}/users` | REST (beta) | Get SSO users |
| DELETE | `/groups/{group_id}/sso_connections/{sso_id}/users/{user_id}` | REST (beta) | Remove SSO user |
| GET | `/group/{groupid}/tags` | V1 | List group tags |
| DELETE | `/group/{groupid}/tags` | V1 | Delete tag |
| GET | `/group/{groupid}/settings` | V1 | View group settings |
| PUT | `/group/{groupid}/settings` | V1 | Update group settings |
| GET | `/group/{groupid}/roles` | V1 | List group roles |
| GET | `/group/{groupid}/orgs` | V1 | List organizations |
| POST | `/group/{groupid}/org/{orgid}/members` | V1 | Add member to org |
| GET | `/group/{groupid}/members` | V1 | List group members |
| GET | `/groups/{group_id}/org_memberships` | REST | Get user org memberships |
| POST | `/groups/{group_id}/memberships` | REST | Create group membership |
| GET | `/groups/{group_id}/memberships` | REST | Get all memberships |
| PATCH | `/groups/{group_id}/memberships/{membership_id}` | REST | Update membership role |
| DELETE | `/groups/{group_id}/memberships/{membership_id}` | REST | Delete membership |

### 2.10 IaC Settings

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| PATCH | `/orgs/{org_id}/settings/iac` | REST | Update org IaC settings |
| GET | `/orgs/{org_id}/settings/iac` | REST | Get org IaC settings |
| PATCH | `/groups/{group_id}/settings/iac` | REST | Update group IaC settings |
| GET | `/groups/{group_id}/settings/iac` | REST | Get group IaC settings |

### 2.11 Ignores

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| GET | `/org/{org_id}/project/{project_id}/ignores` | V1 | List ignores |
| PUT | `/org/{org_id}/project/{project_id}/ignore/{issue_id}` | V1 | Replace ignores |
| POST | `/org/{org_id}/project/{project_id}/ignore/{issue_id}` | V1 | Add ignore |
| DELETE | `/org/{org_id}/project/{project_id}/ignore/{issue_id}` | V1 | Delete ignores |

### 2.12 Import Projects

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| POST | `/org/{org_id}/integrations/{integration_id}/import` | V1 | Import targets |
| GET | `/org/{org_id}/integrations/{integration_id}/import/{job_id}` | V1 | Get import job status |

### 2.13 Integrations

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| POST | `/org/{org_id}/integrations` | V1 | Add integration |
| GET | `/org/{org_id}/integrations` | V1 | List integrations |
| GET | `/org/{org_id}/integrations/{type}` | V1 | Get by type |
| PUT | `/org/{org_id}/integrations/{integration_id}` | V1 | Update |
| PUT | `/org/{org_id}/integrations/{integration_id}/settings` | V1 | Update settings |
| GET | `/org/{org_id}/integrations/{integration_id}/settings` | V1 | Get settings |
| POST | `/org/{org_id}/integrations/{integration_id}/clone` | V1 | Clone |
| DELETE | `/org/{org_id}/integrations/{integration_id}/authentication` | V1 | Delete credentials |
| POST | `/org/{org_id}/integrations/{integration_id}/authentication/switch-token` | V1 | Switch broker token |
| POST | `/org/{org_id}/integrations/{integration_id}/authentication/provision-token` | V1 | Provision broker token |

### 2.14 Issues (Core — Vulnerability Data)

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| GET | `/orgs/{org_id}/packages/{purl}/issues` | REST | List issues for a package by PURL |
| GET | `/orgs/{org_id}/packages/issues` | REST (restricted) | Batch issue lookup for multiple packages |
| GET | `/orgs/{org_id}/issues` | REST | Get all issues for org |
| GET | `/orgs/{org_id}/issues/{issue_id}` | REST | Get specific issue |
| GET | `/groups/{group_id}/issues` | REST | Get issues across group |
| GET | `/groups/{group_id}/issues/{issue_id}` | REST | Get specific group issue |

### 2.15 Jira Integration

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| GET | `/org/{org_id}/project/{project_id}/jira-issues` | V1 | List Jira issues |
| POST | `/org/{org_id}/project/{project_id}/issue/{issue_id}/jira-issue` | V1 | Create Jira issue from finding |

### 2.16 Licenses

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| GET | `/licenses` | V1 | List all licenses |

### 2.17 Monitor

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| POST | `/monitor/dep-graph` | V1 | Monitor a dependency graph |

### 2.18 Organizations

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| GET | `/orgs` | REST | List accessible orgs |
| PATCH | `/orgs/{org_id}` | REST | Update org |
| POST | `/orgs/{org_id}/memberships` | REST | Create org membership |
| GET | `/orgs/{org_id}/memberships` | REST | Get org memberships |
| PATCH | `/orgs/{org_id}/memberships/{membership_id}` | REST | Update membership |
| GET | `/groups/{group_id}/orgs` | REST | List orgs in group |
| GET | `/orgs` | V1 | List user orgs |
| POST | `/org` | V1 | Create org |
| DELETE | `/org/{org_id}` | V1 | Remove org |
| PUT/GET | `/org/{org_id}/settings` | V1 | Update/view org settings |
| POST | `/org/{org_id}/provision` | V1 | Provision user |
| GET | `/org/{org_id}/provision` | V1 | List pending provisions |
| DELETE | `/org/{org_id}/provision/{provision_id}` | V1 | Delete provision |
| POST/GET | `/org/{org_id}/notification-settings` | V1 | Notification settings |
| GET | `/org/{org_id}/members` | V1 | List members |
| PUT | `/org/{org_id}/members/{user_id}` | V1 | Update member |
| DELETE | `/org/{org_id}/members/{user_id}` | V1 | Remove member |
| POST | `/org/{org_id}/invite` | V1 | Invite users |

### 2.19 Projects

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| GET | `/orgs/{org_id}/projects` | REST (GA) | List all org projects |
| PATCH | `/orgs/{org_id}/projects/{project_id}` | REST (GA) | Update project |
| GET | `/orgs/{org_id}/projects/{project_id}` | REST (GA) | Get project |
| DELETE | `/orgs/{org_id}/projects/{project_id}` | REST (GA) | Delete project |
| PUT | `/org/{org_id}/project/{project_id}` | V1 | Update project |
| GET | `/org/{org_id}/project/{project_id}` | V1 | Get project |
| DELETE | `/org/{org_id}/project/{project_id}` | V1 | Delete project |
| POST | `/org/{org_id}/project/{project_id}/tags` | V1 | Add tag |
| DELETE | `/org/{org_id}/project/{project_id}/tags/{tag_name}` | V1 | Remove tag |
| PUT/GET/DELETE | `/org/{org_id}/project/{project_id}/settings` | V1 | Project settings |
| PUT | `/org/{org_id}/project/{project_id}/move` | V1 | Move project to another org |
| GET | `/org/{org_id}/project/{project_id}/issue/{issue_id}/paths` | V1 | List issue dependency paths |
| GET | `/org/{org_id}/project/{project_id}/dep-graph` | V1 | Get full dependency graph |
| POST | `/org/{org_id}/project/{project_id}/deactivate` | V1 | Deactivate project |
| PUT | `/org/{org_id}/project/{project_id}/attributes` | V1 | Apply project attributes |
| GET | `/org/{org_id}/project/{project_id}/aggregated-issues` | V1 | List aggregated issues |
| POST | `/org/{org_id}/project/{project_id}/activate` | V1 | Activate project |

### 2.20 Pull Request Templates (Fix PR)

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| POST | `/groups/{group_id}/settings/pull_request_template` | REST | Create or update fix PR template |
| GET | `/groups/{group_id}/settings/pull_request_template` | REST | Get PR template |
| DELETE | `/groups/{group_id}/settings/pull_request_template` | REST | Delete PR template |

**Fix PR generation is NOT exposed as a direct API call.** It is triggered automatically by Snyk's backend when a project scan identifies new fixable vulnerabilities linked to an SCM integration (GitHub, GitLab, Bitbucket). Manual fix PR creation is done via the Snyk UI "Open Fix PR" button, not via API. The `pull_request_template` endpoints only control the PR description template, not PR generation itself.

Auto Fix PR configuration:
- Threshold: score ≥ 700 (default for orgs created after 2024-12-05) triggers automatic PR
- Configurable threshold per org via settings UI
- `@snyk /fix` inline comment command triggers Snyk Agent fix for Code scan findings

### 2.21 Reporting

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| POST | `/reporting/issues` | V1 | Get list of issues |
| POST | `/reporting/issues/latest` | V1 | Get latest issues |
| GET | `/reporting/counts/tests` | V1 | Get test counts |
| GET | `/reporting/counts/projects` | V1 | Get project counts |
| GET | `/reporting/counts/projects/latest` | V1 | Latest project counts |
| GET | `/reporting/counts/issues` | V1 | Get issue counts |
| GET | `/reporting/counts/issues/latest` | V1 | Latest issue counts |

### 2.22 SBOM

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| GET | `/orgs/{org_id}/projects/{project_id}/sbom` | REST (GA) | Export project SBOM (CycloneDX 1.4/1.5/1.6 JSON, SPDX 2.3 JSON) |
| POST | `/orgs/{org_id}/sbom_tests` | REST (beta) | Create async SBOM vulnerability test job |
| GET | `/orgs/{org_id}/sbom_tests/{job_id}` | REST (beta) | Poll SBOM test job status |
| GET | `/orgs/{org_id}/sbom_tests/{job_id}/results` | REST (beta) | Get SBOM test vulnerability results |

**Supported SBOM formats (export):** CycloneDX 1.4, 1.5, 1.6 JSON; SPDX 2.3 JSON
**Supported SBOM formats (import/test):** CycloneDX 1.4, 1.5, 1.6 JSON; SPDX 2.3 JSON
**SBOM import (upload external SBOM for scanning):** done via `POST /orgs/{org_id}/sbom_tests` with SBOM payload in request body

Total Snyk SBOM endpoints: **4**

### 2.23 SAST Settings

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| PATCH | `/orgs/{org_id}/settings/sast` | REST | Enable/disable Snyk Code |
| GET | `/orgs/{org_id}/settings/sast` | REST | Get SAST settings |

### 2.24 Service Accounts

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| POST/GET/PATCH/DELETE | `/orgs/{org_id}/service_accounts[/{id}]` | REST | Manage org service accounts |
| POST/PATCH/DELETE | `/orgs/{org_id}/service_accounts/{id}/secrets` | REST | Manage secrets |
| POST/GET/PATCH/DELETE | `/groups/{group_id}/service_accounts[/{id}]` | REST | Manage group service accounts |
| POST/PATCH/DELETE | `/groups/{group_id}/service_accounts/{id}/secrets` | REST | Group service account secrets |

### 2.25 Slack Integration

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| POST/GET/DELETE | `/orgs/{org_id}/slack_app/{bot_id}` | REST | Slack app settings |
| GET/POST/PUT/DELETE | `/orgs/{org_id}/slack_app/{bot_id}/projects/{project_id}` | REST | Per-project Slack overrides |
| GET | `/orgs/{org_id}/slack_app/{tenant_id}/channels` | REST | List Slack channels |
| GET | `/orgs/{org_id}/slack_app/{tenant_id}/channels/{channel_id}` | REST | Get channel |

### 2.26 Snapshots

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| GET | `/org/{org_id}/project/{project_id}/history` | V1 | List project snapshots |
| GET | `.../history/{snapshot_id}/issue/{issue_id}/paths` | V1 | Snapshot issue paths |
| GET | `.../history/{snapshot_id}/aggregated-issues` | V1 | Snapshot aggregated issues |

### 2.27 Targets

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| GET | `/orgs/{org_id}/targets` | REST | Get targets by org |
| GET | `/orgs/{org_id}/targets/{target_id}` | REST | Get target |
| DELETE | `/orgs/{org_id}/targets/{target_id}` | REST | Delete target |

### 2.28 Test (V1 — Language-Specific Scanning)

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| POST | `/test/yarn` | V1 | Test yarn lockfile |
| POST | `/test/sbt` | V1 | Test sbt file |
| GET | `/test/sbt/{groupid}/{artifactid}/{version}` | V1 | Test public sbt package |
| POST | `/test/rubygems` | V1 | Test gemfile.lock |
| GET | `/test/rubygems/{gemname}/{version}` | V1 | Test public gem |
| POST | `/test/pip` | V1 | Test requirements.txt |
| GET | `/test/pip/{packagename}/{version}` | V1 | Test public pip package |
| POST | `/test/npm` | V1 | Test package.json + lock |
| GET | `/test/npm/{packagename}/{version}` | V1 | Test public npm package |
| POST | `/test/maven` | V1 | Test Maven POM |
| GET | `/test/maven/{groupid}/{artifactid}/{version}` | V1 | Test public Maven package |
| POST | `/test/gradle` | V1 | Test Gradle file |
| GET | `/test/gradle/{group}/{name}/{version}` | V1 | Test public Gradle package |
| POST | `/test/govendor` | V1 | Test Go vendor.json |
| POST | `/test/golangdep` | V1 | Test Gopkg files |
| POST | `/test/dep-graph` | V1 | Test dependency graph directly |
| POST | `/test/composer` | V1 | Test Composer files |

### 2.29 Users

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| GET | `/user/{user_id}` | V1 | Get user details |
| GET | `/user/me` | V1/REST | Get current user |
| PUT/GET | `/user/me/notification-settings/org/{org_id}` | V1 | Org notification settings |
| PUT/GET | `.../project/{project_id}` | V1 | Project notification settings |
| PATCH | `/groups/{group_id}/users/{id}` | REST (beta) | Update user role in group |
| GET | `/orgs/{org_id}/users/{id}` | REST (beta) | Get user by ID in org |

### 2.30 Webhooks

| Method | Endpoint | API | Purpose |
|--------|----------|-----|---------|
| POST | `/org/{org_id}/webhooks` | V1 | Create webhook |
| GET | `/org/{org_id}/webhooks` | V1 | List webhooks |
| GET | `/org/{org_id}/webhooks/{webhook_id}` | V1 | Get webhook |
| DELETE | `/org/{org_id}/webhooks/{webhook_id}` | V1 | Delete webhook |
| POST | `/org/{org_id}/webhooks/{webhook_id}/ping` | V1 | Ping webhook |

### 2.31 Snyk API Endpoint Count Summary

| Category | REST Endpoints | V1 Endpoints | Total |
|----------|---------------|--------------|-------|
| Access/Apps | 23 | 0 | 23 |
| Audit Logs | 2 | 0 | 2 |
| Cloud (CSPM/IaC) | 9 | 0 | 9 |
| Collections | 8 | 0 | 8 |
| Container Images | 3 | 0 | 3 |
| Custom Base Images | 5 | 0 | 5 |
| Dependencies | 0 | 1 | 1 |
| Groups | 9 | 8 | 17 |
| IaC Settings | 4 | 0 | 4 |
| Ignores | 0 | 4 | 4 |
| Import Projects | 0 | 2 | 2 |
| Integrations | 0 | 10 | 10 |
| Issues | 6 | 0 | 6 |
| Jira | 0 | 2 | 2 |
| Licenses | 0 | 1 | 1 |
| Monitor | 0 | 1 | 1 |
| Organizations | 7 | 16 | 23 |
| Projects | 4 | 12 | 16 |
| PR Templates | 3 | 0 | 3 |
| Reporting | 0 | 7 | 7 |
| SBOM | 4 | 0 | 4 |
| SAST Settings | 2 | 0 | 2 |
| Service Accounts | 14 | 0 | 14 |
| Slack | 8 | 0 | 8 |
| Snapshots | 0 | 3 | 3 |
| Targets | 3 | 0 | 3 |
| Test (language-specific) | 0 | 17 | 17 |
| Users | 2 | 6 | 8 |
| Webhooks | 0 | 5 | 5 |
| **TOTAL** | **117** | **95** | **~212** |

---

## 3. ALDECI API Inventory — Supply Chain, SBOM, and Vulnerability

ALDECI's relevant API surface across 12 routers covering the same functional domains as Snyk.

### 3.1 SBOM Endpoints

**Router: `/api/v1/sbom`** (sbom_router.py — SBOMEngine)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/sbom/assets` | Register an asset (application/container/firmware) |
| GET | `/api/v1/sbom/assets` | List assets for org |
| GET | `/api/v1/sbom/assets/{asset_id}` | Get asset |
| POST | `/api/v1/sbom/assets/{asset_id}/components` | Add component to asset |
| GET | `/api/v1/sbom/assets/{asset_id}/components` | List components |
| GET | `/api/v1/sbom/assets/{asset_id}/export/cyclonedx` | Export CycloneDX 1.4 JSON |
| GET | `/api/v1/sbom/assets/{asset_id}/export/spdx` | Export SPDX 2.3 JSON |
| GET | `/api/v1/sbom/license-summary` | License risk distribution |
| GET | `/api/v1/sbom/vuln-exposure` | Vulnerability exposure analytics |
| GET | `/api/v1/sbom/stats` | SBOM statistics |

**Router: `/api/v1/sbom-export`** (sbom_export_router.py — SBOMExportEngine)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/sbom-export/components` | Register component with PURL, ecosystem, license |
| POST | `/api/v1/sbom-export/components/{id}/vulns` | Add vulnerability to component |
| POST | `/api/v1/sbom-export/generate/cyclonedx` | Generate CycloneDX 1.4 SBOM for project |
| POST | `/api/v1/sbom-export/generate/spdx` | Generate SPDX 2.3 SBOM for project |
| GET | `/api/v1/sbom-export/projects` | List projects |
| GET | `/api/v1/sbom-export/projects/{project_name}/summary` | Project SBOM summary |
| GET | `/api/v1/sbom-export/projects/{project_name}/history` | SBOM export history |
| GET | `/api/v1/sbom-export/search` | Search components |

ALDECI SBOM total: **18 endpoints** (vs. Snyk: 4)

### 3.2 Supply Chain Endpoints

**Router: `/api/v1/supply-chain`** (supply_chain_router.py — SupplyChainEngine)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/supply-chain/sbom/upload` | Upload SBOM (CycloneDX or SPDX JSON) |
| GET | `/api/v1/supply-chain/components` | List tracked components with risk scores |
| GET | `/api/v1/supply-chain/risks` | Supply chain risk dashboard data |
| POST | `/api/v1/supply-chain/scan` | Trigger dependency scan for a repo |
| GET | `/api/v1/supply-chain/policies` | List active supply chain policies |
| POST | `/api/v1/supply-chain/policies` | Create/update policy |
| GET | `/api/v1/supply-chain/vendors` | Vendor risk assessments |
| POST | `/api/v1/supply-chain/vendors` | Create/update vendor risk |
| GET | `/api/v1/supply-chain/provenance/{component}` | Component provenance info |

**Router: `/api/v1/supply-chain`** (supply_chain_risk_router.py — SupplyChainRiskEngine)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/v1/supply-chain/suppliers` | List suppliers (filterable by risk tier) |
| POST | `/api/v1/supply-chain/suppliers` | Register supplier |
| GET | `/api/v1/supply-chain/components` | List components (filter: supplier_id, is_eol) |
| POST | `/api/v1/supply-chain/components` | Add component |
| GET | `/api/v1/supply-chain/risks` | List supply chain risks (filter: status) |
| POST | `/api/v1/supply-chain/risks` | Register a risk |
| POST | `/api/v1/supply-chain/sbom/import` | Import SBOM document |
| GET | `/api/v1/supply-chain/stats` | Aggregated statistics |

**Router: `/api/v1/supply-chain-attacks`** (supply_chain_attack_detection_router.py)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/supply-chain-attacks/packages` | Register package for monitoring |
| GET | `/api/v1/supply-chain-attacks/packages` | List packages |
| GET | `/api/v1/supply-chain-attacks/packages/{id}` | Get package |
| PUT | `/api/v1/supply-chain-attacks/packages/{id}/status` | Update package status |
| POST | `/api/v1/supply-chain-attacks/detections` | Record attack detection |
| GET | `/api/v1/supply-chain-attacks/detections` | List detections |
| PUT | `/api/v1/supply-chain-attacks/detections/{id}/confirm` | Confirm detection |
| POST | `/api/v1/supply-chain-attacks/policies` | Create policy |
| GET | `/api/v1/supply-chain-attacks/policies` | List policies |
| GET | `/api/v1/supply-chain-attacks/stats` | Attack statistics |

**Router: `/api/v1/supply-chain-intel`** (supply_chain_intel_router.py)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/supply-chain-intel/packages` | Track package |
| GET | `/api/v1/supply-chain-intel/packages` | List packages |
| POST | `/api/v1/supply-chain-intel/packages/{pkg_id}/vulns` | Add vulnerability |
| GET | `/api/v1/supply-chain-intel/vulns` | List vulnerabilities |
| POST | `/api/v1/supply-chain-intel/malicious` | Flag malicious package |
| GET | `/api/v1/supply-chain-intel/malicious` | List malicious packages |
| GET | `/api/v1/supply-chain-intel/check` | Check package reputation |
| POST | `/api/v1/supply-chain-intel/sbom/snapshots` | Create SBOM snapshot |
| GET | `/api/v1/supply-chain-intel/sbom/snapshots` | List SBOM snapshots |
| GET | `/api/v1/supply-chain-intel/stats` | Stats |

**Router: `/api/v1/supply-chain-monitoring`** (supply_chain_monitoring_router.py)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/supply-chain-monitoring/suppliers` | Register supplier |
| GET | `/api/v1/supply-chain-monitoring/suppliers` | List suppliers |
| GET | `/api/v1/supply-chain-monitoring/suppliers/{supplier_id}` | Get supplier |
| POST | `/api/v1/supply-chain-monitoring/suppliers/{supplier_id}/assess` | Trigger supplier assessment |
| POST | `/api/v1/supply-chain-monitoring/events` | Create monitoring event |
| GET | `/api/v1/supply-chain-monitoring/events` | List events |
| PUT | `/api/v1/supply-chain-monitoring/events/{event_id}/resolve` | Resolve event |
| GET | `/api/v1/supply-chain-monitoring/stats` | Monitoring statistics |

ALDECI Supply Chain total: **45 endpoints** (Snyk has 0 dedicated supply chain endpoints)

### 3.3 SCA Endpoints

**Router: `/api/v1/sca`** (software_composition_analysis_router.py)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/sca/projects` | Register project |
| GET | `/api/v1/sca/projects` | List projects |
| GET | `/api/v1/sca/projects/{id}` | Get project |
| POST | `/api/v1/sca/projects/{id}/scans` | Submit scan |
| GET | `/api/v1/sca/scans` | List scans |
| GET | `/api/v1/sca/scans/{id}` | Get scan |
| GET | `/api/v1/sca/scans/{id}/vulnerable-deps` | Get vulnerable dependencies |
| GET | `/api/v1/sca/scans/{id}/license-report` | Get license report |
| GET | `/api/v1/sca/stats` | SCA statistics |

**Router: `/api/v1/dep-scanner`** (dep_scanner_router.py)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/dep-scanner/scan-requirements` | Scan requirements.txt |
| POST | `/api/v1/dep-scanner/scan-package-json` | Scan package.json |
| GET | `/api/v1/dep-scanner/scan-installed` | Scan pip-installed packages |
| GET | `/api/v1/dep-scanner/outdated` | List outdated packages |
| GET | `/api/v1/dep-scanner/vulnerable` | List vulnerable installed packages |
| GET | `/api/v1/dep-scanner/upgrade-plan` | Prioritized upgrade plan |

**Router: `/api/v1/license-scanner`** (license_scanner_router.py)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/license-scanner/scan-requirements` | Scan requirements.txt for license risk |
| POST | `/api/v1/license-scanner/scan-package-json` | Scan package.json for license risk |
| POST | `/api/v1/license-scanner/evaluate-policy` | Re-evaluate results vs. org policy |
| GET | `/api/v1/license-scanner/summary` | License risk distribution by org |
| POST | `/api/v1/license-scanner/policy` | Set org license policy rules |
| GET | `/api/v1/license-scanner/violations` | List policy violations |

ALDECI SCA total: **21 endpoints** (Snyk equivalent via V1 Test API: 17 endpoints)

### 3.4 Vulnerability Management Endpoints

**Router: `/api/v1/vuln-intel`** (vuln_intelligence_router.py)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/vuln-intel/cves` | Add CVE |
| GET | `/api/v1/vuln-intel/cves` | List CVEs |
| GET | `/api/v1/vuln-intel/cves/{cve_id}` | Get CVE |
| PATCH | `/api/v1/vuln-intel/cves/{cve_id}/status` | Update CVE status |
| POST | `/api/v1/vuln-intel/advisories` | Add advisory |
| GET | `/api/v1/vuln-intel/advisories` | List advisories |
| POST | `/api/v1/vuln-intel/advisories/{id}/apply` | Apply advisory |
| POST | `/api/v1/vuln-intel/subscriptions` | Subscribe to vendor advisories |
| GET | `/api/v1/vuln-intel/subscriptions` | List subscriptions |
| GET | `/api/v1/vuln-intel/stats` | Intel statistics |

**Router: `/api/v1/vuln-prioritization`** (vuln_prioritization_router.py)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/vuln-prioritization/score` | Score a vulnerability (CVSS+EPSS+KEV) |
| POST | `/api/v1/vuln-prioritization/batch-score` | Batch score multiple vulns |
| GET | `/api/v1/vuln-prioritization/scored` | List scored vulns |
| GET | `/api/v1/vuln-prioritization/scored/{vuln_id}` | Get score |
| POST | `/api/v1/vuln-prioritization/scored/{vuln_id}/sla` | Set SLA for vuln |
| GET | `/api/v1/vuln-prioritization/sla` | Get SLA config |
| GET | `/api/v1/vuln-prioritization/runs` | List scoring runs |
| GET | `/api/v1/vuln-prioritization/stats` | Prioritization statistics |

**Router: `/api/v1/vuln-lifecycle`** (vuln_lifecycle_router.py)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/vuln-lifecycle/{finding_id}/transition` | Move finding to next state |
| GET | `/api/v1/vuln-lifecycle/{finding_id}/history` | Full event history |
| GET | `/api/v1/vuln-lifecycle/{finding_id}/stage` | Current stage |
| GET | `/api/v1/vuln-lifecycle/distribution` | Stage counts by org |
| GET | `/api/v1/vuln-lifecycle/bottlenecks` | Stuck-stage analysis |
| GET | `/api/v1/vuln-lifecycle/avg-time` | Average hours per stage |
| GET | `/api/v1/vuln-lifecycle/flow` | Throughput and cycle time |
| POST | `/api/v1/vuln-lifecycle/validate` | Validate transition legality |

**Router: `/api/v1/vuln-workflow`** (vuln_workflow_router.py)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/vuln-workflow/tickets` | Create workflow ticket |
| GET | `/api/v1/vuln-workflow/tickets` | List tickets |
| GET | `/api/v1/vuln-workflow/tickets/{ticket_id}` | Get ticket |
| PATCH | `/api/v1/vuln-workflow/tickets/{ticket_id}` | Update ticket |
| POST | `/api/v1/vuln-workflow/tickets/{ticket_id}/comments` | Add comment |
| POST | `/api/v1/vuln-workflow/tickets/{ticket_id}/assign` | Assign ticket |
| POST | `/api/v1/vuln-workflow/tickets/{ticket_id}/accept-risk` | Accept risk |
| POST | `/api/v1/vuln-workflow/tickets/bulk-assign` | Bulk assign |
| POST | `/api/v1/vuln-workflow/tickets/bulk-close` | Bulk close |
| GET | `/api/v1/vuln-workflow/sla` | Get SLA config |
| POST | `/api/v1/vuln-workflow/sla` | Set SLA config |
| GET | `/api/v1/vuln-workflow/stats` | Workflow statistics |

**Router: `/api/v1/vuln-remediation`** (vulnerability_remediation_router.py)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/vuln-remediation/tasks` | Create remediation task |
| GET | `/api/v1/vuln-remediation/tasks` | List tasks (filter: status/severity/assignee) |
| GET | `/api/v1/vuln-remediation/tasks/{id}` | Get task |
| PATCH | `/api/v1/vuln-remediation/tasks/{id}/status` | Update task status |
| GET | `/api/v1/vuln-remediation/tasks/overdue` | List overdue tasks |
| POST | `/api/v1/vuln-remediation/tasks/{id}/notes` | Add note |
| GET | `/api/v1/vuln-remediation/tasks/{id}/notes` | Get notes |
| GET | `/api/v1/vuln-remediation/metrics` | MTTR and count metrics |

**Router: `/api/v1/vuln-scoring`** (vulnerability_scoring_router.py)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/vuln-scoring/models` | Create custom scoring model |
| POST | `/api/v1/vuln-scoring/scores` | Score a vulnerability |
| POST | `/api/v1/vuln-scoring/scores/{id}/override` | Override score with justification |
| GET | `/api/v1/vuln-scoring/scores/{id}` | Get score |
| GET | `/api/v1/vuln-scoring/scores` | List scores |
| GET | `/api/v1/vuln-scoring/top` | Get top vulns |
| GET | `/api/v1/vuln-scoring/distribution` | Scoring distribution |
| GET | `/api/v1/vuln-scoring/assets/{asset_id}/risk` | Asset risk score |

ALDECI Vulnerability Management total: **52 endpoints** (Snyk equivalent: 6 issues endpoints)

---

## 4. Head-to-Head API Comparison

### 4.1 SBOM API Comparison

| Capability | Snyk API | ALDECI API |
|-----------|---------|-----------|
| Export SBOM from project | `GET /orgs/{id}/projects/{id}/sbom` (1 endpoint) | `GET /api/v1/sbom/assets/{id}/export/cyclonedx` + `/export/spdx` (2 endpoints) |
| Export SBOM from project (alternate engine) | — | `POST /api/v1/sbom-export/generate/cyclonedx` + `/generate/spdx` (2 more) |
| Import/upload external SBOM | Via `POST /orgs/{id}/sbom_tests` payload | `POST /api/v1/supply-chain/sbom/upload` + `POST /api/v1/supply-chain/sbom/import` |
| Test SBOM for vulnerabilities (async) | 3-endpoint async job pattern (create/poll/results) | Inline via `/api/v1/sbom/vuln-exposure` |
| Supported formats (export) | CycloneDX 1.4/1.5/1.6, SPDX 2.3 | CycloneDX 1.4, SPDX 2.3 |
| Supported formats (import/test) | CycloneDX 1.4/1.5/1.6, SPDX 2.3 | CycloneDX, SPDX (JSON) |
| Component registry | No — project-centric | Yes — `POST /api/v1/sbom/assets/{id}/components` |
| License risk per component | No | Yes — `GET /api/v1/sbom/license-summary` |
| Vuln exposure analytics | In test results payload | `GET /api/v1/sbom/vuln-exposure` |
| Export history tracking | No | `GET /api/v1/sbom-export/projects/{name}/history` |
| Component search | No | `GET /api/v1/sbom-export/search` |
| SBOM snapshots | No | `POST/GET /api/v1/supply-chain-intel/sbom/snapshots` |
| Total SBOM endpoints | **4** | **18** |
| CycloneDX version support | 1.4, 1.5, 1.6 | 1.4 |
| SPDX version support | 2.3 | 2.3 |
| NTIA minimum elements compliance | Implied | Explicit (engine docstring) |
| EO 14028 compliance | Implied | Explicit (engine docstring) |

**Gap:** Snyk supports CycloneDX 1.5 and 1.6 (newer) while ALDECI currently supports 1.4. ALDECI has significantly more SBOM management endpoints and component-level tracking.

### 4.2 Dependency / SCA API Comparison

| Capability | Snyk API | ALDECI API |
|-----------|---------|-----------|
| List org dependencies | `GET /org/{id}/dependencies` (V1) | `GET /api/v1/sca/scans/{id}/vulnerable-deps` |
| Scan dependency manifest | `POST /test/npm`, `/test/pip`, etc. (17 V1 endpoints) | `POST /api/v1/dep-scanner/scan-requirements`, `/scan-package-json` |
| Dependency graph | `GET /org/{id}/project/{id}/dep-graph` | Not yet exposed as API |
| Monitor dependency graph | `POST /monitor/dep-graph` | Not yet (planned) |
| Scan public package by version | `GET /test/npm/{name}/{version}`, etc. (8 V1 endpoints) | Not exposed |
| License scanning | Bundled in project scan | `POST /api/v1/license-scanner/scan-requirements`, `/scan-package-json` |
| License policy enforcement | Via project settings | `POST /api/v1/license-scanner/policy` + `/evaluate-policy` |
| License violations list | In reporting API | `GET /api/v1/license-scanner/violations` |
| Upgrade plan generation | Via UI / fix PR | `GET /api/v1/dep-scanner/upgrade-plan` |
| Outdated packages list | Via project scan results | `GET /api/v1/dep-scanner/outdated` |
| PURL-based issue lookup | `GET /orgs/{id}/packages/{purl}/issues` | Not yet (PURL stored, lookup not exposed) |
| Multi-ecosystem support (npm/pip/maven/go/ruby/gradle) | Yes — 8 ecosystems, V1 test endpoints | npm + pip (2 ecosystems) |
| Container image scanning | `GET /orgs/{id}/container_images` | `/api/v1/container-registry-security` (separate router) |
| IaC scanning | Cloud endpoints, IaC settings | `/api/v1/iac-scanner` (separate router) |

**Gap:** Snyk's V1 test API covers 8 ecosystems; ALDECI's dep-scanner covers npm + pip. Snyk's PURL-based issue lookup is a key API primitive that ALDECI lacks. Snyk's dependency graph API (`dep-graph`) is a significant differentiator for transitive analysis.

### 4.3 Issues / Vulnerability Data API Comparison

| Capability | Snyk API | ALDECI API |
|-----------|---------|-----------|
| List vulnerabilities for org | `GET /orgs/{id}/issues` | `GET /api/v1/vuln-intel/cves` + `/api/v1/vuln-prioritization/scored` |
| Get specific issue | `GET /orgs/{id}/issues/{id}` | `GET /api/v1/vuln-intel/cves/{cve_id}` |
| Issues by package PURL | `GET /orgs/{id}/packages/{purl}/issues` | Not exposed |
| Batch package issue lookup | `GET /orgs/{id}/packages/issues` | Not exposed |
| Issues aggregated per project | `GET /org/{id}/project/{id}/aggregated-issues` | `GET /api/v1/sca/scans/{id}/vulnerable-deps` |
| Issue dependency paths | `GET /org/{id}/project/{id}/issue/{id}/paths` | Not exposed (reachability gap) |
| Ignore/suppress issues | `POST/DELETE /org/{id}/project/{id}/ignore/{issue_id}` | `POST /api/v1/vuln-workflow/tickets/{id}/accept-risk` |
| Composite priority score | Snyk Priority Score (7 factors, 0–1000) | CVSS+EPSS+KEV (3 factors, 0–100) |
| Risk Score (business context) | Yes (asset criticality, env, data sensitivity) | Via `/api/v1/vuln-scoring/models` (custom model) |
| Exploit maturity data | In issue payload | Not in vuln intel payload |
| Reachability data | In issue payload (call path) | Not available |
| SLA enforcement | Not in API | `POST /api/v1/vuln-prioritization/scored/{id}/sla` + workflow engine |
| Lifecycle state machine | Not in API (project-level states only) | 8-state machine: `/api/v1/vuln-lifecycle/transition` |
| Bulk operations | Via reporting API | `POST /api/v1/vuln-workflow/tickets/bulk-assign`, `/bulk-close` |
| MTTR metrics | Not in API | `GET /api/v1/vuln-remediation/metrics` |
| Bottleneck analysis | Not in API | `GET /api/v1/vuln-lifecycle/bottlenecks` |
| Custom scoring models | Not in API | `POST /api/v1/vuln-scoring/models` |
| Score override with audit | Not in API | `POST /api/v1/vuln-scoring/scores/{id}/override` |
| Jira ticket creation | `POST /org/{id}/project/{id}/issue/{id}/jira-issue` | Via workflow engine (separate integration) |
| Snapshot/history | `GET /org/{id}/project/{id}/history` | Not in vuln lifecycle |

### 4.4 Fix PR / Auto-Remediation API Comparison

| Capability | Snyk API | ALDECI API |
|-----------|---------|-----------|
| Auto-generate fix PR | Backend-triggered (not API-callable) | **Not available** |
| PR template management | `POST/GET/DELETE /groups/{id}/settings/pull_request_template` | Not available |
| Manual fix PR initiation | UI button only | Not available |
| Upgrade path recommendation in API | Via `dep-graph` + issue paths endpoints | `GET /api/v1/dep-scanner/upgrade-plan` |
| Automated remediation workflows | Via Snyk CLI `snyk fix` command | `POST /api/v1/autonomous-remediation/workflows` (separate engine) |
| Remediation task management | Not in API | Full CRUD via `/api/v1/vuln-remediation/tasks` |
| MTTR tracking | Not in API | `GET /api/v1/vuln-remediation/metrics` |
| SLA-gated escalation | Not in API | Via SLA escalation engine |

**Summary:** Snyk's fix PR generation is a UI/backend automation, not an open API endpoint. Neither platform exposes a "generate fix PR" REST call that a third party could invoke programmatically — Snyk does this automatically server-side. ALDECI has more structured remediation workflow APIs (task management, MTTR, SLA) but no SCM integration for automated PR generation.

### 4.5 Organization / Multi-tenancy API Comparison

| Capability | Snyk API | ALDECI API |
|-----------|---------|-----------|
| Multi-org hierarchy | Group → Org → Project (3 levels) | org_id scoped per-engine (flat) |
| Create/manage orgs | `POST /org`, `DELETE /org/{id}` | Not in API (admin config) |
| User provisioning | `POST /org/{id}/provision` | Via SSO bridge |
| Role-based access | Group roles, org-level RBAC | RBAC engine + 6 roles |
| Service accounts | Full CRUD via REST | Not exposed as API |
| SSO integration | `GET /groups/{id}/sso_connections` | `/api/v1/sso-bridge` (separate router) |
| Audit log search | `POST /orgs/{id}/audit_logs/search` | Via audit management engine |
| Webhook support | Full CRUD + ping | Via n8n integration |
| Slack integration | Native API endpoints | Via scheduled reports engine |
| Jira integration | Native V1 endpoints | Via workflow engine |

---

## 5. Endpoint Count Summary

| Domain | Snyk Total | ALDECI Total | ALDECI Advantage |
|--------|-----------|-------------|-----------------|
| SBOM | 4 | 18 | +14 |
| Supply Chain | 0 | 45 | +45 |
| SCA / Dependency Scanning | 17 (V1 test) + 1 dep list | 21 | Comparable |
| Vulnerability Issues | 6 | 52 | +46 |
| Fix PR / Remediation | 3 (template only) | 8 (task management) | Different paradigm |
| Organization Management | 23 | ~5 (SSO, basic) | Snyk +18 |
| Reporting | 7 | Via KPI/metrics engines | Comparable |
| Integrations | 10 | Via connectors | Different paradigm |
| Container Scanning | 3 | Separate router | Comparable |
| IaC / Cloud | 9 | Separate engines | Comparable |
| **TOTAL (all domains)** | **~212** | **~574+** | **ALDECI +362** |

---

## 6. Authentication Comparison

| Feature | Snyk | ALDECI |
|---------|------|--------|
| API token (bearer) | Yes — `Authorization: token <key>` | Yes — `X-API-Key: <key>` |
| Personal Access Tokens | Yes | Not exposed |
| OAuth2 | Yes — for Snyk Apps | Yes — SAML/OIDC SSO bridge |
| Service accounts | Yes — full API management | Not in API (internal) |
| RBAC on API keys | Yes — role-scoped | Yes — 6 RBAC roles |
| Key hashing | Not documented | SHA-256 in engine layer |
| Rate limiting | Enterprise-contract based | Not yet implemented |

---

## 7. Strategic Assessment

### 7.1 Where Snyk's API is Stronger

1. **PURL-based issue lookup** (`GET /packages/{purl}/issues`): The ability to query vulnerabilities by Package URL is the most powerful SCA API primitive. It enables any tool to ask "what vulnerabilities does this specific package version have?" ALDECI stores PURLs but does not expose PURL-based issue lookups.

2. **Dependency graph API** (`GET /dep-graph`, `POST /monitor/dep-graph`): The full transitive dependency graph as a queryable API — this is what enables reachability analysis and dependency-grouped remediation. ALDECI has no equivalent.

3. **Multi-ecosystem test API** (17 V1 test endpoints): Covering yarn, sbt, rubygems, pip, npm, maven, gradle, govendor, golangdep, composer, dep-graph — Snyk can test any ecosystem programmatically. ALDECI covers npm and pip.

4. **Organization hierarchy** (Group → Org): Snyk's MSSP-grade tenancy model with full API management of groups, orgs, memberships, and service accounts is enterprise-complete. ALDECI's org_id isolation is functional but not API-manageable.

5. **Native SCM integrations** (GitHub, GitLab, Bitbucket, Azure DevOps): Snyk's integration endpoints and import API connect directly to SCM platforms. ALDECI has connector framework but no SCM-specific endpoints.

6. **CycloneDX 1.5/1.6 support**: Snyk supports the two most recent CycloneDX versions; ALDECI currently generates 1.4 only.

### 7.2 Where ALDECI's API is Stronger

1. **SBOM management depth** (18 vs. 4 endpoints): ALDECI has a full component registry, license risk per component, export history, vuln exposure analytics, SBOM snapshots, and component search. Snyk's SBOM API is export-only with a basic async test job.

2. **Supply chain security** (45 vs. 0 endpoints): Supplier registry, component provenance, supply chain attack detection, malicious package flagging, vendor risk assessment, geo-political risk tracking — Snyk has no supply chain API surface.

3. **Vulnerability lifecycle management** (52 vs. 6 endpoints): ALDECI's 8-state lifecycle state machine, SLA enforcement, remediation task management, MTTR tracking, bottleneck analysis, and bulk operations are enterprise vulnerability management that Snyk's Issues API does not cover.

4. **Custom scoring models**: ALDECI allows organizations to define their own scoring models via API (`POST /api/v1/vuln-scoring/models`) with score overrides and audit trails. Snyk's scoring is a fixed formula.

5. **License policy enforcement** (separate policy engine): ALDECI exposes license policy rules, policy evaluation, and violation listing as distinct API calls. Snyk bundles this into project scan results without a dedicated policy API.

6. **Remediation workflow**: Task management, notes, assignment, bulk operations, MTTR metrics — ALDECI's remediation API is a full workflow system. Snyk offers only Jira ticket creation.

7. **Total API surface**: 574+ endpoints vs. ~212. ALDECI covers 344+ additional security domains (SIEM, IAM, OT/IoT, ZeroTrust, CSPM, NDR, EDR, XDR, insider threat, etc.) that are outside Snyk's scope entirely.

### 7.3 Critical Gaps to Close in ALDECI

**High priority** (close within 2 sprints — directly affects SCA positioning):

| Gap | Effort | Impact |
|-----|--------|--------|
| PURL-based issue lookup: `GET /api/v1/vuln-intel/packages/{purl}/issues` | Low — data exists, endpoint missing | High — SCA API parity |
| Dependency graph API: expose full transitive tree as JSON | Medium — SCA engine needs graph DB | Critical — enables reachability |
| CycloneDX 1.5/1.6 export support | Low — schema extension only | Medium — format parity |
| Public package test: `GET /api/v1/dep-scanner/check/{ecosystem}/{package}/{version}` | Low — wrap PyPI/npm registry | High — enables package-first workflow |

**Medium priority** (1 quarter):

| Gap | Effort | Impact |
|-----|--------|--------|
| Exploit maturity field in vuln intel payloads | Low — NVD CVSS vector has this data | High — priority score quality |
| Multi-ecosystem test API (Go, Ruby, Java, PHP) | High — new scanner normalizers | Medium — ecosystem coverage |
| Service account management API | Medium — extend auth layer | Medium — enterprise tenancy |
| Org hierarchy API (create/manage orgs via API) | High — schema changes | Medium — MSSP positioning |

---

## 8. API Design Recommendations

### 8.1 Add PURL-based Package Issue Lookup

```
GET /api/v1/packages/{purl}/issues?org_id=default&severity=critical,high
```
Returns all known CVEs for a given PURL (Package URL, e.g., `pkg:pypi/requests@2.28.0`). Wire to existing vuln_intel CVE table using the `purl` column already stored in the SBOM component registry.

### 8.2 Add Dependency Graph Endpoint

```
GET /api/v1/sca/projects/{id}/dep-graph
POST /api/v1/dep-scanner/dep-graph
```
Returns directed acyclic graph of direct + transitive dependencies as `{nodes: [...], edges: [...]}`. Enable grouping vulnerabilities by their introducing direct dependency (the Snyk Fixes tab pattern).

### 8.3 Add Public Package Version Test

```
GET /api/v1/dep-scanner/test/pypi/{package}/{version}
GET /api/v1/dep-scanner/test/npm/{package}/{version}
GET /api/v1/dep-scanner/test/maven/{group}/{artifact}/{version}
```
Enables programmatic "is this version safe?" checks without needing a full project scan. Core primitive for CI gate workflows.

### 8.4 Upgrade CycloneDX to 1.6

In `sbom_export_engine.py`, update the `specVersion` field from `"1.4"` to `"1.6"` and add the `metadata.lifecycles` and `vulnerabilities` arrays per CycloneDX 1.6 spec. No schema-breaking change.

### 8.5 Add Exploit Maturity to CVE Payload

In `vuln_intelligence_engine.py`, add `exploit_maturity` field (values: `no_known_exploit`, `proof_of_concept`, `functional`, `high`) sourced from NVD CVSS `exploitabilityScore` and KEV presence. Wire into priority score computation in `vuln_prioritization_engine.py`.

---

## 9. Summary

| Dimension | Snyk | ALDECI |
|-----------|------|--------|
| API total endpoints | ~212 | ~574+ |
| SBOM endpoints | 4 | 18 |
| Supply chain endpoints | 0 | 45 |
| Vulnerability management | 6 | 52 |
| Ecosystem test coverage | 8 ecosystems | 2 (npm, pip) |
| Dependency graph API | Yes (V1) | No |
| PURL-based issue lookup | Yes (REST) | No |
| Reachability in API | Yes | No |
| Fix PR API | UI-only (not REST) | No |
| Custom scoring models | No | Yes |
| Vulnerability lifecycle FSM | No | Yes (8-state) |
| SLA enforcement in API | No | Yes |
| MTTR tracking in API | No | Yes |
| Supplier/vendor registry API | No | Yes (45 endpoints) |
| Supply chain attack detection API | No | Yes |
| License policy engine API | No | Yes |
| Auth: API token | Yes | Yes |
| Auth: OAuth2/OIDC | Yes | Yes (SSO bridge) |
| Auth: Service accounts | Yes (API-managed) | Not API-managed |
| Multi-org hierarchy API | Yes (Group→Org) | Not exposed |
| CycloneDX version | 1.4, 1.5, 1.6 | 1.4 |
| SPDX version | 2.3 | 2.3 |
| Self-hosted | No (SaaS only) | Yes |
| Pricing | $50K+/yr enterprise | $35-60/mo |

**Positioning conclusion**: Snyk's API is deeper in the narrow SCA lane — dependency graph, PURL lookup, multi-ecosystem scanning, and SCM-integrated fix PRs. ALDECI's API is broader across the full security platform (SBOM management, supply chain intelligence, vulnerability lifecycle, custom scoring, 344+ additional security domains). The four highest-ROI API additions to close the SCA gap are: PURL issue lookup, dependency graph export, public package version test, and CycloneDX 1.6 support — all implementable within two sprints.

---

## Sources

- [Snyk API Endpoints Index and Tips](https://docs.snyk.io/snyk-api/api-endpoints-index-and-tips)
- [Snyk SBOM API Reference](https://docs.snyk.io/snyk-api/reference/sbom)
- [Snyk REST API Overview](https://docs.snyk.io/snyk-api/rest-api)
- [Snyk SBOM APIs — Using Specific Snyk APIs](https://docs.snyk.io/snyk-api/using-specific-snyk-apis/sbom-apis)
- [Snyk Fix PR Documentation](https://docs.snyk.io/scan-with-snyk/pull-requests/snyk-pull-or-merge-requests/enable-automatic-fix-prs)
- [Snyk Auto Fix PRs for New Fixes](https://docs.snyk.io/scan-with-snyk/pull-requests/snyk-pull-or-merge-requests/create-automatic-prs-for-new-fixes-fix-prs)
- [Snyk V1 API — Apiary](https://snyk.docs.apiary.io/)
- ALDECI source: `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/sbom_router.py`
- ALDECI source: `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/sbom_export_router.py`
- ALDECI source: `/Users/devops.ai/fixops/Fixops/suite-core/core/sbom_engine.py`
- ALDECI source: `/Users/devops.ai/fixops/Fixops/suite-core/core/sbom_export_engine.py`
- ALDECI source: `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/supply_chain_router.py`
- ALDECI source: `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/supply_chain_attack_detection_router.py`
- ALDECI source: `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/supply_chain_intel_router.py`
- ALDECI source: `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/supply_chain_monitoring_router.py`
- ALDECI source: `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/software_composition_analysis_router.py`
- ALDECI source: `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/dep_scanner_router.py`
- ALDECI source: `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/license_scanner_router.py`
- ALDECI source: `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/vuln_intelligence_router.py`
- ALDECI source: `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/vuln_prioritization_router.py`
- ALDECI source: `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/vuln_lifecycle_router.py`
- ALDECI source: `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/vuln_workflow_router.py`
- ALDECI source: `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/vulnerability_remediation_router.py`
- ALDECI source: `/Users/devops.ai/fixops/Fixops/suite-api/apps/api/vulnerability_scoring_router.py`
- Prior competitive analysis: `/Users/devops.ai/fixops/Fixops/.omc/reports/competitor_snyk_analysis.md`
