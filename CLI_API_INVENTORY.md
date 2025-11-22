# FixOps CLI and API Inventory

## CLI Commands (core/cli.py)

### 1. stage-run
**Purpose:** Normalize a single stage input and materialize canonical outputs
**Entry Point:** `core/cli.py:_handle_stage_run()`
**Arguments:**
- `--stage` (required): requirements, design, build, test, deploy, operate, decision
- `--input`: Path to stage input artifact
- `--app`: Application identifier
- `--output`: Optional path to copy canonical output
- `--mode`: demo or enterprise
- `--sign`: Sign canonical outputs
- `--verify`: Verify signatures
- `--verbose`: Print verbose information

**Flow:** CLI → StageRunner.run_stage() → Output files in registry

### 2. run
**Purpose:** Execute the FixOps pipeline locally
**Entry Point:** `core/cli.py:_handle_run()`
**Arguments:** (via _configure_pipeline_parser)
- Design, SBOM, SARIF, CVE inputs
- `--overlay`: Path to overlay file
- `--quiet`: Suppress summary

**Flow:** CLI → PipelineOrchestrator.run() → Evidence bundle + decision

### 3. ingest
**Purpose:** Normalize artifacts and print pipeline response
**Entry Point:** `core/cli.py:_handle_ingest()`
**Arguments:** Same as run
**Flow:** CLI → PipelineOrchestrator.run() → JSON output

### 4. make-decision
**Purpose:** Execute pipeline and use decision as exit code
**Entry Point:** `core/cli.py:_handle_make_decision()`
**Arguments:** Same as run
**Flow:** CLI → PipelineOrchestrator.run() → Exit code based on decision

### 5. health
**Purpose:** Check integration readiness for local runs
**Entry Point:** `core/cli.py:_handle_health()`
**Arguments:**
- `--overlay`: Path to overlay file
- `--pretty`: Pretty-print JSON

**Flow:** CLI → Check integrations → Health status JSON

### 6. get-evidence
**Purpose:** Copy evidence bundle from pipeline result
**Entry Point:** `core/cli.py:_handle_get_evidence()`
**Arguments:**
- `--result` (required): Path to pipeline result JSON
- `--destination`: Directory to copy bundle
- `--pretty`: Pretty-print JSON

**Flow:** CLI → Read result → Copy evidence bundle

### 7. show-overlay
**Purpose:** Print sanitized overlay configuration
**Entry Point:** `core/cli.py:_handle_show_overlay()`
**Arguments:**
- `--overlay`: Path to overlay file
- `--env`: Set environment variables
- `--pretty`: Pretty-print JSON

**Flow:** CLI → Load overlay → Print config

### 8. train-forecast
**Purpose:** Calibrate probabilistic severity forecast engine
**Entry Point:** `core/cli.py:_handle_train_forecast()`
**Arguments:**
- `--incidents` (required): Historical incident records JSON
- `--config`: Base forecast configuration
- `--output`: File to write calibrated priors
- `--pretty`: Pretty-print JSON
- `--enforce-validation`: Fail if matrix doesn't validate
- `--quiet`: Suppress summary

**Flow:** CLI → Train forecast model → Save calibrated config

### 9. demo
**Purpose:** Run pipeline with bundled demo/enterprise fixtures
**Entry Point:** `core/cli.py:_handle_demo()`
**Arguments:**
- `--mode`: demo or enterprise
- `--output`: Path to write pipeline response
- `--pretty`: Pretty-print JSON
- `--quiet`: Suppress summary

**Flow:** CLI → Load fixtures → PipelineOrchestrator.run() → Output

### 10. train-bn-lr
**Purpose:** Train Bayesian Network + Logistic Regression hybrid model
**Entry Point:** `core/cli.py:_handle_train_bn_lr()`
**Arguments:**
- `--data` (required): Path to CSV training data
- `--output`: Path to write trained model
- `--pretty`: Pretty-print JSON
- `--quiet`: Suppress training summary

**Flow:** CLI → Train BN-LR model → Save model file

### 11. predict-bn-lr
**Purpose:** Make predictions using trained BN-LR model
**Entry Point:** `core/cli.py:_handle_predict_bn_lr()`
**Arguments:**
- `--model` (required): Path to trained model
- `--data` (required): Path to CSV test data
- `--output`: Path to write predictions
- `--pretty`: Pretty-print JSON
- `--quiet`: Suppress prediction summary

**Flow:** CLI → Load model → Make predictions → Output results

### 12. backtest-bn-lr
**Purpose:** Backtest BN-LR model performance
**Entry Point:** `core/cli.py:_handle_backtest_bn_lr()`
**Arguments:**
- `--model` (required): Path to trained model
- `--data` (required): Path to CSV test data
- `--output`: Path to write metrics
- `--pretty`: Pretty-print JSON
- `--thresholds`: Comma-separated decision thresholds
- `--allow-skew`: Allow BN CPD hash mismatch
- `--quiet`: Suppress backtest summary

**Flow:** CLI → Load model → Evaluate on test data → Output metrics

### 13. inventory
**Purpose:** Manage application and service inventory
**Entry Point:** `core/cli.py:_handle_inventory()`

#### 13.1 inventory list
```bash
fixops inventory list [--limit N] [--offset N] [--format table|json]
```
- Lists all applications with pagination
- Default format: table
- Returns exit code 0 on success

#### 13.2 inventory create
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

#### 13.3 inventory get
```bash
fixops inventory get <id> [--format table|json]
```
- Gets application details by ID
- Default format: json
- Returns exit code 0 if found, 1 if not found

#### 13.4 inventory update
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

#### 13.5 inventory delete
```bash
fixops inventory delete <id> --confirm
```
- Deletes application (requires --confirm flag)
- Returns exit code 0 on success, 1 on failure

#### 13.6 inventory search
```bash
fixops inventory search <query> [--limit N]
```
- Searches across all inventory types
- Returns JSON with results
- Returns exit code 0 on success

**Flow:** CLI → InventoryDB operations → Output results

### 14. users
**Purpose:** Manage users and authentication
**Entry Point:** `core/cli.py:_handle_users()`

#### 14.1 users list
```bash
fixops users list [--limit N] [--offset N] [--format table|json]
```
- Lists all users with pagination
- Default format: table
- Returns exit code 0 on success

#### 14.2 users create
```bash
fixops users create \
  --email "user@example.com" \
  --password "password" \
  --first-name "John" \
  --last-name "Doe" \
  --role admin|security_analyst|developer|viewer \
  [--department "Engineering"]
```
- Creates new user with bcrypt password hashing
- Returns exit code 0 on success, 1 on failure

#### 14.3 users get
```bash
fixops users get <id>
```
- Gets user details by ID
- Password hash is redacted by default
- Returns exit code 0 if found, 1 if not found

#### 14.4 users update
```bash
fixops users update <id> \
  [--first-name "Jane"] \
  [--last-name "Smith"] \
  [--role admin|security_analyst|developer|viewer] \
  [--status active|inactive|suspended]
```
- Updates user fields
- Returns exit code 0 on success

#### 14.5 users delete
```bash
fixops users delete <id> --confirm
```
- Deletes user (requires --confirm flag)
- Returns exit code 0 on success, 1 on failure

**Flow:** CLI → UserDB operations → Output results

### 15. teams
**Purpose:** Manage teams and team membership
**Entry Point:** `core/cli.py:_handle_teams()`

#### 15.1 teams list
```bash
fixops teams list [--limit N] [--offset N] [--format table|json]
```
- Lists all teams with pagination
- Returns exit code 0 on success

#### 15.2 teams create
```bash
fixops teams create \
  --name "Security Team" \
  --description "Application security team"
```
- Creates new team
- Returns exit code 0 on success

#### 15.3 teams get
```bash
fixops teams get <id>
```
- Gets team details by ID
- Returns exit code 0 if found, 1 if not found

#### 15.4 teams update
```bash
fixops teams update <id> \
  [--name "New Name"] \
  [--description "New Description"]
```
- Updates team fields
- Returns exit code 0 on success

#### 15.5 teams delete
```bash
fixops teams delete <id> --confirm
```
- Deletes team (requires --confirm flag)
- Returns exit code 0 on success

#### 15.6 teams members
```bash
fixops teams members <team_id> [--format table|json]
```
- Lists all members of a team
- Returns exit code 0 on success

#### 15.7 teams add-member
```bash
fixops teams add-member <team_id> --user-id <user_id> [--role member|lead]
```
- Adds user to team
- Returns exit code 0 on success

#### 15.8 teams remove-member
```bash
fixops teams remove-member <team_id> --user-id <user_id>
```
- Removes user from team
- Returns exit code 0 on success

**Flow:** CLI → UserDB operations → Output results

### 16. policies
**Purpose:** Manage security policies
**Entry Point:** `core/cli.py:_handle_policies()`

#### 16.1 policies list
```bash
fixops policies list [--type guardrail|compliance|custom] [--limit N] [--offset N] [--format table|json]
```
- Lists all policies with optional type filtering
- Returns exit code 0 on success

#### 16.2 policies create
```bash
fixops policies create \
  --name "SQL Injection Policy" \
  --description "Block SQL injection vulnerabilities" \
  --type guardrail \
  [--status active|draft|archived]
```
- Creates new policy
- Returns exit code 0 on success

#### 16.3 policies get
```bash
fixops policies get <id>
```
- Gets policy details by ID
- Returns exit code 0 if found, 1 if not found

#### 16.4 policies update
```bash
fixops policies update <id> \
  [--name "New Name"] \
  [--description "New Description"] \
  [--status active|draft|archived]
```
- Updates policy fields
- Returns exit code 0 on success

#### 16.5 policies delete
```bash
fixops policies delete <id> --confirm
```
- Deletes policy (requires --confirm flag)
- Returns exit code 0 on success

**Flow:** CLI → PolicyDB operations → Output results

### 17. analytics
**Purpose:** Query analytics data and generate reports
**Entry Point:** `core/cli.py:_handle_analytics()`

#### 17.1 analytics dashboard
```bash
fixops analytics dashboard
```
- Gets comprehensive security posture overview
- Returns JSON with total findings, decisions, and breakdowns
- Returns exit code 0 on success

#### 17.2 analytics findings
```bash
fixops analytics findings \
  [--severity critical|high|medium|low|info] \
  [--status open|in_progress|resolved|false_positive|accepted_risk] \
  [--limit N] \
  [--offset N] \
  [--format table|json]
```
- Lists findings with optional filtering
- Default format: table
- Returns exit code 0 on success

#### 17.3 analytics decisions
```bash
fixops analytics decisions \
  [--outcome block|alert|allow|review] \
  [--limit N] \
  [--offset N] \
  [--format table|json]
```
- Lists decision history with optional filtering
- Default format: table
- Returns exit code 0 on success

#### 17.4 analytics top-risks
```bash
fixops analytics top-risks [--limit N]
```
- Gets highest priority security risks
- Default limit: 10
- Returns JSON with risk details
- Returns exit code 0 on success

#### 17.5 analytics mttr
```bash
fixops analytics mttr
```
- Calculates mean time to remediation
- Returns JSON with MTTR in hours and days
- Returns exit code 0 on success

#### 17.6 analytics roi
```bash
fixops analytics roi
```
- Calculates return on investment metrics
- Returns JSON with cost savings estimates
- Returns exit code 0 on success

#### 17.7 analytics export
```bash
fixops analytics export \
  --data-type findings|decisions|metrics \
  [--format json|csv]
```
- Exports analytics data
- Default format: json
- Returns exit code 0 on success

**Flow:** CLI → AnalyticsDB operations → Output results

### 18. integrations
**Purpose:** Manage external integrations
**Entry Point:** `core/cli.py:_handle_integrations()`

#### 18.1 integrations list
```bash
fixops integrations list \
  [--type jira|confluence|slack|github|gitlab|pagerduty] \
  [--limit N] \
  [--offset N] \
  [--format table|json]
```
- Lists all integrations with optional type filtering
- Secrets are redacted by default
- Default format: table
- Returns exit code 0 on success

#### 18.2 integrations create
```bash
fixops integrations create \
  --name "Production Jira" \
  --type jira|confluence|slack|github|gitlab|pagerduty \
  [--status active|inactive]
```
- Creates new integration
- Config must be provided via stdin as JSON
- Returns exit code 0 on success

#### 18.3 integrations get
```bash
fixops integrations get <id> [--show-secrets]
```
- Gets integration details by ID
- Secrets are redacted unless --show-secrets is used
- Returns exit code 0 if found, 1 if not found

#### 18.4 integrations update
```bash
fixops integrations update <id> \
  [--name "New Name"] \
  [--status active|inactive|error]
```
- Updates integration fields
- Returns exit code 0 on success

#### 18.5 integrations delete
```bash
fixops integrations delete <id> --confirm
```
- Deletes integration (requires --confirm flag)
- Returns exit code 0 on success

#### 18.6 integrations test
```bash
fixops integrations test <id>
```
- Tests integration connection
- Returns JSON with test results
- Returns exit code 0 on success

**Flow:** CLI → IntegrationDB operations → Output results

## API Endpoints

### Core API (apps/api/app.py)
- `GET /health` - Health check endpoint
- `GET /api/v1/status` - Authenticated status endpoint
- `POST /inputs/design` - Upload design CSV
- `POST /inputs/sbom` - Upload SBOM JSON
- `POST /inputs/cve` - Upload CVE JSON
- `POST /inputs/vex` - Upload VEX document
- `POST /inputs/cnapp` - Upload CNAPP findings
- `POST /inputs/sarif` - Upload SARIF scan results
- `POST /inputs/context` - Upload business context
- `POST /api/v1/uploads/init` - Initialize chunked upload
- `POST /api/v1/uploads/{upload_id}/chunk` - Upload chunk
- `POST /api/v1/uploads/{upload_id}/complete` - Complete upload
- `GET /api/v1/uploads/{upload_id}/status` - Get upload status
- `POST /pipeline/run` - Execute pipeline
- `GET /analytics/dashboard` - Get analytics dashboard
- `GET /analytics/run/{run_id}` - Get analytics for specific run
- `POST /feedback` - Submit feedback

### Inventory API (apps/api/inventory_router.py) - Phase 1 ✅
- `GET /api/v1/inventory/applications` - List applications
- `POST /api/v1/inventory/applications` - Create application
- `GET /api/v1/inventory/applications/{id}` - Get application
- `PUT /api/v1/inventory/applications/{id}` - Update application
- `DELETE /api/v1/inventory/applications/{id}` - Delete application
- `GET /api/v1/inventory/applications/{id}/components` - List components
- `GET /api/v1/inventory/applications/{id}/apis` - List APIs
- `GET /api/v1/inventory/applications/{id}/dependencies` - Get dependencies
- `GET /api/v1/inventory/services` - List services
- `POST /api/v1/inventory/services` - Create service
- `GET /api/v1/inventory/services/{id}` - Get service
- `GET /api/v1/inventory/apis` - List API endpoints
- `POST /api/v1/inventory/apis` - Create API endpoint
- `GET /api/v1/inventory/apis/{id}/security` - Get API security
- `GET /api/v1/inventory/search` - Search inventory

### User Management API (apps/api/users_router.py) - Phase 2 ✅
- `POST /api/v1/users/login` - Authenticate user and return JWT token
- `GET /api/v1/users` - List users
- `POST /api/v1/users` - Create user
- `GET /api/v1/users/{id}` - Get user details
- `PUT /api/v1/users/{id}` - Update user
- `DELETE /api/v1/users/{id}` - Delete user

### Team Management API (apps/api/teams_router.py) - Phase 2 ✅
- `GET /api/v1/teams` - List teams
- `POST /api/v1/teams` - Create team
- `GET /api/v1/teams/{id}` - Get team details
- `PUT /api/v1/teams/{id}` - Update team
- `DELETE /api/v1/teams/{id}` - Delete team
- `GET /api/v1/teams/{id}/members` - List team members
- `POST /api/v1/teams/{id}/members` - Add team member
- `DELETE /api/v1/teams/{id}/members/{user_id}` - Remove team member

### Policy Management API (apps/api/policies_router.py) - Phase 2 ✅
- `GET /api/v1/policies` - List policies
- `POST /api/v1/policies` - Create policy
- `GET /api/v1/policies/{id}` - Get policy details
- `PUT /api/v1/policies/{id}` - Update policy
- `DELETE /api/v1/policies/{id}` - Delete policy
- `POST /api/v1/policies/{id}/validate` - Validate policy syntax
- `POST /api/v1/policies/{id}/test` - Test policy against sample data
- `GET /api/v1/policies/{id}/violations` - Get policy violations

### Analytics API (apps/api/analytics_router.py) - Phase 3 ✅
- `GET /api/v1/analytics/dashboard/overview` - Get security posture overview
- `GET /api/v1/analytics/dashboard/trends` - Get time-series trend data
- `GET /api/v1/analytics/dashboard/top-risks` - Get highest priority risks
- `GET /api/v1/analytics/dashboard/compliance-status` - Get compliance status
- `GET /api/v1/analytics/findings` - Query findings with filtering
- `POST /api/v1/analytics/findings` - Create finding
- `GET /api/v1/analytics/findings/{id}` - Get finding details
- `PUT /api/v1/analytics/findings/{id}` - Update finding
- `GET /api/v1/analytics/decisions` - Query decision history
- `POST /api/v1/analytics/decisions` - Record decision
- `GET /api/v1/analytics/mttr` - Calculate mean time to remediation
- `GET /api/v1/analytics/coverage` - Get security coverage metrics
- `GET /api/v1/analytics/roi` - Calculate ROI metrics
- `GET /api/v1/analytics/noise-reduction` - Get noise reduction metrics
- `POST /api/v1/analytics/custom-query` - Execute custom query
- `GET /api/v1/analytics/export` - Export analytics data

### Integration Management API (apps/api/integrations_router.py) - Phase 3 ✅
- `GET /api/v1/integrations` - List integrations
- `POST /api/v1/integrations` - Create integration
- `GET /api/v1/integrations/{id}` - Get integration details
- `PUT /api/v1/integrations/{id}` - Update integration
- `DELETE /api/v1/integrations/{id}` - Delete integration
- `POST /api/v1/integrations/{id}/test` - Test integration connection
- `GET /api/v1/integrations/{id}/sync-status` - Get sync status
- `POST /api/v1/integrations/{id}/sync` - Trigger manual sync

### Backend API Routers
- Provenance API (backend/api/provenance/router.py)
- Risk API (backend/api/risk/router.py)
- Graph API (backend/api/graph/router.py)
- Evidence API (backend/api/evidence/router.py)

**Total Endpoints**: ~97 (40 existing + 15 Phase 1 + 22 Phase 2 + 20 Phase 3)
**Remaining to 120+**: ~23 endpoints (Phase 4: Reports, Audit, Workflows)

## Output Files

### Stage Outputs
- requirements.json
- design.manifest.json
- build.report.json
- test.report.json
- deploy.manifest.json
- operate.snapshot.json
- decision.json
- manifest.json (checksums of all stage outputs)

### Evidence Bundle
- evidence_bundle.zip (contains all stage outputs + manifest)

## Code Flow

### Stage Processing
1. CLI/API receives input
2. StageRunner.run_stage() called with stage name and input
3. Stage-specific processor (_process_requirements, _process_design, etc.)
4. Output written to RunRegistry directory
5. Evidence bundle created with all outputs
6. Manifest with checksums generated

### Pipeline Processing
1. CLI/API receives design, SBOM, SARIF, CVE inputs
2. PipelineOrchestrator.run() orchestrates all stages
3. Each stage processes its input
4. Decision engine evaluates all outputs
5. Evidence bundle created
6. Pipeline result returned with all summaries
