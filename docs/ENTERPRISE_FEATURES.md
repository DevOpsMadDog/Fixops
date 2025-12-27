# FixOps Enterprise Features Roadmap

## Executive Summary

This document outlines the world-class enterprise features designed to make FixOps the definitive platform for vulnerability management teams. These features address the five priority areas identified for enterprise readiness, with architectural patterns that differentiate FixOps from all competitors.

**Priority Features:**
1. **HIGH**: Intelligent Deduplication & Correlation Engine
2. **HIGH**: Complete Jira/ServiceNow Integration with Bidirectional Sync
3. **MEDIUM**: Remediation Lifecycle Management
4. **MEDIUM**: Enterprise Bulk Operations for Triage
5. **LOW**: Team Collaboration & Knowledge Sharing

---

## 1. Intelligent Deduplication & Correlation Engine

### Overview

The FixOps Correlation Engine is a two-layer system that separates **deduplication** (identity matching) from **correlation** (root cause analysis). This separation is critical because enterprise teams require extremely high precision for dedup merges while accepting probabilistic correlation for investigation.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Correlation Engine Architecture                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐       │
│  │  Scanner Input   │───▶│  Normalization   │───▶│ FindingIdentity  │       │
│  │  (SARIF/SBOM/    │    │  Layer           │    │ Generation       │       │
│  │   CVE/VEX)       │    │                  │    │                  │       │
│  └──────────────────┘    └──────────────────┘    └────────┬─────────┘       │
│                                                           │                  │
│                          ┌────────────────────────────────┼──────────────┐  │
│                          │         Dedup Layer            │              │  │
│                          │  ┌─────────────────────────────▼────────────┐ │  │
│                          │  │         FindingGroup                     │ │  │
│                          │  │  • Canonical fingerprint                 │ │  │
│                          │  │  • Member findings                       │ │  │
│                          │  │  • Merge history                         │ │  │
│                          │  │  • Confidence score                      │ │  │
│                          │  └─────────────────────────────┬────────────┘ │  │
│                          └────────────────────────────────┼──────────────┘  │
│                                                           │                  │
│                          ┌────────────────────────────────┼──────────────┐  │
│                          │      Correlation Layer         │              │  │
│                          │  ┌─────────────────────────────▼────────────┐ │  │
│                          │  │       CorrelationLink                    │ │  │
│                          │  │  • Source group → Target group           │ │  │
│                          │  │  • Correlation type                      │ │  │
│                          │  │  • Confidence score                      │ │  │
│                          │  │  • Evidence chain                        │ │  │
│                          │  │  • Root cause hypothesis                 │ │  │
│                          │  └──────────────────────────────────────────┘ │  │
│                          └───────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Core Data Models

#### FindingIdentity
A stable identifier for a finding that persists across scanner runs and tool versions.

```python
@dataclass
class FindingIdentity:
    """Canonical identity for a security finding."""
    
    fingerprint: str           # SHA256 of normalized attributes
    rule_id: str               # CWE/CVE/rule identifier
    location_hash: str         # Normalized file:line:column
    component_hash: str        # SBOM component identifier
    scanner_family: str        # SAST/DAST/SCA/IaC
    
    # Enrichment signals
    cve_id: Optional[str]
    cwe_id: Optional[str]
    epss_score: Optional[float]
    kev_listed: bool
```

#### FindingGroup
A deduplicated cluster of findings that represent the same underlying issue.

```python
@dataclass
class FindingGroup:
    """Deduplicated cluster of related findings."""
    
    id: str                              # Stable group identifier
    canonical_identity: FindingIdentity  # Representative identity
    member_findings: List[str]           # Finding IDs in this group
    confidence_score: float              # Dedup confidence (0.0-1.0)
    
    # Lifecycle
    status: GroupStatus                  # open/triaged/remediated/accepted_risk
    created_at: datetime
    updated_at: datetime
    
    # Merge history for audit
    merge_history: List[MergeEvent]
    
    # Crosswalk integration
    affected_components: List[str]       # From design → SBOM crosswalk
    attack_paths: List[str]              # From reachability analysis
```

#### CorrelationLink
An edge in the correlation graph connecting related finding groups.

```python
@dataclass
class CorrelationLink:
    """Correlation edge between finding groups."""
    
    id: str
    source_group_id: str
    target_group_id: str
    
    correlation_type: CorrelationType    # See below
    confidence_score: float              # 0.0-1.0
    
    # Explainability (critical for enterprise)
    evidence_chain: List[CorrelationEvidence]
    root_cause_hypothesis: str
    signals_used: List[str]
    
    # Audit trail
    created_at: datetime
    created_by: str                      # system/user
```

### Correlation Strategies

The engine implements seven correlation strategies, each producing explainable evidence:

| Strategy | Confidence | Description |
|----------|------------|-------------|
| `exact_fingerprint` | 0.95 | Identical normalized fingerprints across runs |
| `location_proximity` | 0.80 | Same file within 10 lines |
| `rule_pattern` | 0.70 | Same rule + scanner + severity |
| `vulnerability_taxonomy` | 0.90 | Same CVE or CWE identifier |
| `dependency_chain` | 0.85 | Shared vulnerable component in SBOM crosswalk |
| `attack_path` | 0.75 | Shared reachability path from internet exposure |
| `root_cause_cluster` | 0.60 | Semantic similarity in description keywords |

### API Endpoints

```
# Correlation Analysis
POST   /api/v1/correlation/analyze              # Analyze findings for correlations
GET    /api/v1/correlation/jobs/{job_id}        # Get async job status
GET    /api/v1/correlation/jobs/{job_id}/results # Get correlation results

# Finding Groups (Dedup)
GET    /api/v1/groups                           # List finding groups
GET    /api/v1/groups/{id}                      # Get group details
GET    /api/v1/groups/{id}/members              # List member findings
POST   /api/v1/groups/{id}/merge                # Merge groups (human-in-loop)
POST   /api/v1/groups/{id}/unmerge              # Unmerge with history
GET    /api/v1/groups/{id}/history              # Merge/unmerge audit trail

# Correlation Links
GET    /api/v1/correlation/links                # List correlation links
GET    /api/v1/correlation/links/{id}           # Get link with evidence
GET    /api/v1/correlation/graph                # Get full correlation graph
POST   /api/v1/correlation/links/{id}/accept    # Accept correlation suggestion
POST   /api/v1/correlation/links/{id}/reject    # Reject with reason
```

### CLI Commands

```bash
# Correlation analysis
fixops correlation analyze --input findings.json --output correlations.json
fixops correlation status <job_id>

# Group management
fixops groups list [--status open|triaged|remediated]
fixops groups show <group_id>
fixops groups merge <source_id> <target_id> --reason "Same root cause"
fixops groups unmerge <group_id> --finding <finding_id>

# Correlation graph
fixops correlation graph --format dot|json --output graph.dot
fixops correlation explain <link_id>
```

### Integration with FixOps Pipeline

The correlation engine integrates at three points in the pipeline:

1. **Post-Normalization**: After SARIF/SBOM/CVE normalization, generate FindingIdentity
2. **Post-Crosswalk**: After crosswalk generation, correlate by dependency chain and attack path
3. **Evidence Bundle**: Include correlation evidence in audit bundles

### Noise Reduction Metrics

Target: **35% reduction in alert fatigue** through intelligent grouping.

```python
@dataclass
class NoiseReductionMetrics:
    """Metrics for correlation effectiveness."""
    
    total_raw_findings: int
    total_groups: int
    reduction_ratio: float              # 1 - (groups / findings)
    
    correlation_breakdown: Dict[str, int]  # By correlation type
    confidence_distribution: List[float]   # Histogram of confidence scores
    
    # Quality metrics
    false_positive_rate: float          # From user feedback
    merge_acceptance_rate: float        # Human-in-loop acceptance
```

---

## 2. Complete Jira/ServiceNow Integration

### Overview

Enterprise-grade integration requires **bidirectional state reconciliation**, not fire-and-forget ticket creation. The FixOps integration framework implements an outbox/inbox pattern with reliable delivery, idempotency, and drift detection.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Integration Framework Architecture                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────┐                           ┌──────────────────┐        │
│  │   FixOps Core    │                           │  External System │        │
│  │                  │                           │  (Jira/ServiceNow)│        │
│  │  ┌────────────┐  │    ┌─────────────────┐   │                  │        │
│  │  │ Finding    │──┼───▶│    Outbox       │───┼─▶│  Create/Update │        │
│  │  │ Group      │  │    │  (Intent Store) │   │  │  Ticket        │        │
│  │  └────────────┘  │    └─────────────────┘   │  └────────┬───────┘        │
│  │                  │                           │           │                │
│  │  ┌────────────┐  │    ┌─────────────────┐   │           │                │
│  │  │ Remediation│◀─┼────│    Inbox        │◀──┼───────────┘                │
│  │  │ Task       │  │    │  (Event Store)  │   │  Webhook/Poll              │
│  │  └────────────┘  │    └─────────────────┘   │                            │
│  │                  │                           │                            │
│  │  ┌────────────┐  │    ┌─────────────────┐   │                            │
│  │  │ Mapping    │◀─┼───▶│  Mapping Store  │   │                            │
│  │  │ Registry   │  │    │  (Link Table)   │   │                            │
│  │  └────────────┘  │    └─────────────────┘   │                            │
│  │                  │                           │                            │
│  └──────────────────┘                           └────────────────────────────┘
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Core Data Models

#### IntegrationMapping
Links FixOps entities to external tickets with state tracking.

```python
@dataclass
class IntegrationMapping:
    """Bidirectional mapping between FixOps and external systems."""
    
    id: str
    fixops_entity_type: str              # finding_group | remediation_task
    fixops_entity_id: str
    
    external_system: str                 # jira | servicenow
    external_id: str                     # Jira key or ServiceNow sys_id
    external_url: str                    # Deep link
    
    # State tracking
    last_fixops_state: Dict[str, Any]    # Hash of relevant fields
    last_external_state: Dict[str, Any]  # Hash of relevant fields
    last_sync_at: datetime
    sync_direction: str                  # fixops_to_external | external_to_fixops | bidirectional
    
    # Drift detection
    drift_detected: bool
    drift_details: Optional[Dict[str, Any]]
```

#### IntegrationOutboxEvent
Reliable delivery with idempotency and retry logic.

```python
@dataclass
class IntegrationOutboxEvent:
    """Outbox event for reliable delivery."""
    
    id: str
    idempotency_key: str                 # Prevents duplicate operations
    
    operation: str                       # create_ticket | update_ticket | close_ticket
    target_system: str                   # jira | servicenow
    payload: Dict[str, Any]
    
    # Delivery tracking
    status: str                          # pending | delivered | failed | dead_letter
    attempts: int
    last_attempt_at: Optional[datetime]
    last_error: Optional[str]
    
    # Audit
    created_at: datetime
    delivered_at: Optional[datetime]
```

### Supported Integrations

#### Jira Cloud/Server
- **Authentication**: OAuth 2.0, API Token, Basic Auth
- **Operations**: Create issue, update fields, transition status, add comments, attach files
- **Webhooks**: Issue created, updated, deleted, transitioned
- **Field Mapping**: Custom field templates with JQL validation

#### ServiceNow
- **Authentication**: OAuth 2.0, Basic Auth
- **Tables**: incident, problem, change_request, security_incident
- **Operations**: Create record, update fields, add work notes, resolve/close
- **Webhooks**: Business rules, scripted REST API callbacks
- **CMDB Integration**: Link to configuration items

### Ticket Lifecycle Policies

```yaml
# Example policy configuration
ticket_lifecycle:
  auto_create:
    enabled: true
    trigger: finding_group_created
    conditions:
      - severity: [critical, high]
      - status: open
    
  auto_close:
    enabled: true
    trigger: finding_group_remediated
    verification_required: true
    
  auto_reopen:
    enabled: true
    trigger: finding_reappeared
    create_child_task: false
    
  risk_acceptance:
    sync_to_ticket: true
    include_expiry: true
    require_approval_chain: true
```

### API Endpoints

```
# Integration Configuration
GET    /api/v1/integrations                      # List configured integrations
POST   /api/v1/integrations                      # Create integration
GET    /api/v1/integrations/{id}                 # Get integration details
PUT    /api/v1/integrations/{id}                 # Update integration
DELETE /api/v1/integrations/{id}                 # Delete integration
POST   /api/v1/integrations/{id}/test            # Test connection

# Ticket Operations
POST   /api/v1/integrations/{id}/tickets         # Create ticket for entity
GET    /api/v1/integrations/{id}/tickets         # List tickets
PUT    /api/v1/integrations/{id}/tickets/{tid}   # Update ticket
POST   /api/v1/integrations/{id}/tickets/{tid}/sync # Force sync

# Mappings
GET    /api/v1/integrations/mappings             # List all mappings
GET    /api/v1/integrations/mappings/{id}        # Get mapping details
DELETE /api/v1/integrations/mappings/{id}        # Unlink mapping

# Webhooks
POST   /api/v1/integrations/webhooks/jira        # Jira webhook receiver
POST   /api/v1/integrations/webhooks/servicenow  # ServiceNow webhook receiver

# Sync Jobs
POST   /api/v1/integrations/{id}/sync            # Trigger full sync
GET    /api/v1/integrations/{id}/sync/status     # Get sync job status
GET    /api/v1/integrations/{id}/sync/history    # Sync history
```

### CLI Commands

```bash
# Integration management
fixops integrations list
fixops integrations configure jira --url https://company.atlassian.net --project SEC
fixops integrations configure servicenow --url https://company.service-now.com --table incident
fixops integrations test <integration_id>

# Ticket operations
fixops tickets create --group <group_id> --integration <integration_id>
fixops tickets sync --integration <integration_id> [--full]
fixops tickets status <ticket_id>

# Mapping management
fixops mappings list [--integration <id>] [--drift-only]
fixops mappings unlink <mapping_id>
```

### Reliability Features

1. **Idempotency**: All write operations accept `X-Idempotency-Key` header
2. **Retry with Backoff**: Exponential backoff with jitter (1s, 2s, 4s, 8s, 16s)
3. **Dead Letter Queue**: Failed events after 5 attempts go to DLQ for manual review
4. **Rate Limiting**: Per-integration rate limits respecting external API quotas
5. **Health Checks**: Continuous connectivity monitoring with alerting
6. **Replay Tooling**: Ability to replay failed events from audit log

---

## 3. Remediation Lifecycle Management

### Overview

Remediation tracking requires a proper **state machine** and **timeline**, not a single status field. FixOps separates **FindingGroup** (what is wrong) from **RemediationTask** (what we're doing about it), enabling proper SLA tracking, ownership, and verification.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Remediation Lifecycle Architecture                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  FindingGroup                          RemediationTask                       │
│  ┌──────────────────┐                  ┌──────────────────────────────────┐ │
│  │ • What is wrong  │    creates       │ • What we're doing about it      │ │
│  │ • Severity       │─────────────────▶│ • Owner                          │ │
│  │ • Correlation    │                  │ • Due date                       │ │
│  │ • Evidence       │                  │ • SLA tracking                   │ │
│  └──────────────────┘                  │ • Status history                 │ │
│         │                              │ • Verification evidence          │ │
│         │ can have many                └──────────────────────────────────┘ │
│         │ tasks over time                           │                       │
│         │                                           │                       │
│         ▼                                           ▼                       │
│  ┌──────────────────┐                  ┌──────────────────────────────────┐ │
│  │ Task 1 (closed)  │                  │        State Machine             │ │
│  │ Task 2 (closed)  │                  │                                  │ │
│  │ Task 3 (active)  │                  │  open → assigned → in_progress   │ │
│  └──────────────────┘                  │    │                    │        │ │
│                                        │    ▼                    ▼        │ │
│                                        │  deferred          verified      │ │
│                                        │    │                    │        │ │
│                                        │    ▼                    ▼        │ │
│                                        │  risk_accepted      closed       │ │
│                                        │                                  │ │
│                                        └──────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Core Data Models

#### RemediationTask
The actionable work item for addressing a finding group.

```python
@dataclass
class RemediationTask:
    """Actionable remediation work item."""
    
    id: str
    finding_group_id: str
    
    # Ownership
    owner_id: Optional[str]
    team_id: Optional[str]
    
    # Status
    status: TaskStatus                   # See state machine
    status_history: List[StatusTransition]
    
    # SLA
    created_at: datetime
    due_date: Optional[datetime]
    sla_policy_id: Optional[str]
    sla_breached: bool
    
    # Risk acceptance
    risk_accepted: bool
    risk_acceptance_expiry: Optional[datetime]
    risk_acceptance_reason: Optional[str]
    risk_acceptance_approver: Optional[str]
    
    # Verification
    verification_required: bool
    verification_evidence: Optional[VerificationEvidence]
    verified_at: Optional[datetime]
    verified_by: Optional[str]
    
    # External tracking
    external_ticket_id: Optional[str]
    external_ticket_url: Optional[str]
```

#### StatusTransition
Audit trail for every status change.

```python
@dataclass
class StatusTransition:
    """Audit record for status changes."""
    
    id: str
    task_id: str
    
    from_status: TaskStatus
    to_status: TaskStatus
    
    transitioned_at: datetime
    transitioned_by: str
    
    reason: Optional[str]
    evidence_id: Optional[str]          # Link to evidence bundle
```

#### VerificationEvidence
Cryptographic proof that remediation occurred.

```python
@dataclass
class VerificationEvidence:
    """Proof of remediation."""
    
    id: str
    task_id: str
    
    verification_type: str              # pipeline_clean | sbom_update | vex_statement | manual
    
    # For pipeline_clean
    pipeline_run_id: Optional[str]
    finding_absent_proof: Optional[str]
    
    # For sbom_update
    sbom_before_hash: Optional[str]
    sbom_after_hash: Optional[str]
    component_version_change: Optional[Dict[str, str]]
    
    # For vex_statement
    vex_statement_id: Optional[str]
    vex_justification: Optional[str]
    
    # Cryptographic signing
    evidence_hash: str
    signature: str
    signed_at: datetime
```

### SLA Policies

```yaml
# Example SLA policy configuration
sla_policies:
  critical_internet_facing:
    name: "Critical + Internet Facing"
    conditions:
      severity: critical
      internet_facing: true
    time_to_triage: 4h
    time_to_remediate: 24h
    escalation_chain:
      - after: 2h
        notify: [security-team]
      - after: 4h
        notify: [security-lead, engineering-lead]
      - after: 8h
        notify: [ciso]
    
  high_severity:
    name: "High Severity"
    conditions:
      severity: high
    time_to_triage: 24h
    time_to_remediate: 7d
    
  standard:
    name: "Standard"
    conditions:
      severity: [medium, low]
    time_to_triage: 72h
    time_to_remediate: 30d
```

### API Endpoints

```
# Remediation Tasks
GET    /api/v1/remediation/tasks                 # List tasks
POST   /api/v1/remediation/tasks                 # Create task for group
GET    /api/v1/remediation/tasks/{id}            # Get task details
PUT    /api/v1/remediation/tasks/{id}            # Update task
DELETE /api/v1/remediation/tasks/{id}            # Delete task

# Status Transitions
POST   /api/v1/remediation/tasks/{id}/assign     # Assign owner
POST   /api/v1/remediation/tasks/{id}/start      # Start work
POST   /api/v1/remediation/tasks/{id}/defer      # Defer with reason
POST   /api/v1/remediation/tasks/{id}/accept-risk # Accept risk with expiry
POST   /api/v1/remediation/tasks/{id}/verify     # Submit verification evidence
POST   /api/v1/remediation/tasks/{id}/close      # Close task

# History
GET    /api/v1/remediation/tasks/{id}/history    # Status history
GET    /api/v1/remediation/tasks/{id}/evidence   # Verification evidence

# SLA
GET    /api/v1/remediation/sla/policies          # List SLA policies
GET    /api/v1/remediation/sla/breaches          # List SLA breaches
GET    /api/v1/remediation/sla/report            # SLA compliance report

# Metrics
GET    /api/v1/remediation/metrics/mttr          # Mean time to remediate
GET    /api/v1/remediation/metrics/mttd          # Mean time to detect
GET    /api/v1/remediation/metrics/sla           # SLA compliance rate
```

### CLI Commands

```bash
# Task management
fixops remediation list [--status open|in_progress|verified]
fixops remediation create --group <group_id> --owner <user_id>
fixops remediation assign <task_id> --owner <user_id>
fixops remediation start <task_id>
fixops remediation verify <task_id> --evidence <evidence_file>
fixops remediation close <task_id>

# Risk acceptance
fixops remediation accept-risk <task_id> --reason "Compensating controls" --expiry 90d

# SLA reporting
fixops remediation sla-report --period 30d --format csv
fixops remediation mttr --period 90d
```

### Drift Detection

When a remediated finding reappears:

1. System detects finding in new pipeline run
2. Matches to previously closed task via FindingGroup
3. Creates new task linked to previous task
4. Notifies original owner and team
5. Includes diff showing what changed

---

## 4. Enterprise Bulk Operations

### Overview

Enterprise bulk operations require **job semantics** with partial failure handling, per-item outcomes, and full audit trails. FixOps implements an async job model that scales to thousands of items.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Bulk Operations Architecture                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐       │
│  │  Submit Bulk     │───▶│   Job Queue      │───▶│  Job Processor   │       │
│  │  Request         │    │                  │    │                  │       │
│  │                  │    │  • Job ID        │    │  • Batch items   │       │
│  │  • Selection     │    │  • Status        │    │  • Apply action  │       │
│  │  • Action        │    │  • Progress      │    │  • Record result │       │
│  │  • Parameters    │    │  • Results       │    │  • Update status │       │
│  └──────────────────┘    └──────────────────┘    └──────────────────┘       │
│                                   │                        │                 │
│                                   ▼                        ▼                 │
│                          ┌──────────────────┐    ┌──────────────────┐       │
│                          │  Job Status API  │    │  Audit Log       │       │
│                          │                  │    │                  │       │
│                          │  • Poll status   │    │  • Per-item      │       │
│                          │  • Get results   │    │  • Timestamps    │       │
│                          │  • Download      │    │  • User/system   │       │
│                          └──────────────────┘    └──────────────────┘       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Core Data Models

#### BulkJob
The container for a bulk operation.

```python
@dataclass
class BulkJob:
    """Bulk operation job."""
    
    id: str
    
    # Selection
    selection_type: str                  # explicit_ids | query_filter
    selection_ids: Optional[List[str]]   # If explicit
    selection_query: Optional[Dict]      # If query-based
    resolved_ids: List[str]              # Snapshot at submission time
    
    # Action
    action: BulkAction                   # See below
    parameters: Dict[str, Any]
    
    # Status
    status: JobStatus                    # pending | running | completed | failed | cancelled
    progress: JobProgress
    
    # Results
    results: List[BulkItemResult]
    summary: BulkJobSummary
    
    # Audit
    created_at: datetime
    created_by: str
    completed_at: Optional[datetime]
```

#### BulkAction
Supported bulk actions.

```python
class BulkAction(Enum):
    """Supported bulk operations."""
    
    # Status changes
    ASSIGN = "assign"
    CHANGE_STATUS = "change_status"
    SET_PRIORITY = "set_priority"
    
    # Risk management
    ACCEPT_RISK = "accept_risk"
    REVOKE_RISK_ACCEPTANCE = "revoke_risk_acceptance"
    
    # Ticketing
    CREATE_TICKETS = "create_tickets"
    SYNC_TICKETS = "sync_tickets"
    
    # Export
    EXPORT_CSV = "export_csv"
    EXPORT_JSON = "export_json"
    EXPORT_SARIF = "export_sarif"
    
    # Correlation
    MERGE_GROUPS = "merge_groups"
    APPLY_CORRELATION = "apply_correlation"
```

#### BulkItemResult
Per-item outcome for audit and retry.

```python
@dataclass
class BulkItemResult:
    """Result for a single item in bulk operation."""
    
    item_id: str
    status: str                          # success | failed | skipped
    
    # Success details
    changes_applied: Optional[Dict[str, Any]]
    
    # Failure details
    error_code: Optional[str]
    error_message: Optional[str]
    
    # Timing
    processed_at: datetime
```

### API Endpoints

```
# Job Management
POST   /api/v1/bulk/jobs                         # Submit bulk job
GET    /api/v1/bulk/jobs                         # List jobs
GET    /api/v1/bulk/jobs/{id}                    # Get job status
GET    /api/v1/bulk/jobs/{id}/results            # Get per-item results
GET    /api/v1/bulk/jobs/{id}/download           # Download export
POST   /api/v1/bulk/jobs/{id}/cancel             # Cancel running job
POST   /api/v1/bulk/jobs/{id}/retry              # Retry failed items

# Saved Queries (Views)
GET    /api/v1/bulk/views                        # List saved views
POST   /api/v1/bulk/views                        # Create saved view
GET    /api/v1/bulk/views/{id}                   # Get view details
PUT    /api/v1/bulk/views/{id}                   # Update view
DELETE /api/v1/bulk/views/{id}                   # Delete view
POST   /api/v1/bulk/views/{id}/execute           # Execute view as bulk job
```

### CLI Commands

```bash
# Bulk operations
fixops bulk assign --query "severity:critical AND status:open" --owner security-team
fixops bulk accept-risk --ids id1,id2,id3 --reason "Compensating controls" --expiry 90d
fixops bulk create-tickets --query "severity:high" --integration jira
fixops bulk export --query "created:>2024-01-01" --format csv --output findings.csv

# Job management
fixops bulk status <job_id>
fixops bulk results <job_id> [--failed-only]
fixops bulk cancel <job_id>
fixops bulk retry <job_id>

# Saved views
fixops views list
fixops views create "Critical Open" --query "severity:critical AND status:open"
fixops views execute <view_id> --action assign --owner security-team
```

### Query Language

FixOps supports a powerful query language for bulk selections:

```
# Severity and status
severity:critical AND status:open

# Date ranges
created:>2024-01-01 AND created:<2024-06-01

# Exploitability
kev:true OR epss:>0.7

# Component and location
component:log4j* AND internet_facing:true

# Correlation
correlation_group:group-123 OR root_cause:input_validation

# Combined
(severity:critical OR severity:high) AND internet_facing:true AND status:open
```

---

## 5. Team Collaboration & Knowledge Sharing

### Overview

Enterprise collaboration requires **append-only, auditable** communication with attribution and retention. FixOps implements a threaded comment system with mentions, watchers, and integration with evidence bundles.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Collaboration Architecture                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐       │
│  │  Comment Thread  │    │  Activity Feed   │    │  Notifications   │       │
│  │                  │    │                  │    │                  │       │
│  │  • Comments      │───▶│  • All events    │───▶│  • Mentions      │       │
│  │  • Replies       │    │  • Filterable    │    │  • Watchers      │       │
│  │  • Attachments   │    │  • Searchable    │    │  • Assignments   │       │
│  │  • Mentions      │    │  • Since cursor  │    │  • SLA alerts    │       │
│  └──────────────────┘    └──────────────────┘    └──────────────────┘       │
│           │                       │                       │                  │
│           │                       │                       │                  │
│           ▼                       ▼                       ▼                  │
│  ┌──────────────────────────────────────────────────────────────────┐       │
│  │                      Evidence Integration                         │       │
│  │                                                                   │       │
│  │  • Decision rationale → Evidence bundle                          │       │
│  │  • Risk acceptance notes → Compliance report                     │       │
│  │  • Compensating controls → Audit trail                           │       │
│  └──────────────────────────────────────────────────────────────────┘       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Core Data Models

#### Comment
A single comment in a thread.

```python
@dataclass
class Comment:
    """A comment on a finding group or task."""
    
    id: str
    
    # Target
    entity_type: str                     # finding_group | remediation_task
    entity_id: str
    
    # Threading
    parent_id: Optional[str]             # For replies
    thread_id: str                       # Root comment ID
    
    # Content
    body: str                            # Markdown supported
    body_html: str                       # Rendered HTML
    
    # Mentions
    mentions: List[str]                  # User IDs mentioned
    
    # Attachments
    attachments: List[Attachment]
    
    # Metadata
    comment_type: CommentType            # general | decision_rationale | risk_acceptance | compensating_control
    
    # Audit
    created_at: datetime
    created_by: str
    edited_at: Optional[datetime]
    edited_by: Optional[str]
    
    # Evidence promotion
    promoted_to_evidence: bool
    evidence_bundle_id: Optional[str]
```

#### CommentType
Special comment types that integrate with compliance.

```python
class CommentType(Enum):
    """Comment types with special handling."""
    
    GENERAL = "general"                  # Standard comment
    DECISION_RATIONALE = "decision_rationale"  # Why this decision was made
    RISK_ACCEPTANCE = "risk_acceptance"  # Risk acceptance justification
    COMPENSATING_CONTROL = "compensating_control"  # Compensating control description
    VERIFICATION_NOTE = "verification_note"  # Verification details
    ESCALATION = "escalation"            # Escalation reason
```

#### Watcher
Users watching an entity for updates.

```python
@dataclass
class Watcher:
    """User watching an entity."""
    
    id: str
    user_id: str
    entity_type: str
    entity_id: str
    
    # Notification preferences
    notify_on_comment: bool
    notify_on_status_change: bool
    notify_on_assignment: bool
    notify_on_sla_breach: bool
    
    created_at: datetime
```

### API Endpoints

```
# Comments
GET    /api/v1/groups/{id}/comments              # List comments on group
POST   /api/v1/groups/{id}/comments              # Add comment
GET    /api/v1/tasks/{id}/comments               # List comments on task
POST   /api/v1/tasks/{id}/comments               # Add comment
PUT    /api/v1/comments/{id}                     # Edit comment
DELETE /api/v1/comments/{id}                     # Delete comment
POST   /api/v1/comments/{id}/promote             # Promote to evidence

# Watchers
GET    /api/v1/groups/{id}/watchers              # List watchers
POST   /api/v1/groups/{id}/watchers              # Add watcher
DELETE /api/v1/groups/{id}/watchers/{user_id}    # Remove watcher
GET    /api/v1/tasks/{id}/watchers               # List watchers
POST   /api/v1/tasks/{id}/watchers               # Add watcher

# Activity Feed
GET    /api/v1/activity                          # Global activity feed
GET    /api/v1/groups/{id}/activity              # Group activity
GET    /api/v1/tasks/{id}/activity               # Task activity
GET    /api/v1/users/{id}/activity               # User activity

# Notifications
GET    /api/v1/notifications                     # User notifications
PUT    /api/v1/notifications/{id}/read           # Mark as read
POST   /api/v1/notifications/read-all            # Mark all as read
```

### CLI Commands

```bash
# Comments
fixops comments list --group <group_id>
fixops comments add --group <group_id> --body "Investigation complete, root cause identified"
fixops comments add --task <task_id> --type decision_rationale --body "Accepting risk due to compensating controls"

# Watchers
fixops watch --group <group_id>
fixops unwatch --group <group_id>
fixops watchers list --group <group_id>

# Activity
fixops activity --since 24h
fixops activity --group <group_id>
```

### Integration with External Systems

Comments can be synced bidirectionally with Jira/ServiceNow:

```yaml
# Comment sync configuration
comment_sync:
  jira:
    enabled: true
    sync_direction: bidirectional
    fixops_to_jira:
      include_types: [decision_rationale, risk_acceptance, compensating_control]
      prefix: "[FixOps] "
    jira_to_fixops:
      include_internal: false
      
  servicenow:
    enabled: true
    sync_direction: fixops_to_servicenow
    field: work_notes
```

---

## Feature Flags

All enterprise features are controlled by feature flags for gradual rollout:

```yaml
# Feature flag configuration
feature_flags:
  # Correlation Engine
  fixops.feature.correlation.enabled: false
  fixops.feature.correlation.strategies: [fingerprint, location, pattern, vulnerability]
  fixops.feature.correlation.auto_merge: false
  
  # Integrations
  fixops.feature.integrations.jira.enabled: true
  fixops.feature.integrations.servicenow.enabled: false
  fixops.feature.integrations.bidirectional_sync: false
  
  # Remediation
  fixops.feature.remediation.sla_tracking: true
  fixops.feature.remediation.verification_required: false
  fixops.feature.remediation.drift_detection: true
  
  # Bulk Operations
  fixops.feature.bulk.enabled: true
  fixops.feature.bulk.max_items: 10000
  fixops.feature.bulk.async_threshold: 100
  
  # Collaboration
  fixops.feature.collaboration.comments: true
  fixops.feature.collaboration.watchers: true
  fixops.feature.collaboration.activity_feed: true
```

---

## Migration Path

### Phase 1: Foundation (Current)
- Basic correlation engine (feature-flagged)
- Jira/ServiceNow connectors (fire-and-forget)
- Stub bulk operations
- Feedback recording

### Phase 2: Enterprise Core
- FindingGroup and CorrelationLink data models
- Bidirectional integration sync
- RemediationTask state machine
- Async bulk job framework

### Phase 3: Enterprise Advanced
- Full correlation graph with explanations
- SLA policies and breach alerting
- Saved views and query language
- Comment threading and evidence promotion

### Phase 4: Enterprise Complete
- Human-in-loop merge workflows
- Drift detection and auto-reopen
- Real-time activity feeds
- Full external system sync

---

## Metrics and KPIs

### Correlation Engine
- Noise reduction ratio (target: 35%)
- Merge acceptance rate (target: >90%)
- False positive rate (target: <5%)

### Integrations
- Ticket sync success rate (target: >99%)
- Sync latency p95 (target: <30s)
- Drift detection accuracy (target: >95%)

### Remediation
- MTTR by severity (target: Critical <24h, High <7d)
- SLA compliance rate (target: >95%)
- Verification rate (target: >80%)

### Bulk Operations
- Job completion rate (target: >99%)
- Per-item success rate (target: >98%)
- Job latency p95 (target: <5min for 1000 items)

### Collaboration
- Comment response time (target: <4h)
- Evidence promotion rate (target: >20% of decision rationales)
- Watcher engagement (target: >50% of assigned users)
