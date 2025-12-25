# FixOps – Final Feature Design

## 1. Current State Summary
The existing FixOps codebase is a modular, stateless "Decision Engine" pipeline. It excels at normalizing inputs from various sources (GitHub, Jenkins, SonarQube) into a canonical format, evaluating them against policies, and producing a decision verdict.

-   **Strengths:**
    -   **Strong Canonicalization:** `core/sarif_canon.py` provides a solid foundation for normalizing SARIF inputs.
    -   **Adapter Pattern:** `integrations/` implementations (GitHub, Jenkins, SonarQube) consistently map external payloads to internal structures.
    -   **Design Linking:** `services/match/` contains rudimentary logic (`build_crosswalk`) to link design-time elements with SBOM components.
    -   **Risk Scoring:** `cli/fixops_risk.py` has a clean implementation of risk calculation based on SBOM, EPSS, and KEV.

-   **Gaps:**
    -   **Statelessness:** The system currently processes single events/artifacts in isolation. There is no "memory" of previous scans, making tracking "New" vs. "Fixed" findings impossible.
    -   **Brittle Identification:** Deduplication relies largely on `rule_id` and simple location data, which is prone to drift (e.g., changing line numbers).
    -   **Unidirectional Integrations:** Integrations are primarily "Inbound" (Webhooks/Ingest). There is no "Outbound" capability to sync findings to issue trackers (Jira) or chat ops (Slack).

## 2. Feature 1: Deduplication & Correlation Engine

### 2.1 Problem Statement
Currently, every scan is treated as a new event. If a vulnerability exists in `main.py` on Monday and Tuesday, FixOps treats them as isolated data points. This leads to "alert fatigue" and prevents tracking remediation metrics (Mean Time to Remediation). Furthermore, scanner findings (SAST) are not effectively correlated with Design inputs or Runtime alerts.

### 2.2 Design Goals
-   **Stable Identity:** Generate deterministic IDs for findings that persist despite minor code edits (line shifts).
-   **Temporal Tracking:** Distinguish between `NEW`, `EXISTING`, and `FIXED` findings by comparing against a baseline.
-   **Cross-Source Correlation:** Merge findings from different tools (e.g., Snyk and Trivy reporting the same CVE) into a single logical issue.

### 2.3 Canonical Finding/Event Model
We will extend the dictionary produced by `core/sarif_canon.py` to include:

-   `synthetic_id` (UUID): A deterministic hash of `rule_id` + `file_path` + `fingerprint`.
-   `fingerprint` (String): A context-aware hash (e.g., hash of the 3 lines of code surrounding the finding), robust against line insertions/deletions.
-   `correlation_ids` (List[String]): External IDs (CVE-2023-1234, GHSA-xxxx) to allow merging across tools.
-   `first_seen` (ISO8601): Timestamp of initial discovery.
-   `status` (Enum): `OPEN`, `FIXED`, `SUPPRESSED`.

### 2.4 Deduplication Strategy
1.  **Intra-Scan Dedup:** (Already partially exists) Remove identical duplicates within a single report.
2.  **Baseline Dedup:**
    -   Input: `current_report.json` and `baseline_report.json`.
    -   Logic:
        -   If `synthetic_id` exists in Baseline -> Mark as `EXISTING`.
        -   If `synthetic_id` NOT in Baseline -> Mark as `NEW`.
        -   If `synthetic_id` in Baseline but NOT in Current -> Mark as `FIXED`.
3.  **Fuzzy Dedup:** Use `fingerprint` to re-associate findings if file paths match but line numbers have shifted significantly.

### 2.5 Correlation Strategy
Leverage and expand `services/match`:
-   **Design-to-Code:** Correlate `Design Components` (from inputs) to `SBOM Components` (from build) using `purl` (Package URL) or normalized naming.
-   **Finding-to-Component:** Link SAST/SCA findings to the specific component they affect.
-   **Multi-Scanner Merging:** Group findings by `cve_id` or `cwe_id` + `location`.

### 2.6 API Enhancements
**Existing API Modifications:**
-   `POST /api/evidence`: Accept an optional `baseline_id` query param to trigger differential analysis.
-   `POST /api/pentagi`: Update payload model to include `synthetic_id`.

**New Service Logic (No new HTTP endpoints required yet):**
-   `core/dedup.py`: Logic for hashing and comparison.
-   `core/correlator.py`: Logic for graph-based linking.

### 2.7 CLI Changes
Update `cli/scanner.py` or `cli/main.py`:
-   `fixops correlate --target <current_sarif> --baseline <prev_sarif> --out <diff_report.json>`
-   `fixops fingerprint --target <sarif_file>`: Utility to inject fingerprints into a standard SARIF file.

### 2.8 YAML Overlay Changes
No significant schema changes required. Configuration for "Exclusion Rules" (false positives) should be added to `policy.yml`:

```yaml
deduplication:
  ignore_paths: ["**/test/**", "**/vendor/**"]
  fingerprint_method: "context_hash" # or "strict_line"
```

### 2.9 Risks & Mitigations
-   **Risk:** Context hashing is expensive on large codebases.
    -   *Mitigation:* Only compute context hashes for critical/high severity findings initially.
-   **Risk:** "Flapping" findings (toggle between New/Fixed) due to non-deterministic tool output.
    -   *Mitigation:* Implementing a "grace period" or "pending" state before declaring something Fixed.

## 3. Feature 2: Integrations

### 3.1 Integration Inventory
| Integration | Type | Status | Assessment |
| :--- | :--- | :--- | :--- |
| **GitHub** | CI Adapter | **Partial** | Handles Webhooks & PR comments. Lacks Issue sync. |
| **Jenkins** | CI Adapter | **Partial** | Handles Ingest. Lacks pipeline feedback step (blocking). |
| **SonarQube** | Ingest | **Partial** | Normalizes issues. Lacks bi-directional sync. |

### 3.2 Missing Critical Integrations
To move from a "Decision Engine" to a "FixOps Platform", we need:
1.  **Issue Tracker (Jira/GitHub Issues):** Automate ticket creation for `HIGH` severity `NEW` findings.
2.  **Notification (Slack/Teams):** Alert teams on `CRITICAL` findings or failed policies.
3.  **Container Registry (ECR/DockerHub):** Native ingestion of container scan results.

### 3.3 Design for Completion
**Abstract Action Provider:**
Define a new interface in `core/interfaces.py` (or similar) for Outbound actions.

```python
class ActionProvider:
    def create_ticket(self, finding: CanonicalFinding) -> str: ...
    def update_ticket(self, ticket_id: str, status: str) -> bool: ...
```

**Jira Integration:**
-   **Config:** Add `jira_url`, `project_key`, `auth_token` to `config/oss_tools.yml` or secrets.
-   **Logic:**
    -   On `decision_outcome == REJECT`: Create Ticket.
    -   Include `synthetic_id` in ticket metadata to prevent duplicates.

### 3.4 API / CLI / YAML Implications
-   **CLI:** `fixops sync --provider jira` command to batch process findings and update tickets.
-   **YAML:** Add `actions` section to `policy.yml` to define *when* to trigger integrations.

### 3.5 Risks & Mitigations
-   **Risk:** Creating 1000 tickets for 1000 findings (Ticket Storm).
    -   *Mitigation:* Implement "Grouping" (1 Ticket per Component or per Scan) by default.
-   **Risk:** Auth management for external tools.
    -   *Mitigation:* Use existing `secrets_db.py` pattern or environment variable injection strictly.

## 4. Non-Goals
-   **Real-time Code Scanning:** FixOps is a post-process / admission controller, not an IDE plugin scanner.
-   **Custom Rule Engine:** We will not write a new grep-based scanner; we rely on external tools (Semgrep, Trivy, etc.).
-   **Complex UI:** The design focuses on API/CLI/Backend; the existing React frontend will consume the new data models but is not the primary design target here.

## 5. Implementation Readiness Checklist
-   [ ] **Dependency:** Identify a library for robust source code context hashing (or write simple sliding window hash).
-   [ ] **Data:** Define the `CanonicalFinding` Pydantic model fully.
-   [ ] **Test:** Create a "Golden Dataset" of SARIF files with slight variations (line shifts) to test deduplication logic.
-   [ ] **Env:** Provision a mock Jira/Slack instance for integration testing.
