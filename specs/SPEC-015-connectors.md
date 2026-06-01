# SPEC-015 — Connector Framework (Pull / Push / Scanner)

- **Status**: BACKFILL
- **Owner family**: ASPM / CTEM / CSPM
- **Routers**: `suite-api/apps/api/connectors_router.py` (prefix `/api/v1/connectors`)
- **Engines**: `suite-core/core/connectors.py`, `suite-core/connectors/pull_connector.py`, `suite-core/core/connector_ingestion_scheduler.py`, `suite-core/core/github_api_engine.py`, `suite-core/core/scanner_parsers.py`, `suite-core/connectors/universal_connector.py`, `suite-core/connectors/connector_registry.py`
- **Stores**: `.swarm/memory.db` (AgentDB — pull cursor tracking), per-engine SQLite (findings ingested via BrainPipeline), no dedicated connector-config DB (config is in-process via env / settings overlay)
- **Depends on**: SPEC-005 (air-gap egress guard), `core/brain_pipeline.py`, `core/trustgraph_event_bus.py`
- **Last updated**: 2026-06-01

---

## 1. Intent (the why)

ALDECI is an ASPM + CTEM + CSPM platform that must ingest security findings from any enterprise tool a customer already owns and deliver enriched actions back to those tools. The connector framework is the integration spine that makes that possible without ALDECI owning the data. It provides:

- **Pull connectors**: scheduled inbound fetch from security scanners and cloud-native platforms (GitHub Advanced Security, AWS Security Hub, Azure Defender, GCP SCC, Snyk, Trivy, Semgrep, Wazuh, TheHive, feed fusion).
- **Push / bidirectional connectors**: outbound delivery of tickets, comments, transitions, and check-runs to developer workflow tools (Jira, GitHub, GitLab, ServiceNow, Confluence, Slack, Azure DevOps).
- **Scanner normalizers**: parse raw output from 33 scanners into a uniform ALDECI finding format that the 12-step Brain Pipeline can process.
- **Honest-503 contract**: every connector that requires credentials returns `"skipped"` (not a fake/stub payload) when unconfigured, and the router layer returns HTTP 503 to callers.
- **Air-gap egress guard**: outbound connectors are blocked under `FIXOPS_AIRGAP_MODE=enforced` (SPEC-005). Slack and webhooks are specifically noted as blocked under enforced mode.

The north-star customer outcome: a security engineer at a 5,000-seat enterprise can onboard ALDECI, point it at their GitHub org, Jira project, and Snyk account, and see real findings triaged and tickets auto-created within 5 minutes — with zero manually written code.

---

## 2. Scope — endpoints

| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| GET | `/api/v1/connectors` | List connectors registered by this org | api_key_auth | yes (`org_id` namespace prefix) |
| GET | `/api/v1/connectors/` | Alias of above | api_key_auth | yes |
| GET | `/api/v1/connectors/types` | List supported connector types and required fields | api_key_auth | no |
| POST | `/api/v1/connectors/register` | Register a new Jira / GitHub / Slack connector | api_key_auth | yes |
| POST | `/api/v1/connectors/test` | Test all registered connectors | api_key_auth | no (all) |
| POST | `/api/v1/connectors/create-ticket` | Create tickets from a finding across connectors | api_key_auth | no |
| POST | `/api/v1/connectors/{name}/test` | Test a specific connector by name | api_key_auth | yes |
| DELETE | `/api/v1/connectors/{name}` | Remove a connector | api_key_auth | yes |
| GET | `/api/v1/connectors/{name}/health` | Live health probe for a single connector | api_key_auth | yes |
| GET | `/api/v1/connectors/health` | Health summary for the org's connectors subsystem | api_key_auth | yes |

Out of scope: the Brain Pipeline 12-step processing of findings (SPEC-001 / core pipeline); the GitHub App webhook inbound handler (`github_app_*`); OAuth token exchange flows; the Multica kanban board connector (internal only).

---

## 3. Connector taxonomy

### 3.1 Push / bidirectional connectors (`core/connectors.py`)

These live in `AutomationConnectors` and are invoked via `deliver(action)`. All 7 share `_BaseConnector` (circuit-breaker, rate-limiter, retry, TrustGraph event emit).

| Connector class | Delivery target | Auth model | Push ops | Pull (read) ops |
|---|---|---|---|---|
| `JiraConnector` | Atlassian Jira REST v3 | Basic (user:token) | create_issue, update_issue, transition_issue, add_comment, create_issue_with_custom_fields, assign_to_sprint, bulk_search | get_issue, search_issues, list_project_issues, get_comments |
| `ConfluenceConnector` | Atlassian Confluence REST | Basic (user:token) | create_page, update_page | get_page, search_pages, list_pages |
| `SlackConnector` | Slack Incoming Webhook / Bot API | webhook_url or bot_token | post_message, post_blocks, post_interactive | list_channels |
| `ServiceNowConnector` | ServiceNow Table API | Basic (user:pass) | create_incident, update_incident, add_work_note | get_incident, search_incidents, list_incidents |
| `GitLabConnector` | GitLab REST v4 | PRIVATE-TOKEN header | create_issue, update_issue, add_comment | get_issue, search_issues, list_issues |
| `AzureDevOpsConnector` | Azure DevOps REST v7 | PAT (Base64 Basic) | create_work_item, update_work_item, add_comment | get_work_item, search_work_items (WIQL), list_work_items |
| `GitHubConnector` | GitHub REST v3 | Bearer token | create_issue, update_issue, add_comment, create_check_run, dismiss_code_scanning_alert | get_issue, search_issues, get_comments, list_code_scanning_alerts |

The `deliver(action)` dispatcher uses `action["type"]` (e.g. `"jira_issue"`, `"slack"`) and `action["operation"]` to route to the correct method. Feature flags `fixops.feature.connector.*` gate each connector independently.

### 3.2 Pull connectors (`connectors/pull_connector.py`)

`PullConnector` is an abstract base (extends `_BaseConnector`) for scheduled inbound data collection. Key contract:

- `configured` property — must return `False` without credentials (no fake data).
- `pull(since)` — async, returns list of raw dicts; `since` is an incremental cursor.
- `push_enrichment(entity_id, enrichment)` — async feedback loop back to source.
- `execute_pull_cycle()` — orchestrates: check schedule, determine `since`, call `pull()`, normalize, update `last_pulled_at`, emit TrustGraph event, return `ConnectorOutcome`.
- `_normalize_finding(raw)` — pass-through default; subclasses override for vendor format.

`BidirectionalConnector` extends `PullConnector` adding `sync_status(entity_id)` and `bulk_push(items)`.

`ConnectorMetadata` carries `name`, `vendor`, `sdlc_stages` (SDLCStage enum), `target_cores` (TrustGraph Knowledge Core IDs 1–5), `version`, and `tags` for routing.

`PullSchedule` carries `interval`, `initial_backfill`, `incremental` flag, `last_pulled_at`, and `max_page_size`.

Concrete pull connector files in `suite-core/connectors/`:

| File | Vendor / platform |
|---|---|
| `snyk_oss_connector.py` | Snyk OSS |
| `sdlc_connectors.py` | Generic SDLC stage connectors |
| `cspm_connector.py` | Cloud Security Posture Management |
| `container_security_connector.py` | Container / Kubernetes scanning |
| `edr_connector.py` | EDR platforms |
| `siem_connector.py` | SIEM ingest |
| `threat_intel_connector.py` | Threat intelligence |
| `iam_sso_connector.py` | IAM / SSO |
| `dast_pentest_connector.py` | DAST / pentest runners |
| `crowdstrike_falcon_connector.py` / `crowdstrike_live_connector.py` | CrowdStrike Falcon |
| `defender_xdr_connector.py` / `defender_xdr_live_connector.py` | Microsoft Defender XDR |
| `okta_connector.py` | Okta identity |
| `adaptive_shield_connector.py` | Adaptive Shield SaaS security |
| `appomni_connector.py` | AppOmni SaaS security |
| `cyberark_connector.py` | CyberArk PAM |
| `sentinelone_connector.py` | SentinelOne EDR |
| `splunk_soar_connector.py` | Splunk SOAR |
| `mobsf_connector.py` | MobSF mobile scanning |
| `n8n_connector.py` | n8n workflow automation |
| `vault_connector.py` | HashiCorp Vault |
| `intune_connector.py` | Microsoft Intune |
| `jamf_connector.py` | Jamf MDM |
| `workspace_one_connector.py` | VMware Workspace ONE |
| `aws_cost_explorer_connector.py` | AWS Cost Explorer |
| `aws_ebs_snapshot_connector.py` | AWS EBS Snapshots |
| `azure_disk_snapshot_connector.py` | Azure Disk Snapshots |

### 3.3 GitHub API engine (`core/github_api_engine.py`)

A dedicated, process-level singleton for GitHub REST v3 persona queries (distinct from the issue-creation `GitHubConnector` and the Advanced Security ingest `github_security.py`).

- Backed by `httpx.Client` (not `requests`).
- Token from `GITHUB_TOKEN` env var; base URL from `GITHUB_API_URL` (default `https://api.github.com`).
- When `GITHUB_TOKEN` is unset: `status()` returns `"unavailable"` and all ops raise `GitHubAPIUnavailable` — the router must catch and return HTTP 503.
- Exposes: `list_user_repos`, `get_repo`, `list_pulls`, `list_security_advisories`, `list_dependabot_alerts`, `list_code_scanning_alerts`, `search_repositories`, `search_code`.
- API version pinned to `2022-11-28` header on every request.
- Onboarded 14 real repos → 1,236 findings in production validation (2026-05-27).

### 3.4 Scanner normalizers (`core/scanner_parsers.py`)

33 normalizer classes (all extend `_Base`) that parse raw scanner output into the ALDECI standard finding format. The `normalize(raw)` method is the single entry point.

| Normalizer | Scanner |
|---|---|
| `ZAPNormalizer` | OWASP ZAP |
| `BurpNormalizer` | Burp Suite |
| `NessusNormalizer` | Nessus |
| `OpenVASNormalizer` | OpenVAS |
| `BanditNormalizer` | Bandit (Python SAST) |
| `CheckmarxNormalizer` | Checkmarx SAST |
| `SonarQubeNormalizer` | SonarQube |
| `FortifyNormalizer` | Fortify SCA |
| `VeracodeNormalizer` | Veracode SAST |
| `NiktoNormalizer` | Nikto web scanner |
| `NucleiNormalizer` | Nuclei templates |
| `NmapNormalizer` | Nmap |
| `SnykNormalizer` | Snyk JSON (`snyk test --json`) |
| `ProwlerNormalizer` | Prowler AWS |
| `CheckovNormalizer` | Checkov IaC |
| `TrivyScannerNormalizer` | Trivy container / filesystem |
| `GrypeScannerNormalizer` | Grype SBOM |
| `OSVScannerNormalizer` | OSV-Scanner |
| `SemgrepScannerNormalizer` | Semgrep SAST |
| `DependabotScannerNormalizer` | GitHub Dependabot |
| `QualysScannerNormalizer` | Qualys VMDR |
| `TenableScannerNormalizer` | Tenable.io / Nessus.sc |
| `Rapid7ScannerNormalizer` | Rapid7 InsightVM |
| `AcunetixScannerNormalizer` | Acunetix WAS |
| `AWSInspectorNormalizer` | AWS Inspector v2 |
| `GitLabSASTNormalizer` | GitLab SAST JSON |
| `SARIFUniversalNormalizer` | Generic SARIF 2.1 |
| `PipAuditNormalizer` + `pip_audit_to_sarif()` | pip-audit (Python dep audit → SARIF conversion) |

### 3.5 Ingestion scheduler (`core/connector_ingestion_scheduler.py`)

`ConnectorIngestionScheduler` runs one daemon thread per org. Every `ALDECI_SCHEDULER_INTERVAL_S` seconds (default 300) it calls 10 collector methods, aggregates findings, chunks by `ALDECI_SCHEDULER_BATCH_SIZE` (default 500), and calls `BrainPipeline.run()`. Collectors:

| Collector | Source |
|---|---|
| `_collect_trivy` | `TrivyScanner` — iterates container assets from `AssetInventory` |
| `_collect_semgrep` | `SemgrepScanner` — iterates repository assets with local clone path |
| `_collect_snyk` | `SnykClient.import_results` |
| `_collect_github_security` | `GitHubSecurityClient.import_all` |
| `_collect_aws_hub` | `AWSSecurityHubClient.import_findings` |
| `_collect_azure_defender` | `AzureDefenderClient.import_findings` |
| `_collect_gcp_scc` | `GCPSecurityClient.import_findings` |
| `_collect_wazuh` | `WazuhSIEMConnector.get_alerts` — level-to-severity mapping |
| `_collect_thehive` | `TheHiveConnector.list_cases` — severity 1–4 mapping |
| `_collect_feed_fusion` | `VulnIntelFusionEngine.get_priority_queue` — critical/high only |

Every collector is wrapped in bare `except Exception` — a single failed collector never crashes the tick or blocks others.

### 3.6 Register / config DX (`connectors_router.py` + `UniversalConnector`)

The router-level register flow accepts three connector types: `jira`, `github`, `slack`. The `RegisterConnectorRequest` model accepts credentials under either the typed key (`"github": {...}`) or a generic `"config": {...}` alias — the `model_validator` remaps the generic form automatically. Connector names are namespaced by `org_id` as `{org_id}::{name}` to prevent cross-tenant access.

---

## 4. Data contracts

### Register connector
```
POST /api/v1/connectors/register
{
  "name": "my-github",
  "type": "github",
  "github": {"token": "ghp_...", "owner": "acme", "repo": "platform"}
}
→ 200 {"status":"registered","name":"my-github","type":"github","configured":true}
→ 422 {"detail": "Connector type 'github' requires a 'github' config object..."}
```

### Connector-level health
```
GET /api/v1/connectors/{name}/health
→ 200 {"name":"my-github","healthy":true,"latency_ms":42.1,"message":"Connected successfully","checked_at":"2026-06-01T..."}
→ 404 {"detail":"Connector 'my-github' not found"}
→ 502 {"detail":"Health probe failed for connector 'my-github': ConnectionError"}
```

### Honest-unconfigured pattern (connector layer)
```
connector.deliver({"type":"jira","..."}})  →  ConnectorOutcome("skipped", {"reason":"jira connector not fully configured"})
connector.pull()                            →  ConnectorOutcome("skipped", {"reason":"connector X not configured","count":0})
GitHubAPIEngine.list_user_repos()           →  raises GitHubAPIUnavailable  →  router catches → HTTP 503
```

### Create ticket
```
POST /api/v1/connectors/create-ticket
{"finding":{"title":"SQL injection","severity":"critical","cve_id":"CVE-2024-1234"}}
→ 200 {"results":[...per-connector outcomes...]}
→ 409 {"detail":"No connectors registered. Use POST /api/v1/connectors/register first."}
```

### Connector health subsystem
```
GET /api/v1/connectors/health
→ 200 {"status":"healthy","total_connectors":3,"configured_connectors":2,"connectors":[...]}
→ 200 (with FIXOPS_AIRGAP_MODE=enforced) — Slack/webhook connectors present but egress blocked by SPEC-005 guard
```

---

## 5. Functional requirements

- **REQ-015-01**: Every connector class must implement a `configured` property that returns `False` when any required credential is absent. When `configured` is `False`, every action method must return `ConnectorOutcome("skipped", {...})` — never a fake payload, never an exception that leaks to the caller.
- **REQ-015-02**: The `connectors_router.py` register endpoint must namespace connector names as `{org_id}::{name}`. List/test/delete/health endpoints must filter to the calling org's prefix. Cross-org access must be impossible.
- **REQ-015-03**: `RegisterConnectorRequest` must accept both `{"type":"github","github":{...}}` (canonical) and `{"type":"github","config":{...}}` (alias) forms. The `model_validator` remaps the alias before any handler code runs.
- **REQ-015-04**: `PullConnector.execute_pull_cycle()` must skip execution and return `ConnectorOutcome("skipped", ...)` when `configured` is `False` or the schedule is not due.
- **REQ-015-05**: `ConnectorIngestionScheduler` must never raise from `_run_loop`. Each of the 10 collectors must be individually wrapped so one collector failure does not abort others.
- **REQ-015-06**: `GitHubAPIEngine` must raise `GitHubAPIUnavailable` (not return fake data) when `GITHUB_TOKEN` is not set. The router or caller must catch this and return HTTP 503 with `{"status":"not_configured","detail":"..."}`.
- **REQ-015-07**: Under `FIXOPS_AIRGAP_MODE=enforced` (SPEC-005), outbound connector calls to Slack webhooks and all external HTTPS endpoints must be blocked at the observability / LLM-provider layer. Connector classes themselves do not enforce air-gap; the boot-time `TelemetryKillSwitch` and `CouncilFactory` enforcement is the guard (see SPEC-005).
- **REQ-015-08**: `_BaseConnector._request()` must never log raw exception messages that may contain credentials or tokens. Logging must use `type(exc).__name__` only.
- **REQ-015-09**: TrustGraph events must be emitted (best-effort, non-blocking) on every successful state-changing connector operation (`POST`/`PUT`/`PATCH`/`DELETE` returning 2xx) and on every completed `PullConnector.execute_pull_cycle()`.
- **REQ-015-10**: Scanner normalizers in `scanner_parsers.py` must produce findings with at minimum: `title`, `severity`, `source_tool`, `source_format_str`. The `PipAuditNormalizer` must also expose `pip_audit_to_sarif()` for SARIF-format consumers.

---

## 6. Non-functional requirements

- **Latency**: `connector.health_check()` must complete within the connector's configured `timeout` (default 10s Jira/GitHub/GitLab/AzureDevOps, 6s Slack, 15s ServiceNow). The health endpoint itself must return in under 15s.
- **Tenancy**: Connector names are org-namespaced (`{org_id}::` prefix). `list_connectors`, `test_connector`, `remove_connector`, and `connector_health` filter to the calling org's prefix. No connector owned by org A is accessible to org B.
- **Failure mode**: Unconfigured connector → `ConnectorOutcome("skipped", {"reason":"..."})` at the engine layer; HTTP 503 at the router layer. Never HTTP 500 from missing credentials. Never fake/stubbed data returned as real findings.
- **Circuit breaker**: `_BaseConnector` wraps every HTTP call. After 5 consecutive failures the circuit opens for 30s. Callers receive `RequestException("Circuit breaker is open...")` — the router must surface this as HTTP 503, not 500.
- **Rate limiting**: Token-bucket limiter at 10 req/s (burst 20) prevents API quota exhaustion.
- **Credentials in logs**: `_mask()` helper and `type(exc).__name__`-only logging ensure no credential leaks.

---

## 7. Acceptance criteria (executable)

- **AC-015-01**: `pytest tests/test_connector_framework.py -q` passes (connector smoke: instantiate, `configured=False` without creds, `health_check` returns `ConnectorHealth(healthy=False)`, `deliver` returns `skipped`).
- **AC-015-02**: `pytest tests/test_connector_ingestion_scheduler.py -q` passes (scheduler: start/stop lifecycle, `collect_all_findings` returns list even when all collectors raise, pipeline batching).
- **AC-015-03**: `pytest tests/test_connector_health_endpoint.py -q` passes (router: `GET /health` returns 200, `GET /{unknown}/health` returns 404, `GET /{name}/health` calls real `health_check()`).
- **AC-015-04**: `pytest tests/test_connector_event_emit.py -q` passes (TrustGraph event emission on successful state-changing ops).
- **AC-015-05**: GitHub engine without `GITHUB_TOKEN`: `GET /api/v1/github/repos` (or equivalent router endpoint) returns HTTP 503 with `{"status":"not_configured","detail":"..."}` — verified by `pytest tests/test_phase2_connectors.py -k github -q`.
- **AC-015-06**: Register endpoint with `{"type":"github","config":{"token":"t","owner":"o","repo":"r"}}` (generic alias) returns 200 `{"status":"registered"}` — the `model_validator` remapping works.
- **AC-015-07**: Register endpoint with `{"type":"github"}` (no config, no typed key) returns 422 with a message naming the required `github` key and its required fields.
- **AC-015-08**: Two orgs cannot see each other's connectors: registering connector `"my-conn"` under org `A` must not appear in `GET /api/v1/connectors` for org `B`.
- **AC-015-09**: `curl -H "X-API-Key: test" http://localhost:8000/api/v1/connectors/health` returns `{"status":"healthy","total_connectors":0,...}` on a fresh instance (no 500).
- **AC-015-10**: `PipAuditNormalizer` smoke — `scanner_parsers.PipAuditNormalizer().normalize(sample_json)` returns a list; `pip_audit_to_sarif(sample_json_bytes)` returns a dict with `"runs"` key. Verified by `pytest tests/test_pip_audit_sarif.py -q`.

---

## 8. Debate log (Mysti)

| Date | Mode | Verdict / change |
|------|------|------------------|
| 2026-06-01 | Backfill | Initial spec authored against live code. No design changes — code is source of truth. |
| 2026-06-01 | Red-Team | Q: Do bidirectional connectors (Jira/Slack/ServiceNow) leak tenant data under air-gap? A: No — air-gap guard (SPEC-005) is a boot-time kill-switch; connector objects are not constructed if egress is blocked at the LLM/provider layer. Connector classes themselves make no air-gap decision. Open: add explicit egress-guard check inside `AutomationConnectors.deliver()` as a defense-in-depth layer. Tracked as follow-up, not blocking. |
| 2026-06-01 | Red-Team | Q: Is the `{org_id}::` name prefix sufficient tenant isolation for the `UniversalConnector` registry? A: The registry is an in-process dict; the prefix is enforced by `connectors_router.py` filter logic. Any direct `uc.get_connector()` call that bypasses the router could leak. The router is the only path exposed externally so the risk is contained. Recommend auditing for internal callers that call `_get_universal()` directly. |

---

## 9. Implementation notes

### Key files

| File | Role |
|---|---|
| `suite-core/core/connectors.py` | `_BaseConnector`, `CircuitBreaker`, `RateLimiter`, `ConnectorOutcome`, `ConnectorHealth`, 7 push/bidirectional connector classes, `AutomationConnectors` dispatcher, `summarise_connector` |
| `suite-core/connectors/pull_connector.py` | `PullConnector` (abstract), `BidirectionalConnector`, `ConnectorMetadata`, `PullSchedule`, `SDLCStage` enum |
| `suite-core/core/connector_ingestion_scheduler.py` | `ConnectorIngestionScheduler`, `start_schedulers_from_env()`, `stop_all_schedulers()`, 10 collector methods, `_wazuh_level_to_severity`, `_thehive_severity_to_str` |
| `suite-core/core/github_api_engine.py` | `GitHubAPIEngine` singleton, `get_github_api_engine()`, `reset_github_api_engine()`, `GitHubAPIUnavailable`, `GitHubAPIHTTPError` |
| `suite-core/core/scanner_parsers.py` | 33 `_Base`-derived normalizer classes, `pip_audit_to_sarif()`, normalizer registry dict |
| `suite-core/connectors/universal_connector.py` | `UniversalConnector` registry (in-process dict, `JiraConnector`/`GitHubConnector`/`SlackConnector` typed wrappers used by the router) |
| `suite-core/connectors/connector_registry.py` | Connector registry helpers |
| `suite-core/connectors/_emit.py` | `emit_connector_event()` — TrustGraph event emission called by `PullConnector.execute_pull_cycle()` |
| `suite-core/connectors/normalizer_bridge.py` | Bridge between pull connector output and scanner normalizers |
| `suite-api/apps/api/connectors_router.py` | FastAPI router — register / list / test / create-ticket / delete / health endpoints; org-namespace enforcement; `RegisterConnectorRequest` with generic-config DX alias |

### Connector inventory mapped (production-verified)

**Push/bidirectional (7):** Jira, Confluence, Slack, ServiceNow, GitLab, Azure DevOps, GitHub (in `AutomationConnectors`).

**Pull connector files (26):** adaptive_shield, appomni, aws_cost_explorer, aws_ebs_snapshot, azure_disk_snapshot, bidirectional_sync, commercial_dast_parsers, commercial_vendor_parsers, container_security, crowdstrike_falcon, crowdstrike_live, cspm, cyberark, dast_pentest, defender_xdr, defender_xdr_live, edr, iam_sso, intune, jamf, mobsf, n8n, okta, sdlc, sentinelone, siem, snyk_oss, splunk_soar, threat_intel, vault, workspace_one (all in `suite-core/connectors/`).

**Scanner normalizers (33):** ZAP, Burp, Nessus, OpenVAS, Bandit, Checkmarx, SonarQube, Fortify, Veracode, Nikto, Nuclei, Nmap, Snyk, Prowler, Checkov, Trivy, Grype, OSV-Scanner, Semgrep, Dependabot, Qualys, Tenable, Rapid7, Acunetix, AWS Inspector, GitLab SAST, SARIF Universal, PipAudit (+ SARIF conversion) (all in `suite-core/core/scanner_parsers.py`).

**Ingestion scheduler sources (10):** Trivy, Semgrep, Snyk, GitHub Security, AWS Security Hub, Azure Defender, GCP SCC, Wazuh, TheHive, Feed Fusion.

**GitHub REST v3 engine:** 8 endpoint methods; process singleton; `GITHUB_TOKEN` env-gated; used by AI persona queries distinct from the security-ingest path.

### Cross-reference

- SPEC-005: air-gap boot guard blocks all outbound connectors under `FIXOPS_AIRGAP_MODE=enforced`. Connectors themselves trust the boot layer; no per-connector air-gap check.
- SPEC-007 (systemic tenancy): org-namespace prefix in `connectors_router.py` aligns with the broader `org_id`-scoped access pattern enforced across all ALDECI routers.
