# NotImplementedError + Honest-Stub Triage — 2026-06-01

**Method:** Code-truth grep of `raise NotImplementedError` across suite-core + suite-api, followed by router-mount tracing to confirm customer HTTP reachability.  
**Global handler:** `app.py:2607` — `NotImplementedError` → HTTP 501. The gate exists; what follows classifies whether landing there is acceptable or a product gap.

**ADVERTISED-BUT-501 count: 6 items** (items a customer on a paid plan can hit when using features named in the UI, pricing, or docs as working).

---

## Section 1 — ADVERTISED-BUT-501 (Critical Gaps)

These are endpoints reachable by authenticated customers that return HTTP 501 on advertised feature paths. Sorted by customer-impact severity.

---

### 1. OpenClaw Pentest — Start Campaign & Advance Phase

| Field | Value |
|---|---|
| Feature | Automated Penetration Testing (MPTE — 19-phase campaign execution) |
| Endpoint | `POST /api/v1/openclaw/campaigns/{id}/start` and `POST /api/v1/openclaw/campaigns/{id}/advance` |
| File:line | `suite-core/core/openclaw_engine.py:603`, `610`, `623`, `628` |
| Router | `suite-api/apps/api/openclaw_router.py` — mounted in `ctem_app.py:485` |
| Classification | **ADVERTISED-BUT-501** |
| Why critical | The pricing page and UI expose "Penetration Testing" as a Pro/Enterprise feature. Campaign CRUD (create/list/get/pause/complete/findings) all work. But `start` — the action that actually launches the pentest — raises 501 unconditionally unless `PENTEST_CONNECTOR_URL` is set. `advance_phase` is the same. A paying customer creates a campaign and clicks Start and gets a 501. |
| What makes it real | Needs either (a) `PENTEST_CONNECTOR_URL` set to a real pentest executor (Metasploit RPC, Nuclei API, Pentera SaaS, or Cymulate) **and** the connector integration code written in `openclaw_engine.start_campaign()` — the env-var check is present but the connector call below it is also `raise NotImplementedError`; so both the env guard AND the integration logic are missing. This is **our code to write** — not just a customer credential. |
| Effort | Medium — 2-3 days to wire one real executor (Nuclei is OSS, no commercial dependency). |

---

### 2. Cloud Drift Detection — Run Drift Scan

| Field | Value |
|---|---|
| Feature | CSPM Cloud Drift Detection (advertised under CSPM tab, "Cloud Configuration Drift") |
| Endpoint | `POST /api/v1/cspm/drift/scan` (prefix from `cloud_drift_router.py`, mounted in `cspm_app.py:241`) |
| File:line | `suite-core/core/cloud_drift_engine.py:369`, `376` |
| Classification | **ADVERTISED-BUT-501** |
| Why critical | CSPM is a core tier feature. The UI has a Drift tab. `run_drift_scan()` raises 501 unless `CSPM_CONNECTOR_URL` is set. Unlike OpenClaw, the env guard is honest and informative, but the downstream integration code is also `raise NotImplementedError` — so even with the env var set the scan doesn't execute. CRUD (baselines, acknowledge, remediate) works and can receive injected drift events; the scan initiation trigger is the gap. |
| What makes it real | Needs `CSPM_CONNECTOR_URL` **and** integration code to call AWS Config / Azure Policy / GCP Asset Inventory via their SDKs. The engine has no provider SDK calls written yet. This is **our code to write** — boto3/azure-mgmt/google-cloud-asset calls. |
| Effort | High — 3-5 days per cloud provider (3 providers = ~2 weeks for full coverage). Can ship AWS-only first (1 week). |

---

### 3. Semantic Analyzer — TypeScript, Java, Go, and Drizzle Parsing

| Field | Value |
|---|---|
| Feature | Multi-language SAST / Code Intelligence (ASPM tier — "Semantic Code Analysis") |
| Endpoints | `POST /api/v1/semantic/parse-repo` (with `language=typescript\|java\|go`) and `POST /api/v1/semantic/orm-schema` (with `orm_framework=drizzle`) |
| File:line | `suite-core/core/semantic_analyzer_engine.py:611`, `826`, `1065`, `1232` |
| Router | `suite-api/apps/api/semantic_analyzer_router.py:100-101` — correctly catches `NotImplementedError` and re-raises as HTTP 501. Mounted in `aspm_app.py:568` and `app.py:6864`. |
| Classification | **ADVERTISED-BUT-501** |
| Why critical | The `ParseRepoRequest` schema advertises `language: str  # python/typescript/java/go`. Python works fully. If a customer sends any of the other three languages, they receive 501. ASPM is a paid tier; multi-language support is a core competitive claim against Snyk Code and Apiiro. |
| What makes it real | `pip install tree-sitter tree-sitter-typescript tree-sitter-java tree-sitter-go` **and** the parsing logic is already written (the methods are complete past the guard check). This is **a missing pip dependency**, not missing engine code. The 501 fires only when the C extension is absent at runtime. Fixing it is: add the four packages to `requirements.txt`, rebuild the Docker image, done. |
| Effort | Very Low — 1-2 hours (requirements.txt + Docker rebuild). No new code needed. |

---

### 4. Function Reachability — TypeScript and Java Call-Graph Parsing

| Field | Value |
|---|---|
| Feature | Reachability Analysis (ASPM — "Is this CVE reachable?") |
| Endpoints | `POST /api/v1/reachability/parse` with `language=typescript` or `language=java` |
| File:line | `suite-core/core/function_reachability_engine.py:900`, `1010` |
| Router | `suite-api/apps/api/function_reachability_router.py:97` — correctly catches NotImplementedError → HTTP 501. Mounted in `aspm_app.py:540`. |
| Classification | **ADVERTISED-BUT-501** |
| Why critical | Same root cause as semantic_analyzer above. Python repos work fully. TypeScript and Java repos return 501. Reachability analysis on TypeScript (the dominant language for web-app customers) is a critical ASPM feature. |
| What makes it real | `pip install tree-sitter tree-sitter-typescript tree-sitter-java` — same dependency fix as item 3. The parsing logic in `parse_typescript_repo()` and `parse_java_repo()` is complete past the import guard. |
| Effort | Very Low — same 1-2 hour fix as item 3. Likely same requirements.txt PR. |

---

### 5. CSPM Engine — Stub Monkey-Patch Silently Returns Empty Data

| Field | Value |
|---|---|
| Feature | CSPM Posture, Findings, Resources, Benchmark, Scan, Drift (core CSPM tier) |
| Endpoints | Multiple CSPM router endpoints calling `get_posture`, `list_findings`, `list_resources`, `run_scan`, etc. |
| File:line | `suite-core/core/cspm_engine.py:1727-1866` |
| Classification | **ADVERTISED-BUT-501** (worse than 501 — silent empty data) |
| Why critical | This is actually worse than a 501. The CSPM engine monkey-patches 16 methods at module load time with stub implementations that return empty lists, zero-scores (posture score = 100.0 with 0 findings), and no-op saves. A customer sees a CSPM dashboard showing "Overall Score: 100, 0 Findings" — not a 501, not an error, just silently fabricated data. This is a mock that slipped past the no-mocks gate. `_stub_run_scan()` returns `overall_score=100.0, total_findings=0` unconditionally. |
| What makes it real | The CSPM engine needs real cloud credential checks and actual AWS Config / Azure Policy / GCP Asset Inventory calls wired into these stub methods, or the stubs must be replaced with the `run_drift_scan()` path (which at least raises 501 honestly). At minimum, the stubs should check for cloud credentials and return a 503/empty with a clear `not_configured` message rather than a fake 100-score. |
| Effort | High to make fully real (same as item 2). Low to fix the honesty gap: 1 day to replace `overall_score=100.0` with a `not_configured` response. |

---

### 6. Secrets Manager — Vault Integration Stubs (read/write/dynamic/encrypt)

| Field | Value |
|---|---|
| Feature | HashiCorp Vault Integration (Enterprise tier — secret rotation, dynamic credentials, transit encryption) |
| Endpoints | Methods `vault_read`, `vault_write`, `vault_dynamic_creds`, `vault_transit_encrypt` in `SecretsRotationManager`. The `secrets_manager_router.py` is mounted at `app.py:5954` and `aspm_app.py:651`. |
| File:line | `suite-core/core/secrets_manager.py:1648`, `1661`, `1667`, `1677` |
| Classification | **ADVERTISED-BUT-501** (silent stub — returns fabricated response, not 501) |
| Why critical | `vault_transit_encrypt()` returns `"vault:v1:STUB_ENCRYPTED_{sha256[:16]}"` — a fake ciphertext that looks real. `vault_read()` and `vault_dynamic_creds()` return stub response dicts with `"stub": True` in metadata, which is honest in the object but no HTTP 501 is raised. Any downstream system consuming this as a real Vault response will treat stub ciphertext as valid. |
| What makes it real | `VAULT_ADDR` + `VAULT_TOKEN` env vars + `hvac` Python client (`pip install hvac`). The integration logic needs to be written. **Our code to write** — not just a credential. |
| Effort | Medium — 1-2 days to wire `hvac` calls for the four Vault operations. |

---

## Section 2 — HONEST-OPTIONAL (Acceptable — gated on customer-provided integration)

These raise 501/503 or return a clear `not_configured` message when the customer has not opted into the integration. The gate is honest; no fake data is returned. Action: document the env var in the integration catalog, not in the bug tracker.

| Feature | Engine / File | Env Var(s) Required | Gate Behavior |
|---|---|---|---|
| OpenClaw campaign CRUD | `openclaw_engine.py` (non-start methods) | None — works without any connector | Fully real (SQLite-backed) |
| Cloud Drift CRUD (baselines, acknowledge) | `cloud_drift_engine.py` | None — CRUD works | Fully real |
| Splunk SIEM output | `splunk_siem_engine.py:95` | `SPLUNK_URL`, `SPLUNK_TOKEN` | Honest error dict, no fake data |
| Sumo Logic SIEM | `sumologic_siem_engine.py:113` | `SUMO_ACCESS_ID`, `SUMO_ACCESS_KEY` | Honest error dict |
| AWS WAF | `aws_waf_engine.py:86` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Raises `AwsWafUnavailableError` → 503 |
| Amazon Inspector | `amazon_inspector_engine.py:68` | AWS credentials | Raises exception → 503 |
| GCP Security Command Center | `gcp_scc.py:391` | `GCP_PROJECT_ID`, `GOOGLE_APPLICATION_CREDENTIALS` | Returns empty list with warning log |
| Azure Defender | `azure_defender.py:406` | `AZURE_SUBSCRIPTION_ID`, `AZURE_CLIENT_*` | Returns empty list with warning log |
| Wiz CNAPP | `wiz_cnapp_engine.py:178` | `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET`, `WIZ_API_URL` | Honest error dict |
| Lacework | `lacework_engine.py:108` | `LACEWORK_ACCOUNT`, `LACEWORK_KEY_ID`, `LACEWORK_SECRET` | Honest error dict |
| PagerDuty incidents | `pagerduty_integration.py:355` | `PAGERDUTY_API_TOKEN`, `PAGERDUTY_SERVICE_ID` | Returns `not_configured` shape |
| PagerDuty Events v2 | `pagerduty_events_v2_engine.py:127` | `PAGERDUTY_EVENTS_TOKEN` | Returns not_configured |
| Jira Cloud | `jira_cloud_engine.py:58` | `JIRA_URL`, `JIRA_USER`, `JIRA_TOKEN` | Raises `JiraUnavailableError` → 503 |
| Jira (universal connector) | `universal_connector.py:445` | `JIRA_URL`, `JIRA_USER`, `JIRA_TOKEN`, `JIRA_PROJECT` | Honest error dict |
| GitHub (universal connector) | `universal_connector.py:829` | `GITHUB_TOKEN`, `GITHUB_OWNER`, `GITHUB_REPO` | Honest error dict |
| Slack notifications | `universal_connector.py:1222`, `slack_notifier.py:5` | `SLACK_WEBHOOK_URL` | Returns skipped/not_configured |
| XSOAR | `xsoar_engine.py:107` | `XSOAR_BASE_URL`, `XSOAR_API_KEY` | Raises `XsoarUnavailableError` |
| Qualys | `qualys_engine.py:122` | `QUALYS_USERNAME`, `QUALYS_PASSWORD`, `QUALYS_API_BASE` | Honest error dict |
| Terraform Cloud | `terraform_cloud_engine.py:74` | `TFC_TOKEN` | Raises exception → 503 |
| Harbor Registry | `harbor_registry_engine.py:54` | `HARBOR_URL`, `HARBOR_USERNAME`, `HARBOR_PASSWORD` | Raises `HarborNotConfiguredError` |
| Bitbucket | `bitbucket_engine.py:44` | `BITBUCKET_USER`, `BITBUCKET_APP_PASSWORD` | Raises `BitbucketNotConfiguredError` |
| CircleCI | `circleci_engine.py:47` | `CIRCLECI_TOKEN` | Raises `CircleCINotConfiguredError` |
| MISP Threat Intel | `misp_integration_engine.py:100` | `MISP_URL`, `MISP_AUTH_KEY` | Honest error dict |
| New Relic APM | `newrelic_apm_engine.py:77` | `NEWRELIC_API_KEY` | Raises exception → 503 |
| Drata Compliance | `drata_compliance_engine.py:48` | `DRATA_API_KEY` | Raises `DrataNotConfiguredError` |
| CyberArk PAM | `cyberark_pam_engine.py:54` | `CYBERARK_PVWA_URL`, `CYBERARK_APP_ID`, `CYBERARK_SAFE` | Raises `CyberArkUnavailableError` |
| Keycloak IAM/SSO | `iam_sso_connector.py:684` | `KEYCLOAK_URL`, `KEYCLOAK_ADMIN`, `KEYCLOAK_PASSWORD` | Returns not_configured shape |
| APIcrunch | `apicrunch_engine.py:96` | `APICRUNCH_API_TOKEN` | Honest error dict |
| SDLC GitHub connector | `sdlc_connectors.py:288` | `GITHUB_TOKEN` | Returns `ConnectorOutcome("failed", ...)` |
| SDLC Jira connector | `sdlc_connectors.py:508` | `JIRA_URL`, `JIRA_USER`, `JIRA_TOKEN` | Returns `ConnectorOutcome("failed", ...)` |
| PyRIT AI red-team | `pyrit_engine.py:152` | `PYRIT_RUNNER_URL` | Raises `PyritNotConfiguredError` |
| Vendor Risk threat-intel IP check | `vendor_risk_engine.py:871` | None (stub, hookable) | Returns empty threat intel dict — internal scoring path only, not a dedicated endpoint |
| Secrets rotation trigger | `secrets_manager.py:1443` | Relevant provider credentials | Updates DB status to IN_PROGRESS — workflow is partially real, cloud API call is stubbed |
| Airgap NVD feed stubs | `airgap_deployment.py:626` | Admin scope (`admin:all`) | Only reachable by admin; generates placeholder CVE JSON for offline deployments. Expected behavior. |

---

## Section 3 — INTERNAL / DEV (Not Customer-Reachable — Safe to Ignore)

These raise `NotImplementedError` in abstract base classes or in dev-only infrastructure. No HTTP route calls them directly.

| Item | File:line | Reason |
|---|---|---|
| `SIEMIntegration.send_alert()` (base class) | `suite-api/apps/api/integrations.py:49` | Abstract base — `SplunkIntegration` and `QRadarIntegration` override it. The base is never instantiated directly. |
| `TicketingIntegration.create_ticket()` + `update_ticket()` (base class) | `suite-api/apps/api/integrations.py:135`, `139` | Abstract base — `JiraIntegration` and `ServiceNowIntegration` override. |
| `SCMIntegration.create_pull_request()` + `get_repository_info()` (base class) | `suite-api/apps/api/integrations.py:301`, `305` | Abstract base — `GitHubIntegration` overrides. `integrations.py` is a library module, not mounted as a router. |
| `BaseScannerParser.normalize()` | `suite-core/core/scanner_parsers.py:237` | Abstract base — all concrete parsers (SonarQube, Trivy, Snyk, Bandit, etc.) override. Never called on the base class. |
| `BaseSIEMAdapter.parse()` | `suite-core/connectors/siem_connector.py:129` | Abstract base — `SplunkHECAdapter`, `QRadarAdapter`, etc. override. |
| `_BaseAdapter.configured` + `fetch_findings()` | `suite-core/core/adapters.py:97`, `101` | Abstract base — `GitLabAdapter` and others override. |
| `VectorStore` abstract base | `suite-core/core/vector_store.py:89`, `94` | Abstract base — concrete implementations provide the methods. |
| `VectorStore` (enterprise services) | `suite-core/core/services/enterprise/vector_store.py:33`, `38`, `64` | Same — abstract base. |
| `OPAEngine.evaluate_policy()` + `health_check()` (base class) | `suite-core/core/services/enterprise/real_opa_engine.py:66`, `70` | Abstract base — `LocalOPAEngine` overrides both. `LocalOPAEngine` is the live instance used by routes. |
| `PullConnector.health_check()` | `suite-core/core/connectors.py:342` | Abstract base — all concrete pull connectors override. |
| `_LocalConnector.health_check()` | `suite-core/core/enterprise_sim_services.py:129` | Abstract base for local enterprise simulation connectors (`WazuhSIEMConnector` etc.). Never called on base. |
| `AgentDB bridge abstract` | `suite-core/trustgraph/agentdb_bridge.py:175` | Internal memory bridge base. Not HTTP-exposed. |
| `EnterpriseUtilBase` crypto | `suite-core/core/utils/enterprise/crypto.py:49-75` | Abstract crypto adapter base. Concrete implementations provide real methods. Not HTTP-exposed. |

---

## Summary

| Classification | Count | Action |
|---|---|---|
| **ADVERTISED-BUT-501** | **6** | Fix before next customer demo / GA |
| HONEST-OPTIONAL | 31 | Document env vars in integration catalog |
| INTERNAL/DEV | 13 | No action needed |

### Priority order for ADVERTISED-BUT-501 fixes

1. **Items 3 + 4 (tree-sitter deps)** — fix in 1-2 hours; `pip install tree-sitter tree-sitter-typescript tree-sitter-java tree-sitter-go` in `requirements.txt`. Unblocks multi-language SAST and reachability for TypeScript/Java customers immediately.

2. **Item 5 (CSPM stub monkey-patch)** — 1 day to replace `overall_score=100.0` silent stubs with honest not-configured responses. Stops fabricated 100-score from reaching the dashboard.

3. **Item 6 (Vault stubs)** — 1-2 days to wire `hvac` for the four Vault operations. Prevents fake ciphertext (`STUB_ENCRYPTED_...`) from being treated as real by downstream consumers.

4. **Item 2 (Cloud Drift scan)** — 1 week to wire AWS Config first, then Azure/GCP. The env guard is already honest; this is adding the real provider SDK calls.

5. **Item 1 (OpenClaw Start/Advance)** — 2-3 days to wire Nuclei (OSS) as the default pentest executor. Most visible customer-facing gap; campaign CRUD already works.

---

*Generated by chief-architect triage sweep. Branch: `chore/ui-prune-plan-2026-05-24`. Date: 2026-06-01.*
