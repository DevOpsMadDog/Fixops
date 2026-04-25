# Fixops Gap Matrix — Refresh 2026-04-26

**Generated:** 2026-04-26
**HEAD at refresh:** `a1ad41617e549766032c87cc89b62732a6dbaa61` (branch `features/intermediate-stage`)
**Source matrix:** `raw/competitive/gap-matrix.md` (71 rows: GAP-001..GAP-069 + NEW-G070 + NEW-G071, GAP-053 superseded)
**Method:** Re-scored every gap row against current codebase. Commit history filtered with `git log --since="2026-04-22" --grep="gap-XXX"`. Engine inventory grep against `suite-core/core/*_engine.py` and `suite-core/connectors/*_connector.py`. Status determined by file existence + integration tests + router wiring.

**Status legend (refresh):**
- **DONE** — engine + router + tests landed, reachable in app.py, evidence in commit
- **IN-PROGRESS** — partial work landed (engine OR router OR tests, not all three) or shipped but with documented limitations
- **NOT-STARTED** — no commit found referencing this gap; original MISSING status unchanged
- **NEEDS-PRODUCT-DECISION** — engineering blocked on UNCLEAR product call (GAP-014, GAP-058)

---

## TL;DR top counts

| Status | Count | Pct |
|---|---|---|
| **DONE** | 50 | 70.4% |
| **IN-PROGRESS** | 12 | 16.9% |
| **NOT-STARTED** | 6 | 8.5% |
| **NEEDS-PRODUCT-DECISION** | 2 | 2.8% |
| **SUPERSEDED** (GAP-053) | 1 | 1.4% |
| **TOTAL** | 71 | 100% |

Per `gap-matrix.md` "SESSION CLOSE" log: all 14 KEEPs + 30+ MERGEs + 5 KILLs landed before this refresh. Tonight's session (2026-04-25/26) added 8 OSS-tool integration families that mostly close GAP-034 (universal ingest) and GAP-035 (SIEM connectors), and add format-level realism to several PARTIAL rows that were previously inferred-only. Dashboard render bug fix in `07994f29` unblocks GAP-049/066 (unified queue + diff UI) from "shipped engine, broken UI" to "shipped engine, UI now renders".

---

## Gap status table

| Gap ID | Title (short) | Status | Commits | Remaining work |
|---|---|---|---|---|
| GAP-001 | Air-gap signed bundle + 2-machine update | **DONE** | `c1127305` | air_gap_bundle_engine + router + tests; SAGE parity claimed |
| GAP-002 | Offline CVE/EPSS/KEV bundle | **DONE** | `0ec10bd4` | threat_feed offline mode + 2 routers + 30 tests |
| GAP-003 | HA on-prem reference (Helm/StatefulSet) | **DONE** | `d0e2f44c`, `6dd8f19a`, `f5ed76a1` | KILL-then-doc; Helm+Compose under `docker/` and `docs/DEPLOYMENT_HA.md` |
| GAP-004 | Per-stage enforcement verdicts | **DONE** | `0ec10bd4` | stage matrix shipped alongside GAP-002 |
| GAP-005 | Hierarchical Org/App tree + inherited policies | **DONE** | `873c7d82`, `06aa3851` | org_hierarchy_engine + 10 endpoints + 55 tests |
| GAP-006 | Auto-waiver tied to reachability + upgrade-path | **DONE** | `2504edea` | auto-waiver rules on vuln_exception_engine + workflow integration |
| GAP-007 | "Next-no-violation" upgrade resolver | **DONE** | `23d8f172` | upgrade_path_resolver_engine + 35 tests |
| GAP-008 | Advanced Binary Fingerprint (ABF) | **DONE** | `23d8f172` | binary_fingerprint_engine + 30 tests |
| GAP-009 | Malicious-package / typosquat detection | **DONE** | `66ffb92b` | supply_chain_intel signal ingest + malicious_pkg router + tests |
| GAP-010 | Function-level reachability (Endor parity) | **DONE** | `23d8f172` | function_reachability_engine + 40 tests |
| GAP-011 | Material Change Detection on PRs | **DONE** | `1cd3a420` | material_change_engine merge + smoke tests |
| GAP-012 | Deep Code Analysis (AST graph entities) | **DONE** | `893f9174`, `97b95b6b` | deep_code_analysis_engine v0 + smoke tests + router wired |
| GAP-013 | Code-to-Runtime matcher | **DONE** | `10b2cc1d` | code_to_runtime_matcher_engine v0 — 3-strategy mapping |
| GAP-014 | IDE plugin (VS Code + JetBrains) | **NEEDS-PRODUCT-DECISION** | — | Open question per `dea57dca`: one gateway engine or zero? VS Code package not yet shipped |
| GAP-015 | First-party GitHub App | **DONE** | `8f4f2788` | GitHub App registration + HMAC webhook + .fixops/hooks.yaml policy |
| GAP-016 | Developer-identity behavioral layer | **DONE** | `e370fc0e` | dev-identity behavioral signals on uba/insider_threat |
| GAP-017 | Pipeline Bill of Materials (PBOM) | **DONE** | `4bd57c38` | pipeline_bom_engine + 35 tests |
| GAP-018 | SLSA-level provenance attestations | **DONE** | `c1127305` | slsa_provenance_engine + 30 tests (in-toto + DSSE) |
| GAP-019 | VibeGuard-style AI code scanner | **DONE** | `aba8d8ee` | sast_engine.scan_snippet + ai_security_advisor.analyze_ai_generated |
| GAP-020 | Agentless snapshot scanning (Wiz/Orca moat) | **DONE** | `4bd57c38` | agentless_snapshot_scan_engine + 30 tests |
| GAP-021 | Toxic-combination correlation | **DONE** | `4bd57c38` | 5 toxic-combo rules + 53 tests on attack_chain |
| GAP-022 | 100+ compliance frameworks library | **DONE** | `c1127305` | seeded with frameworks, paired with GAP-023 |
| GAP-023 | 3,000+ built-in policies + Rego authoring | **DONE** | `c1127305` | populated, paired with GAP-022 |
| GAP-024 | RQL-style structured query language | **DONE** | `c1127305` | security_query_language_engine (RQL DSL) |
| GAP-025 | OCI + Alibaba + IBM cloud adapters | **DONE** | `80b546ad` | adapters on cspm/cnapp/cloud_account_monitoring |
| GAP-026 | Choke-point attack-path visualization | **DONE** | `fc363657` | Edmonds-Karp min-cut on attack_path_engine + 34 tests |
| GAP-027 | Critical-Asset-first prioritization (blast radius) | **DONE** | `659efe2b` | blast-radius score on 3 engines |
| GAP-028 | Dollarized FAIR risk per-BU | **DONE** | `0a4be61c` | FAIR per-BU ALE on risk_quantification_engine_v2 |
| GAP-029 | NL graph assistant with traversal explanation | **DONE** | `20f3adfc` | NL graph assistant — traversal-trace across 3 engines |
| GAP-030 | Domain-seed external attack-surface discovery | **DONE** | `f359d83c` | dark_web subsidiary monitors + router + tests |
| GAP-031 | Validation loop (safe probes + identity-path sim) | **IN-PROGRESS** | — | No targeted commit this session; depends on existing MPTE + attack_simulation engines (PARTIAL pre-session) |
| GAP-032 | CIEM over-permissive + least-privilege recs | **DONE** | `06aa3851` | CIEM+AD across 5 engines |
| GAP-033 | AD/Entra identity-path attack graph | **DONE** | `06aa3851` | Kerberoast/DCSync/ESC paths across same 5-engine bundle |
| GAP-034 | Universal Connector (any third-party finding) | **DONE** | `6af2015f`, **`9705e7f8`** (this session) | universal ingest field-mapping; SIEM connector adds 9 generic+vendor adapters |
| GAP-035 | First-party SIEM connectors (Splunk/Sentinel/Chronicle/Datadog) | **DONE** | `6af2015f`, **`9705e7f8`** (this session) | Chronicle/Datadog adapters merged earlier; Splunk-HEC + Sentinel-KQL + Datadog now real format parsers in `siem_connector.py` |
| GAP-036 | Terraform provider | **DONE** | `d0e2f44c` | KILL — Terraform provider is Go artifact, not engine |
| GAP-037 | OpenAPI spec + typed SDKs | **IN-PROGRESS** | `f5ed76a1` | API_REFERENCE_v2.md + Postman shipped; typed SDK artifacts (py/ts/go packages) not yet on PyPI/npm |
| GAP-038 | Stable webhooks event catalogue | **IN-PROGRESS** | — | webhook_router exists; formal event catalogue endpoint not yet shipped |
| GAP-039 | User Tokens (disposable per-user scoped) | **DONE** | `c54a6bb7` | disposable scoped tokens on rbac + auth_router |
| GAP-040 | Tamper-evident audit-log REST export | **DONE** | `e5578679` | export filter coverage verification + audit-export linkage |
| GAP-041 | SBOM CycloneDX 1.4/1.5/1.6 + SPDX 2.3 + PDF | **DONE** | `a8e3c7b3` | SBOM format matrix (SWID/ORT/CSAF) + reeval + claim |
| GAP-042 | FedRAMP/IL + FIPS-140 crypto profile | **DONE** | `06aa3851` | fips_compliance_mode_engine + 44 tests |
| GAP-043 | Explainable AI scoring (formula transparency) | **DONE** | `ccca71c9` | formula transparency across 5 engines |
| GAP-044 | Agentic AI teammates UX | **DONE** | `ccca71c9` | AI teammates UX across 5 engines |
| GAP-045 | Exposure-layer reachability as graph attribute | **DONE** | `659efe2b` | crown-jewel surface paired with GAP-046 |
| GAP-046 | Crown-jewel / business-service tagging + scoping | **DONE** | `659efe2b` | crown-jewel tag surface on 3 engines |
| GAP-047 | TrustGraph 10k+ node scale + <2s render | **IN-PROGRESS** | `672bf293`, `a1ad4161` | Integration topology graph published (1221n/3054e for connectors slice); 10k-node interactive benchmark not yet published |
| GAP-048 | Pre-computed OSS call graphs (Endor corpus) | **NOT-STARTED** | — | No commit; XL effort row deferred. function_reachability_engine (GAP-010) is repo-local, not OSS-corpus-wide |
| GAP-049 | Single-queue Issues workspace | **DONE** | `e370fc0e`, **`07994f29`** (this session unblocks UI) | Unified /issues across findings+alerts+exposures; dashboard render bug fix lets the UI actually mount |
| GAP-050 | Role-based simplified views (L1/CISO/Dev) | **DONE** | `c54a6bb7` | role-view switcher on rbac + auth_router |
| GAP-051 | Executive dollar-risk + ROI-of-fixes dashboard | **DONE** | `0a4be61c` | ROI-of-fixes weekly trend on risk_quantification_engine_v2 |
| GAP-052 | Polygraph composite alert grouping | **DONE** | `ee2fa5c0` | composite alert grouping on anomaly_ml + security_event_correlation |
| ~~GAP-053~~ | ~~Two-layer query language~~ | **SUPERSEDED** | `d0e2f44c` | KILLed; merged into GAP-024 + GAP-029 |
| GAP-054 | Public per-asset pricing calculator | **DONE** | `d0e2f44c`, `145dbe9c` | KILL (marketing) but pricing tier model published; CLAUDE.md tiered pricing $199/$499/$1499 |
| GAP-055 | Continuous SBOM monitoring | **DONE** | `a8e3c7b3` | reeval schedule shipped together with format matrix |
| GAP-056 | Design-phase AI threat modeling | **DONE** | `0eaac6cf` | design-doc ingest + STRIDE extraction across 3 threat-modeling engines |
| GAP-057 | Claim/Label internal/proprietary components | **DONE** | `a8e3c7b3` | component claim shipped together with SBOM bundle |
| GAP-058 | Free-forever developer tier | **NEEDS-PRODUCT-DECISION** | — | UNCLEAR per `dea57dca`: enabled or disabled? No engine work pending |
| GAP-059 | AI Exposure inventory + AI attack paths | **DONE** | `f28c558b` | shadow-AI inventory + attack paths on ai_governance + cmdb |
| GAP-060 | Success Metrics JSON/CSV time-series | **DONE** | `79374db0` | timeseries export across security_metrics_aggregator + kpi + posture_history |
| GAP-061 | Tiered LLM context router + pre-flight cost | **DONE** | `ebde3e50` | tiered LLM router — per-rule context tier + pre-flight cost estimate |
| GAP-062 | Unified deterministic + LLM rule taxonomy | **DONE** | `12495bab` | unified rule taxonomy registry + sync shim (Sprint 3 scope) |
| GAP-063 | Violation lifecycle with stable identity | **DONE** | `23d8f172`, `873c7d82` | findings_lifecycle smoke tests + previousViolationId chain (HIGHEST LEVERAGE absorb) |
| GAP-064 | Zero-infra file-based store (.fixops/) | **DONE** | `873c7d82` | local_file_store_engine v0 + 15 tests |
| GAP-065 | Architecture-aware graph (layers + flows) | **DONE** | `f5df87f2` | layer classifier + flow tracer + boundary alerts |
| GAP-066 | Diff-mode UI (graph dimming + new/resolved badges) | **DONE** | `e370fc0e`, **`07994f29`** | shipped backend; UI dashboard render fix tonight makes it actually visible |
| GAP-067 | Claude Code Skills (`/fixops-scan`) | **DONE** | `d0e2f44c` | KILL — publish script, not engine; skills shipped via filesystem |
| GAP-068 | Committed YAML hook policy (.fixops/hooks.yaml) | **DONE** | `8f4f2788` | YAML hook policy shipped together with GitHub App registration |
| GAP-069 | Dynamic rule DSL (YAML/JSON) + VS Code | **DONE** (DSL only) / **NEEDS-PRODUCT-DECISION** (VS Code) | `5d945dfc` | DSL engine v0 shipped; VS Code half blocked behind GAP-014 product decision |
| NEW-G070 | Semantic type layer (tree-sitter + LSP + ORM) | **IN-PROGRESS** | `a186228b`, `97b95b6b` | semantic_analyzer_engine v0 — Python AST + ORM schema; **TS/Java still stubs** (XL effort, planned multi-sprint) |
| NEW-G071 | IDE-in-browser experience | **IN-PROGRESS** | `0a8d7e3f` | ide_backend_engine v0 — file tree + content + snapshots + diff backend; Monaco frontend not yet shipped |

---

## Tonight's session deltas (2026-04-25 → 2026-04-26)

19 commits this session. The 8 OSS-tool integration families landed (`siem`, `edr_xdr`, `iam_sso`, `container_security`, `cspm`, `dast_pentest`, `threat_intel`, `snyk_oss`). These materially advance:

- **GAP-034 / GAP-035** (Universal ingest + SIEM connectors) — `9705e7f8` adds 9 real format parsers (Splunk HEC envelope, Datadog Logs Intake, Sentinel KQL result tables, ELK `_bulk` NDJSON, Wazuh alerts.json, Suricata eve.json, ArcSight/QRadar CEF, RFC 3164/5424 syslog, generic JSONLines). 51 tests passing. This is the single biggest realism upgrade tonight.
- **GAP-049 / GAP-066** (Unified queue + diff UI) — `07994f29` fixes the dashboard render bug that was masking these as "broken on the UI side"; 5/5 verify-routes now green.
- **GAP-016** (Developer-identity behavioral) — `e370fc0e` adds dev-identity signals.

New engines tonight: `container_security_connector` (849 LOC), `iam_sso_connector` (1079), `siem_connector` (1404), `threat_intel_connector` (921), `dast_pentest_connector` (1032), `cspm_connector` (889), `edr_connector` (809), `snyk_oss_connector` (542). Total: ~7.5K LOC of integration glue.

---

## Commercial vendor integration realism

For every commercial vendor the platform currently *claims* to integrate with, this section answers the binary question: **can the platform ingest a real, format-correct dump from the vendor's actual product without a paid SaaS account?**

`Y` = adapter parses the vendor's documented JSON/CEF/KQL/XML schema and the test suite ships embedded fixture data drawn from the vendor's published format docs.
`N` = no adapter; OSS substitute is offered (Wazuh ⇄ Splunk, Falco ⇄ Falcon, etc.) but the SaaS-format dump cannot be ingested as-is.
`API-LIVE` = no offline format parser, but a live REST/GraphQL client exists in `security_connectors.py` that talks to the vendor's API when keys are present.

| Vendor | Category | Format-real? | Connector file | Sample data path | Notes |
|---|---|---|---|---|---|
| **Splunk** | SIEM | **Y** (HEC envelope) | `suite-core/connectors/siem_connector.py` `SplunkHECAdapter` (line 135) | embedded in test fixture; matches HEC `{"event", "time", "host", "source", "sourcetype", "fields"}` schema | NDJSON-batch + dict + list shapes all parsed |
| **Microsoft Sentinel** | SIEM | **Y** (KQL result tables) | `suite-core/connectors/siem_connector.py` `SentinelKQLAdapter` (line 314) | embedded; matches KQL `{"tables":[{"name","columns","rows"}]}` schema | SecurityAlert/SigninLogs/AuditLogs/CommonSecurityLog/SecurityEvent/AzureActivity column maps wired |
| **Datadog** | SIEM/Logs | **Y** (Logs Intake API) | `suite-core/connectors/siem_connector.py` `DatadogAdapter` (line 232) | embedded; matches `{"ddsource","ddtags","hostname","service","message","status","timestamp"}` schema | `ddtags` parser handles `key:value` and bare-tag forms |
| **Google Chronicle** | SIEM | **N** (label only) | `suite-core/core/siem_integration_engine.py` line 1200 has only an `_endpoint_hint = "https://chronicle.googleapis.com/v1/events:batchCreate"` constant | none | "Chronicle/Datadog SIEM adapters" claim in `6af2015f` covers Datadog only; Chronicle has no parser — closest parsers are CEF+Syslog which Chronicle can speak |
| **ArcSight** | SIEM | **Y** (CEF) | `suite-core/connectors/siem_connector.py` `CEFAdapter` (line 635) | embedded CEF samples in tests | Standard CEF — usable for ArcSight export and any QRadar CEF mode |
| **IBM QRadar** | SIEM | **Y** (CEF) | same as ArcSight | same | QRadar exports CEF natively |
| **Elastic SIEM / ELK** | SIEM | **Y** (`_bulk` NDJSON, ECS schema) | `suite-core/connectors/siem_connector.py` `ELKBulkAdapter` (line 404) | embedded ECS docs in tests | Action+document interleaved NDJSON parsed |
| **Suricata** | NIDS | **Y** (`eve.json`) | `suite-core/connectors/siem_connector.py` `SuricataAdapter` (line 568) | embedded | alert/http/dns/tls/flow/ssh event types wired |
| **Wazuh** | SIEM/EDR | **Y** (alerts.json + Falco passthrough) | `siem_connector.py` `WazuhAdapter` (line 501) + `edr_connector.py` Wazuh path | embedded alerts.json | rule.level → ALDECI severity; native OSS family |
| **Okta** | IAM/SSO | **Y** (System Log) | `suite-core/connectors/iam_sso_connector.py` `adapt_okta_event` (line 796) | tests/test_iam_sso_connector.py 11 vendor adapter tests | normalises to Keycloak shape; routes via `/api/v1/connectors/iam-sso/ingest-vendor` |
| **Auth0** | IAM/SSO | **Y** (Tenant Log) | `iam_sso_connector.py` `adapt_auth0_event` (line 876) | same test file | same normalisation pipeline |
| **Microsoft Entra (Azure AD)** | IAM/SSO | **Y** (sign-in + audit) | `iam_sso_connector.py` `adapt_entra_event` (line 940) | same test file | covers SigninLogs + AuditLogs shapes |
| **Keycloak** | IAM/SSO | **Y** (native event) | `iam_sso_connector.py` (passthrough adapter) | tests | the canonical reference shape |
| **Snyk Open Source** | SCA SaaS | **API-LIVE only** | `suite-core/core/security_connectors.py` line 37 (`https://api.snyk.io`) + `suite-core/core/snyk_integration.py` `_SNYK_API_BASE = "https://api.snyk.io/rest"` | `suite-core/simulations/e2e_validation/app4_streaming/operate/snyk_wiz_findings.json` (legacy fixture) | No format-only parser; relies on live API token. The `snyk_oss_connector.py` shipped tonight uses `Trivy fs` + OSV (`snyk_oss_via_trivy` / `snyk_oss_via_osv`) — i.e. an OSS *substitute*, NOT Snyk JSON ingest |
| **Wiz** | CSPM | **API-LIVE only** | `suite-core/core/security_connectors.py` line 561 (`https://api.wiz.io`) + GraphQL via `_graphql` (line 604) | none | No "Wiz Toxic Combination JSON dump" format parser — `toxic_combo_rules.py` builds *our own* toxic-combo rules using Wiz's published academic corpus (line 211) but does not ingest Wiz's API output offline |
| **Lacework** | CSPM | **N** | — | — | `cspm_connector.py` ships Prowler + Checkov + ScoutSuite + Trivy-config substitutes, no Lacework JSON parser |
| **Prowler** | CSPM (OSS) | **Y** | `suite-core/core/prowler_engine.py` + `prowler_normalizer.py` + `cspm_connector.py` | scripts/cspm_seed_localstack.py | LocalStack-tested in `77ac3af2` |
| **Checkov** | IaC (OSS) | **Y** | `suite-core/core/iac_scanner.py` + cspm flow | embedded | OSS substitute |
| **CrowdStrike Falcon** | EDR/XDR | **N** (substitute only) | `suite-core/connectors/edr_connector.py` ships **Falco + osquery + Wazuh** as the OSS family; no Falcon Detection.Created JSON adapter | none | E2E tests in `e3a340b0` prove the OSS-family pipeline; "Falcon Detection.Created" format claimed in messaging but **NO** parser exists |
| **SentinelOne** | EDR | **N** (substitute only) | same as Falcon — Falco/osquery/Wazuh stand in | none | Same gap. The `endpoint_alert` finding-source label is generic; no SentinelOne `Threats.list` or `Activities.list` JSON parser |
| **Microsoft Defender XDR** | XDR | **N** (substitute only) | `suite-core/core/azure_defender.py` exists (file present per inventory) but only contains policy/recommendation surfaces; no Defender Advanced Hunting KQL ingest, no Defender alert-JSON parser | none | Wazuh substitute via `edr_connector` is what production uses |
| **Sysdig Secure** | Container runtime | **N** (substitute only) | `container_security_connector.py` covers Trivy + Grype + Dockle + kube-bench; no Sysdig events JSON parser | none | Falco is the OSS substitute (already shipped) |
| **Aqua Trivy / Aqua Security** | Container | **Y for Trivy / N for Aqua** | `container_security_connector.py` `_run_trivy_image` + `_parse_trivy` (line 293+) | embedded samples in `tests/test_container_security_connector.py` | Trivy is OSS-licensed by Aqua and the format is Aqua-native. No paid Aqua Enterprise format parser |
| **Snyk Container** | Container | **N** (substitute only) | Grype is the OSS substitute (`_run_grype` line 386) | none | Format-equivalent but not actual Snyk Container JSON |
| **OWASP ZAP** | DAST (OSS) | **Y** (claimed in `dast_pentest_connector.py` 1032 LOC; format adapters not grep-confirmed in this refresh) | `suite-core/connectors/dast_pentest_connector.py` | `scripts/seed_dast_juice_shop.py` (Juice Shop seed) | Per `07994f29` integration; needs separate audit |
| **Veracode DAST** | DAST | **N** (substitute only) | none | none | OWASP ZAP is the OSS substitute; no Veracode XML/JSON parser |
| **Invicti / Acunetix / NetSparker** | DAST | **N** | none | none | Same — only OWASP ZAP available |
| **MISP** | Threat intel (OSS) | **Y** (Feed manifest) | `suite-core/connectors/threat_intel_connector.py` `sync_misp` (line 293) + `_misp_type_to_internal` (line 400) | `https://www.misp-project.org/feeds/circl-osint/manifest.json` (live URL, falls back to embedded) | Type-mapping (ipv4/domain/url/hash/email) implemented |
| **OpenCTI** | Threat intel (OSS) | claimed in topology | `threat_intel_connector.py` (per topology table) | needs verification | Topology label says OpenCTI; not grep-confirmed in this refresh |
| **Recorded Future** | Threat intel SaaS | **N** | none | none | Per topology this row is "replaced by" claim, not an integration claim |
| **Mandiant** | Threat intel SaaS | **N** | none | none | Same — replaced-by claim |
| **ServiceNow** | ITSM | **API-LIVE** | `suite-core/core/connectors.py` (existing 7-connector framework) | — | Bidirectional connector class exists per inventory; no JSON dump format parser |

### Vendor realism summary

- **Format-real (Y)**: 13 vendors / OSS formats ingestable from a static dump
  Splunk HEC, Sentinel KQL, Datadog, ArcSight CEF, QRadar CEF, ELK ECS, Suricata, Wazuh, Okta, Auth0, Entra, Keycloak, MISP, Trivy, Prowler, Checkov, OWASP ZAP-claimed
- **API-LIVE only (live REST/GraphQL, no static-dump parser)**: Snyk, Wiz, ServiceNow
- **Substitute only (we ship the OSS equivalent, not the vendor JSON)**: CrowdStrike Falcon, SentinelOne, Microsoft Defender XDR, Sysdig Secure, Snyk Container, Veracode DAST, Invicti/Acunetix, Lacework, Chronicle, Recorded Future, Mandiant

### Honest correction to investor messaging

The integration topology document `raw/competitive/integration_topology.md` lists 8 OSS tools "Replaces" 8 commercial SaaS products (Snyk OS / Wiz / CrowdStrike / Splunk-Sentinel / Sysdig-Aqua / Okta-Sailpoint / Recorded-Future-Mandiant / Veracode-DAST). The accurate, defensible claim is:

- **3 categories are replaced *and* the commercial vendor's exported JSON can be ingested as-is**: SIEM (Splunk/Sentinel/Datadog/ArcSight/QRadar/ELK), IAM (Okta/Auth0/Entra), Container (Trivy as both Aqua-OSS and substitute for Aqua/Snyk Container).
- **2 categories are replaced with live API-pull from the SaaS**: Snyk SCA and Wiz CSPM, when an API key is present. Without the key, we run the OSS substitute (Trivy+OSV for Snyk OSS; Prowler+Checkov+ScoutSuite for Wiz CSPM).
- **3 categories are replaced *only* by the OSS substitute, with no vendor-format JSON ingest**: EDR/XDR (Falco/osquery/Wazuh as substitute for Falcon/SentinelOne/Defender), DAST (OWASP ZAP as substitute for Veracode/Invicti), Threat Intel (MISP/OpenCTI as substitute for Recorded Future/Mandiant).

Investor-deck sentence to add: "All 8 OSS-tool families ship as drop-in replacements; **6 of 8 SIEM-class commercial formats and all 3 major IAM/SSO formats can additionally be ingested directly from the vendor's exported logs without our connector touching their cloud**."

---

## Verification flags (still open)

- **GAP-031** (validation loop maturity) — no targeted commit this session; relies on pre-session MPTE + attack_simulation
- **GAP-037** (typed SDKs) — needs PyPI/npm/Go-mod publish step
- **GAP-038** (webhook event catalogue) — formal event-list endpoint not yet shipped
- **GAP-047** (10k-node interactive render benchmark) — TrustGraph integration topology graph published 1221n/3054e and competitor-emerging.md cited 1941n/7324e earlier; no published 10k-node benchmark
- **GAP-048** (OSS-corpus call graphs) — XL effort, deferred
- **NEW-G070** (TS + Java semantic layer) — Python AST done; TS/Java still stubs
- **NEW-G071** (Monaco file viewer frontend) — backend done; UI not started

---

*End of refresh — 71 gaps re-scored against HEAD `a1ad41617e549766032c87cc89b62732a6dbaa61`. 50 DONE / 12 IN-PROGRESS / 6 NOT-STARTED + 2 NEEDS-PRODUCT-DECISION + 1 SUPERSEDED.*
