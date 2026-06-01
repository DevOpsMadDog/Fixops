# SPEC-016 — SCIF Stack-Fit: Correlate Existing Tools + Close the Loop

- **Status**: DRAFT
- **Owner family**: Connectors / TrustGraph / Orchestration
- **Routers**: `wiz_router.py`, `prisma_router.py` (NEW), `confluence_*` (via `connectors.py`), `jira_cloud_router.py`, `servicenow_router.py`, `splunk_router.py`, `github_api_router.py`, `scanner_ingest_router.py`
- **Engines**: `wiz_cnapp_engine.py`, `security_connectors.py:PrismaCloudConnector`, `connectors.py:ConfluenceConnector`, `pipeline_orchestrator.py`, `knowledge_brain` (Store B), `_index_findings_into_brain`
- **Stores**: `data/fixops_brain.db` (Store B), `data/trustgraph.db` (Store A), findings DB (SecurityFindingsEngine)
- **Depends on**: SPEC-001 (TrustGraph correlation), SPEC-005b (graph populate), SPEC-015 (connectors), SPEC-007 (tenancy). Env: `WIZ_CLIENT_ID/SECRET/API_URL`, `PRISMA_*`, `CONFLUENCE_*`, `JIRA_*`, `SERVICENOW_*`, `SPLUNK_*`, `GITHUB_*`
- **Last updated**: 2026-06-02

## 1. Intent (the why)
A SCIF organization already runs WIZ (CNAPP), Prisma Cloud (CNAPP), CrowdStrike/Defender/SentinelOne (XDR),
Splunk (SIEM), GitHub Enterprise (CI/CD), ServiceNow (CMDB), Jira (ALM), Confluence (ADRs/architecture), and AWS.
**ALDECI does not replace any of these.** It is the correlation + decision + evidence brain that sits *above*
them: it ingests each tool's findings, correlates code→cloud→runtime into one TrustGraph exposure, renders an
air-gapped AI-council verdict with blast-radius + reachability, and writes the decision back into the customer's
own systems of record (Jira ticket, ServiceNow change, Splunk event), signed for the ATO package. The SCIF
differentiator: WIZ/Prisma consoles are SaaS and may be unreachable in a true air-gap — ALDECI is the one place
classified findings get AI-correlated with **zero egress** (local LLM, `FIXOPS_AIRGAP_MODE=enforced`).

**Code-as-source-of-truth note (verified 2026-06-02):** the connectors mostly *already exist and are real* —
this spec is NOT "build connectors", it is "wire the real connectors into the correlation brain and close the
loop". Confirmed real in code: `wiz_cnapp_engine.py` (live Wiz GraphQL OAuth2, no mocks, honest `unavailable`);
`PrismaCloudConnector` (live `api.prismacloud.io`, alerts + Compute vulns); `ConfluenceConnector` (read via
`get_page_by_id`/CQL `search`/`list_pages` + write/update). Splunk/CrowdStrike/ServiceNow/Jira/GitHub/AWS/
Defender/SentinelOne all have real routers.

## 2. Scope — endpoints
| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| POST | /api/v1/wiz/ingest | Pull Wiz issues → normalize → findings → Store B brain | api_key_auth | yes (org_id) |
| GET  | /api/v1/wiz/capability | Honest configured/unavailable status | api_key_auth | yes |
| POST | /api/v1/prisma/ingest | Pull Prisma alerts+Compute vulns → normalize → findings → brain | api_key_auth | yes |
| GET  | /api/v1/prisma/capability | Honest configured/unavailable status | api_key_auth | yes |
| POST | /api/v1/design-context/confluence/import | Pull ADR/arch page (CQL) → design-time threat context node | api_key_auth | yes |
| POST | /api/v1/closed-loop/decide | Run a finding through verdict → write Jira + ServiceNow + Splunk + signed evidence | api_key_auth | yes |
| GET  | /api/v1/closed-loop/status | Last loop runs + delivery receipts per org | api_key_auth | yes |

Out of scope: building new scanners (we ingest the customer's tools, not re-scan); WIZ/Prisma SaaS console UX;
replacing Splunk dashboards; any egress in `enforced` air-gap mode beyond the customer's own on-prem tool endpoints.

## 3. Data contracts
```
POST /api/v1/wiz/ingest      → 200 {"ingested":N,"brain_nodes_added":M,"correlated":true}
                             | 503 {"status":"unavailable","detail":"WIZ_CLIENT_ID unset"}
POST /api/v1/prisma/ingest   → 200 {"ingested":N,"brain_nodes_added":M}
                             | 503 {"status":"not_configured","detail":"PRISMA_* unset"}
POST /api/v1/design-context/confluence/import
                             → 200 {"page_id":"...","context_nodes":K,"linked_findings":J}
                             | 503 {"status":"not_configured"}
POST /api/v1/closed-loop/decide
  body {"finding_id":"...","targets":["jira","servicenow","splunk"]}
                             → 200 {"verdict":"block|allow|defer","jira_key":"SEC-123",
                                    "servicenow_sys_id":"...","splunk_event_id":"...",
                                    "evidence_signature":"<ML-DSA>"}
                             | 503 per-target {"target":"jira","status":"not_configured"}
```
Every connector returns an **honest unconfigured path** (503 `unavailable`/`not_configured`) — never 500, hang, or fake data.

## 4. Functional requirements
- **REQ-016-01**: `/wiz/ingest` pulls Wiz issues via the existing live GraphQL client, normalizes each to a Finding,
  promotes org-scoped, and calls `_index_findings_into_brain` so council enrichment sees Wiz exposures (Store B grows).
- **REQ-016-02**: `/prisma/ingest` uses `PrismaCloudConnector` (alerts + Compute vulns), same normalize→findings→brain path.
- **REQ-016-03**: Prisma gets a real mounted router (`prisma_router.py`) and is registered in `connector_registry`.
- **REQ-016-04**: Confluence ADR/architecture pages import into TrustGraph as **design-time context nodes**, linkable to
  findings (design→runtime provenance), reusing the existing `ConfluenceConnector` read methods (no new auth code).
- **REQ-016-05**: `/closed-loop/decide` takes a finding, runs the air-gapped council verdict (SPEC-001/003 path), and
  on `block`/`defer` writes a Jira ticket, a ServiceNow change/incident, and a Splunk decision event, then signs the
  decision bundle with ML-DSA (SPEC-006b) — each delivery best-effort + idempotent, honest per-target failure.
- **REQ-016-06**: All ingest + loop writes are org-scoped (SPEC-007 ContextVar `get_org_id`); cross-org read → 404.
- **REQ-016-07**: In `FIXOPS_AIRGAP_MODE=enforced`, every connector outbound call MUST pass a pre-flight egress guard
  (`assert_egress_allowed(url, connector)`) BEFORE any socket opens: (a) a custom on-prem URL must be explicitly set;
  (b) known vendor-SaaS FQDNs (`*.wiz.io`, `prismacloud.io`) are rejected; (c) RFC-1918 / link-local /
  metadata IPs (`169.254.169.254`, `10.*`, `172.16-31.*`, `127.*`, `::1`, `fd*`) and non-`https` schemes are rejected
  (SSRF); (d) HTTP clients use `follow_redirects=False`. Failing any → honest 503, never a silent egress. *(both reviewers, P0)*
- **REQ-016-08**: `/closed-loop/decide` finding lookup MUST be `WHERE finding_id=? AND org_id=get_org_id()` → 404 on miss
  (ContextVar alone is insufficient); all finding text is escaped/stripped before being written to Jira/ServiceNow
  fields (no `[~mention]` / script / business-rule injection). *(Red-Team, P0)*
- **REQ-016-09**: Each `/closed-loop/decide` delivery is deduped on `(org_id, finding_id, verdict_hash)` via a UNIQUE
  constraint in a `closed_loop_deliveries` table — replay returns the existing receipt, never re-writes Jira/ServiceNow. *(Red-Team, P1)*
- **REQ-016-10**: The signed decision bundle (ML-DSA, SPEC-006b) is written to the append-only tamper-evident audit
  store (`evidence_chain`) carrying subject identity (api-key principal), org_id, classification label, full verdict
  input+output, and a monotonic timestamp — AU-2/3/9/12. Returning the signature in the HTTP response is NOT sufficient. *(SCIF-Accreditor, P0)*
- **REQ-016-11**: `_index_findings_into_brain` stamps a `classification_level` on every node (from tenant metadata, default
  per the org's banner level); the brain read path refuses nodes whose level exceeds the requesting org's clearance. *(SCIF-Accreditor, P1)*
- **REQ-016-12**: The raw `POST /api/v1/wiz/graphql` passthrough is gated (admin-scope + audit-logged); `/wiz/ingest`
  calls the engine's typed methods directly and never proxies caller-supplied GraphQL through a shared credential. *(Red-Team, P1)*
- **REQ-016-13**: Black Duck SCA gets a real ingest path (Hub REST API connector + normalizer registered in
  `scanner_parsers`, `source_tool="blackduck"`) → findings → brain — the only genuine build gap among the org's
  named SCA/SAST/DAST tools. *(code-truth audit 2026-06-02)*

### Adjacent stack tools the org named (Snyk / Veracode / Black Duck / Prisma) — code-truth status
- **Snyk** ✅ real: `SnykOSSConnector` (live API) **+** `SnykNormalizer` (registered, `source_tool="snyk"`) — already
  flows scanner-ingest → normalize → `_index_findings_into_brain` (wired in increment 1). No work.
- **Veracode** ✅ real: `VeracodeNormalizer` (SAST XML + Findings API) + DAST parser, registered (`"veracode"`) —
  flows via upload → brain. No work.
- **Prisma** ✅ real `PrismaCloudConnector`, unmounted → increment 2 (router + registry).
- **Black Duck** 🔴 build gap → REQ-016-13.
- All four vendor-SaaS FQDNs (`snyk.io`, `veracode.com`, `blackduck.com`, `synopsys.com`, `prismacloud.io`) are in the
  enforced-mode egress blocklist (`assert_egress_allowed`) so a SCIF deploy must point each at its on-prem endpoint.

## 5. Non-functional requirements
- Latency: ingest is async/paginated; GET capability < 1s; `/closed-loop/decide` < 10s (council bound).
- Tenancy: org_id from `apps.api.org_middleware`/`dependencies`; all brain nodes carry org_id; cross-org → 404.
- Failure mode: any unconfigured connector → honest 503; partial closed-loop delivery → 200 with per-target receipts
  (some `delivered`, some `not_configured`), never a fabricated success.
- Air-gap: no telemetry; no vendor-SaaS default URLs reachable in `enforced`; local LLM only for the verdict.

## 6. Acceptance criteria (executable)
- **AC-016-01**: With WIZ env unset, `POST /api/v1/wiz/ingest` → 503 `unavailable` (no 500, no fake findings).
- **AC-016-02**: With a stub Wiz endpoint returning 2 issues, ingest → `ingested:2` and Store B node count increases by ≥2 for the org (verify via brain query, not a self-report).
- **AC-016-03**: `prisma_router.py` mounts (`create_app()` boots, route present in `/openapi.json`); Prisma in `connector_registry`.
- **AC-016-04**: Confluence import of a fixture ADR page creates ≥1 design-context node linked to a finding (graph edge present).
- **AC-016-05**: `/closed-loop/decide` on a real ingested finding returns a verdict + at least one delivery receipt; with all targets configured, returns jira_key + servicenow_sys_id + splunk_event_id + a non-empty ML-DSA signature.
- **AC-016-06**: A second org cannot read org-A's closed-loop status (→ 404). `scripts/tenancy_lint.py` stays green.
- **AC-016-07**: Beast Mode 13-file smoke stays 756/756; `create_app()` boots all routes in all 3 air-gap modes.

## 7. Debate log (Mysti)
| Date | Mode | Verdict / change |
|------|------|------------------|
| 2026-06-02 | Author (Chief-Architect) | Reframed from "build WIZ/Prisma/Confluence" to "wire existing real connectors + close loop" after code-truth audit. |
| 2026-06-02 | SCIF-Accreditor | **APPROVE-WITH-CHANGES**: (1) REQ-016-07 was policy-only, no code gate → added `assert_egress_allowed` pre-flight guard. (2) ML-DSA signature alone insufficient for AU-family → added REQ-016-10 (append-only evidence_chain w/ subject+class+full I/O). (3) brain nodes carry no classification marking → added REQ-016-11. |
| 2026-06-02 | Red-Team | **APPROVE-WITH-CHANGES**: (1) cross-org `finding_id` probe → added REQ-016-08 (`AND org_id=` predicate, 404 on miss, field escaping). (2) raw `/wiz/graphql` shared-credential exfil → added REQ-016-12 (admin-gate, ingest uses typed methods). (3) `/ingest` as SSRF primitive (metadata URL) → folded into REQ-016-07. (4) replay → duplicate tickets → added REQ-016-09 (`(org,finding,verdict_hash)` UNIQUE). |
| 2026-06-02 | Resolution | Both APPROVE-WITH-CHANGES; 6 new REQs (07-12) folded in. Increment-1 scope (WIZ /ingest) must ship REQ-016-07 (egress guard) + REQ-016-11 (class marking). Closed-loop REQs 08-10 land in increment 3. |

## 8. Implementation notes
Build order: (1) `/wiz/ingest` normalize→brain (highest ROI — engine already real), (2) `prisma_router.py` + registry,
(3) `/closed-loop/decide` orchestration over existing Jira/ServiceNow/Splunk routers, (4) Confluence design-context import.
Reuse `_index_findings_into_brain` (scanner_ingest_router) as the single brain-write path. Do NOT add new connector
auth — the OAuth2/REST clients already exist and are real. Commit per increment; verify each AC against the running app.
