# FixOps Mock/Demo Data Audit — Knowledge Graph

> **Generated**: 2026-03-14 | **Scope**: Full codebase line-by-line audit
> **Purpose**: Pass to GitHub Copilot for automated remediation

---

## CATEGORY 1: FRONTEND — Demo Data Generators (CRITICAL)

### 1.1 MPTEConsole.tsx — Fake Pentest Evidence
- **File**: `suite-ui/aldeci/src/pages/attack/MPTEConsole.tsx`
- **Lines**: 166–237 (`seededValue`, `seededInt`, `seededHex` helpers)
- **Lines**: 189–237 (`generateDemoPhases()` — generates fake 19-phase pentest results)
- **Lines**: 240–457 (`generateEvidence()` — hardcoded strings for 19 phases: fake Nmap output, SQLi payloads, PCAP counts, etc.)
- **Lines**: 459–498 (`generateDemoVerifications()` — 6 fake verification runs against `api.acmecorp.com`, `payments.acmecorp.com`, etc.)
- **Lines**: 1942, 1960 — Fallback: if API returns empty, calls `generateDemoVerifications()` / `generateDemoPhases()`
- **Impact**: The entire MPTE verification history shown in the UI is fabricated when backend has no data
- **Fix**: Remove generators. Show "No verifications yet — run a scan" empty state. Wire to real `/api/v1/micro-pentest/run` results.

### 1.2 EvidenceBundles.tsx — Fake Evidence Bundles
- **File**: `suite-ui/aldeci/src/pages/evidence/EvidenceBundles.tsx`
- **Lines**: 102–196 (`DEMO_BUNDLES` — 4 fake evidence bundles: EVB-2026-001 through EVB-2026-004)
- **Lines**: 198–270 (`DEMO_COMPLIANCE` — fake compliance status for SOC2/PCI-DSS/HIPAA/ISO27001)
- **Lines**: 1623 — Fallback: `return DEMO_BUNDLES` when API returns empty
- **Lines**: 1638 — Fallback: `return DEMO_COMPLIANCE` when API returns empty
- **Impact**: Users see fake evidence bundles that don't correspond to real scans
- **Fix**: Remove DEMO_BUNDLES/DEMO_COMPLIANCE. Show empty state. Generate real bundles via `/api/v1/evidence/export`.

### 1.3 AICopilot.tsx — Fake AI Responses
- **File**: `suite-ui/aldeci/src/components/AICopilot.tsx`
- **Lines**: 210–300 (`getFallbackResponse()` — keyword-matched static responses for vuln, risk, compliance queries)
- **Lines**: 176, 191 — Used as both primary fallback and catch-block fallback
- **Impact**: AI Copilot appears to "work" even when backend AI service is completely down
- **Fix**: Show "AI service unavailable" error. Remove fake responses. Connect to real `/api/v1/copilot/chat`.

### 1.4 MultiLLMConsensusPanel.tsx — Hardcoded Confidence Scores
- **File**: `suite-ui/aldeci/src/components/dashboard/MultiLLMConsensusPanel.tsx`
- **Lines**: 68–76 (`PROVIDER_BASE_CONFIDENCE` — hardcoded scores: GPT-4=92, Claude=89, Gemini=85, Mistral=78, Llama=75)
- **Line**: 220 — Uses hardcoded scores when no real LLM response
- **Impact**: Multi-LLM consensus panel shows fake confidence values
- **Fix**: Only show providers that actually responded. Get confidence from real LLM API responses.

### 1.5 MLDashboard.tsx — Hardcoded ML Metrics
- **File**: `suite-ui/aldeci/src/pages/ai-engine/MLDashboard.tsx`
- **Lines**: 276–280 — Hardcoded feedback loop accuracies (94.2%, 89.7%, 96.1%, 91.5%, 97.3%) with fake sample counts
- **Lines**: 314–317 — Hardcoded "learning progression" (Week 1: 78.4%, Week 2: 85.1%, etc.)
- **Impact**: ML dashboard shows impressive but completely fabricated metrics
- **Fix**: Wire to real `/api/v1/self-learning/metrics`. Show "No training data" when empty.

### 1.6 SelfLearningDemo.tsx — Demo Label in Name
- **File**: `suite-ui/aldeci/src/pages/ai-engine/SelfLearningDemo.tsx`
- **Lines**: 1–15 — File literally named "Demo", labeled "DEMO-012"
- **Impact**: Entire page is a demo simulation. Calls real API but seeds fake data first.
- **Fix**: Rename to `SelfLearning.tsx`. Remove seed-first pattern. Only show real feedback data.

---

## CATEGORY 2: FRONTEND — Silent API Failure Pattern (HIGH)

### Pattern: `.catch(() => ({ data: { items: [] } }))`
12 page components silently swallow API errors and show empty arrays, which often trigger demo data fallbacks.

| # | File | Line(s) | Endpoint(s) Silenced |
|---|------|---------|---------------------|
| 1 | `pages/core/KnowledgeGraphExplorer.tsx` | 472-473, 531 | `/brain/nodes`, `/brain/all-edges`, `/brain/nodes/{id}/neighbors` |
| 2 | `pages/core/ExposureCaseCenter.tsx` | 748 | `/cases` |
| 3 | `pages/core/BrainPipelineDashboard.tsx` | 217 | `/brain/pipeline/runs` |
| 4 | `pages/evidence/SOC2EvidenceUI.tsx` | 98 | `/brain/evidence/packs` |
| 5 | `pages/evidence/EvidenceAnalytics.tsx` | 195-197 | `/analytics/summary`, `/analytics/trends/*` |
| 6 | `pages/evidence/SLSAProvenance.tsx` | 28-29 | `/provenance/`, `/evidence/` |
| 7 | `pages/protect/AutoFixDashboard.tsx` | 293-294 | `/autofix/history`, `/autofix/fix-types` |
| 8 | `pages/code/SBOMGeneration.tsx` | 130-132 | `/inventory/applications`, `/inventory/assets` |
| 9 | `pages/feeds/LiveFeedDashboard.tsx` | 244-247 | `/feeds/health`, `/feeds/epss`, `/feeds/kev` |
| 10 | `pages/cloud/ContainerSecurity.tsx` | 281-282 | Container scan status, `/vulns/discovered` |
| 11 | `pages/cloud/RuntimeProtection.tsx` | 249-250 | `/inventory/services`, `/nerve-center/state` |
| 12 | `pages/ai-engine/MLDashboard.tsx` | 63-66 | `/ml/models`, `/ml/analytics/*` |

**Fix**: Replace `.catch(() => empty)` with proper error handling that shows error banners to the user.

---

## CATEGORY 3: BACKEND — Demo Data Module (CRITICAL)

### 3.1 demo_data.py — Central Demo Data Repository
- **File**: `suite-api/apps/api/demo_data.py`
- **Lines**: 15–80 (`DEMO_REPORTS` — 8 fake security reports)
- **Lines**: 83–124 (`DEMO_MPTE_REQUESTS` — 5 fake pentest requests with fake CVE IDs)
- **Lines**: 127–170 (`DEMO_MPTE_RESULTS` — 3 fake exploitation results)
- **Lines**: 173–204 (`DEMO_MARKETPLACE_ITEMS` — 3 fake marketplace packs)
- **Lines**: 207–372 (`generate_demo_*_report()` — generates fake PDF/JSON/CSV/SARIF reports)
- **Lines**: 374–432 (`seed_demo_reports()` — seeds fake reports to disk)
- **Lines**: 435–438 (`is_demo_mode()` — checks if mode is "local" or "sandbox")
- **Impact**: This file is imported by multiple routers to seed fake data on startup
- **Fix**: Delete entire file. Reports should come from real scan results only.

---

## CATEGORY 4: BACKEND — Connector Demo Mode (HIGH)

### 4.1 universal_connector.py — Fake Jira/GitHub/Slack Tickets
- **File**: `suite-core/connectors/universal_connector.py`
- **Lines**: 43 (`_DEMO_LATENCY_MS = 5.0` — artificial delay to simulate real API calls)
- **Lines**: 157 (`demo_mode: bool = False` in ConnectorResult dataclass)
- **Lines**: 445, 515, 580, 684 — JiraConnector falls back to `_demo_create`, `_demo_update`, `_demo_close`, `_demo_get`
- **Lines**: 777–819 — JiraConnector `_demo_*` methods return fake DEMO-XXXXXX ticket keys with `demo.atlassian.net` URLs
- **Lines**: 866, 927, 989, 1048 — GitHubConnector falls back to `_demo_*` methods
- **Lines**: 1137–1179 — GitHubConnector `_demo_*` methods return fake issue numbers with `github.com/demo-org/demo-repo` URLs
- **Lines**: 1296, 1365, 1421 — SlackConnector falls back to `_demo_*` methods
- **Lines**: 1464–1477 — SlackConnector `_demo_create` returns fake Slack message responses
- **Impact**: All 3 connectors (Jira, GitHub, Slack) silently succeed with fake data when credentials missing
- **Fix**: Return `ConnectorResult(success=False, error="Credentials not configured")` instead of fake success.

---

## CATEGORY 5: BACKEND — Evidence Router Demo Fallbacks (CRITICAL)

### 5.1 evidence_router.py — Fake Evidence Bundles & Verification
- **File**: `suite-evidence-risk/api/evidence_router.py`
- **Lines**: 465–528 — Returns 4 hardcoded demo bundles (EVB-2026-001 to EVB-2026-004) when no real bundles on disk
- **Lines**: 827–936 — `download_bundle()`: Generates synthetic JSON when no physical file exists
- **Lines**: 955–1040 — `verify_bundle()`: Falls back to `_DEMO_SIGNED_BUNDLES = {"EVB-2026-001", "EVB-2026-003"}`
- **Line**: 1025 — `pass  # Evidence storage not configured -- fall through to demo`
- **Impact**: Evidence verification (V10 pillar — cryptographic proof) is faked
- **Fix**: Return 404 when storage empty. Return "unable to verify" instead of fake pass/fail.

---

## CATEGORY 6: BACKEND — Self-Learning Demo Seeding (MEDIUM)

- **File**: `suite-core/core/self_learning.py` lines 1154–1306 (`seed_demo_data()`)
- **File**: `suite-core/api/self_learning_router.py` lines 503–569 (seed/reset endpoints)
- **File**: `suite-core/api/knowledge_graph_router.py` line 336 (graph seed endpoint)
- **Fix**: Remove seed endpoints or gate behind admin auth + non-production flag.

---

## CATEGORY 7: BACKEND — Marketplace Hardcoded Packs (MEDIUM)

- **File**: `suite-api/apps/api/marketplace_router.py`
- **Lines**: 127–203 (`_BUILTIN_MARKETPLACE_ITEMS` — 3 items with fake download counts)
- **Lines**: 272–327 — Legacy `/packs/{framework}/{control}` with hardcoded ISO27001 packs
- **Fix**: Keep builtin items but remove fake counts. Legacy packs should query real DB.

---

## CATEGORY 8: BACKEND — Hardcoded Encryption Key (SECURITY 🔴)

- **File**: `suite-core/core/evidence.py` line 130–133
- **Key**: `XA4YsbLpheGujMd1vXX4HR1jAWGTL9D9ZvGBZgy00eg=`
- **Fix**: MUST require `FIXOPS_EVIDENCE_ENCRYPTION_KEY` env var. Fail hard in production.

---

## CATEGORY 9: BACKEND — Settings & CLI (LOW)

- **File**: `suite-core/config/enterprise/settings.py` lines 30–38 — `DEMO_MODE`, `DEMO_VECTOR_DB_PATTERNS`
- **File**: `suite-core/core/cli.py` lines 611–636 — Creates dummy input files
- **File**: `suite-core/core/demo_runner.py` lines 128–195 — CLI demo pipeline
- **Fix**: Rename `DEMO_*` prefixes. Keep demo_runner for demos only.

---

## CATEGORY 10: Compliance Fallback Controls (ACCEPTABLE)

- **File**: `suite-evidence-risk/api/evidence_router.py` lines 1322–1383
- SOC2/PCI-DSS/HIPAA control definitions — reference data, ACCEPTABLE.
- Assessment STATUS should come from real checks, not hardcoded values.

---

## PRIORITY MATRIX

| Priority | What | File:Lines | Effort |
|----------|------|-----------|--------|
| 🔴 P0 | Hardcoded encryption key | evidence.py:130 | 1h |
| 🔴 P0 | Evidence verification faked | evidence_router.py:955-1040 | 4h |
| 🟠 P1 | MPTE fake evidence | MPTEConsole.tsx:166-498 | 8h |
| 🟠 P1 | Evidence bundles faked | EvidenceBundles.tsx:102-270 | 4h |
| 🟠 P1 | demo_data.py entire file | demo_data.py:1-438 | 4h |
| 🟠 P1 | Connector demo mode | universal_connector.py:777-1477 | 6h |
| 🟠 P1 | Evidence router demo bundles | evidence_router.py:465-936 | 4h |
| 🟡 P2 | Silent API failures (12 pages) | See Category 2 table | 6h |
| 🟡 P2 | AI Copilot fake responses | AICopilot.tsx:210-300 | 2h |
| 🟡 P2 | ML Dashboard fake metrics | MLDashboard.tsx:276-317 | 2h |
| 🟡 P2 | LLM confidence hardcoded | MultiLLMConsensusPanel.tsx:68-76 | 2h |
| 🟡 P2 | Self-learning seed endpoints | self_learning_router.py:503-569 | 2h |
| 🟢 P3 | Marketplace fake counts | marketplace_router.py:127-203 | 1h |
| 🟢 P3 | Settings DEMO_ prefixes | settings.py:36-38 | 30m |
| 🟢 P3 | CLI dummy files | cli.py:611-636 | 1h |

**Total**: 6 frontend components, 12 silent-error pages, 8 backend files, 3 demo endpoints, 11 constants, 1 security issue. **~48h to remediate.**

---

## COPILOT REMEDIATION RULES

1. **Never delete an endpoint** — replace demo data with empty-state response
2. **Frontend**: Replace `generateDemo*()` with `[]` + "No data yet" UI message
3. **Frontend**: Replace `.catch(() => ({ data: [] }))` with proper error toast + throw
4. **Backend**: Replace demo fallbacks with HTTP 404 or `{"items": [], "total": 0}`
5. **Backend**: Connectors return `success=False` when credentials missing
6. **Backend**: Evidence verification returns `"unable_to_verify"` instead of fake pass/fail
7. **Security**: Hardcoded encryption key → require env var, fail startup if production
