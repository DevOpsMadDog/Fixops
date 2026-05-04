# Changelog

All notable changes to ALDECI/Fixops will be documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [SemVer](https://semver.org/).

---

## [Unreleased] — 2026-05-05

> **Branch**: `features/intermediate-stage`
> **Session**: ~50 commits across hardening, performance, QA, and feature backfill.
> **Tip SHA at entry cut**: `43d43d95`

---

### Added

- **Prometheus `/metrics` endpoint** — 5 gauges (active scans, findings, connectors, pipeline runs, trust events) [`e583d24d`]
- **`/api/v1/health/comprehensive` aggregator** — single endpoint polling all subsystem health checks [`bfa88303`]
- **Rate limiting** on auth, webhook, and ingest — 7 endpoints hardened against burst abuse [`c03ffd27`]
- **17 SQLite indexes** across 6 domain databases — covering high-frequency query paths (findings, scans, connectors, risk, evidence, trust) [`43d43d95`]
- **6 deferred empty-endpoints backfilled** with real engine wiring (no more 501 stubs on critical paths) [`3d8fd7c9`]
- **CI regression-gate workflow** — OWASP audit, perf benchmarks, and import sweep run on every PR via GitHub Actions [`7c86c8d2`]

---

### Changed

- **Brain Pipeline** — 3 hotspots fixed, ~2 s saved per 12-step run [`ee340f83`]
- **LLM Council** — 3 hotspots fixed, 600–1 500 ms saved on real-provider path [`d61dde59`]
- **Connector framework** — O(N²) endpoint lookup → O(1); sequential `bulk_push` → `asyncio.gather`; sequential `scan_fleet` → `ThreadPoolExecutor` [`eb46d106`]
- **Risk scorer** — latency reduced from ~527 ms → < 50 ms [`91187379`]
- **RSA cache** — latency reduced from ~2 111 ms → < 50 ms [`91187379`]

---

### Fixed

- `commercial_vendor_router` — missing `Query` import causing 500 on vendor list endpoints [`ee340f83`]
- `validation_router` — relative import error breaking module load [`eb46d106`]
- `scanner_parsers` — cross-scanner dedup logic producing duplicate findings across parser boundaries [`51895d85`]
- 4 platform gaps closed: pip-audit SARIF normalisation, ingest-to-issues pipeline linkage, `/risk-scoring/summary` missing fields, cross-scanner dedup [`51895d85`]
- 5 frontend dashboards (`FindingsExplorer`, `ThreatHunting`, `VendorManagement`, `DeveloperPortal`, `SBOMManagement`) — mock fallback data replaced with live API calls [`736a1188`, `d71dd091`, `30c8464b`, `d14ba174`, `01e08e81`]
- `AgeBadge` stale `now` reference in `FindingsExplorer` causing incorrect age rendering [`736a1188`]

---

### Security

OWASP audit across 7 packages — ~38 individual fixes including:

- Information disclosure via verbose error responses → generic error messages
- Hardcoded secrets moved to environment variables (JWT secret, OAuth tokens)
- Missing HTTP timeouts on external calls → explicit timeout enforcement
- CVE injection via unsanitised scanner input → input validation layer
- Severity bypass via crafted payload → server-side severity enum enforcement
- Overly broad exception handlers narrowed to specific exception types
- OAuth token redaction in structured logs
- SBOM bomb cap (unbounded dependency tree recursion → depth limit)
- Suite-core connector OWASP fixes (4 issues) [`2652b066`]

---

### Tests

- **OWASP regression lockdown** — 46 tests covering all 7 hardened packages; wired into CI [`51895d85`, `7c86c8d2`]
- **TrustGraph emit-site assertions** — 14/14 engines validated emitting events on expected paths [`11b5f10c`]
- **Engine + router import sweep** — 1 315 modules verified clean (0 skipped, 0 import errors) [`752951f5`]
- **Perf benchmark suite** — RSA cache, risk scorer, and brain pipeline thresholds enforced; CI blocks regression [`91187379`, `7c86c8d2`]
- **Rate-limit tests** — burst and sustained load tests for all 7 rate-limited endpoints [`c03ffd27`]
- **Health endpoint tests** — comprehensive aggregator response structure validated [`bfa88303`]
- **Prometheus metrics tests** — gauge presence and label correctness verified [`e583d24d`]

---

## [0.1.0-alpha] - 2026-04-26

> **Branch**: `features/intermediate-stage`
> **Session**: ~69 commits across a pre-dawn-to-evening megasession.
> **Tip SHA at release cut**: `f9cf3fe8`

---

### Frontend (Phase 3 UX Consolidation)

#### Added
- **Issues hero** (Wiz-pattern, single queue with 8 tabs — findings/triage/SBOM/supply-chain/threat-intel/upgrade-paths/exception) [`12f16c83`]
- **Brain Pipeline hero** (12-step visualizer + Multi-LLM Council rail, MPTE Console, FAIL Chaos, Code Intelligence tabs) [`0771bd11`, `8b36a6ee`, `9cbf0ae1`]
- **Compliance hero** (Cloud Posture + AI Exposure Tenable-parity + Waivers + Policies sub-tabs) [`e0972bac`, `0b8c0b86`, `2a97fbcf`]
- **Asset Graph hero** (Apiiro/Wiz-pattern second-brain canvas + Inventory tab, Attack Paths) [`7e728702`, `afc66592`, `c08b9325`]
- **Command Dashboard hero** (persona-aware landing, AI Copilot tab, real apiFetch) [`4c6cd97b`, `5486541d`]
- **Admin Console hero** (multi-tenant administration, MCP Gateway + System Health sub-tabs) [`a6e73395`, `f4983bcb`]
- **Remediation Center hero** at `/remediate` [`00f41b74`]
- **Integrations Hub** folded into Asset Graph hero [`c08b9325`]
- **Executive Brief, SOC Ops, SLA/Risk, Issue Detail** screens folded into P1 heroes [`768c5da9`]
- Playwright golden-path E2E suite for all 6 P0 hero screens — **6/6 PASS, zero mocks** [`22268aeb`]
- **81+ consolidation redirect rules** preserving bookmarks for 90 days [`82c1ae36`]
- IDE-in-browser (3-panel Monaco file-tree + diff viewer, NEW-G071) [`8b957ae1`]
- Real customer end-to-end demo trace with 6-hero screenshot evidence (Juice Shop) [`134cd807`]
- Admin + Asset Graph clean screenshots after P0 bug fixes [`aad87027`]

#### Changed
- Consolidated 370+ source screens to 30 hero screens; 99+ redirect rules in place [`7a2990a3`, `82c1ae36`]
- ~50 mock pages (J-O slice) wired to live API endpoints [`3feb5b71`]
- ~50 mock pages (P-Z slice) wired to live API endpoints [`ab325746`]

#### Fixed
- TypeScript errors reduced from 152 to 98 (54 cleared) — SecurityTrainingDashboard + KPICard label fixes [`b11fff60`]

---

### Backend — TrustGraph Event Bus

#### Added
- `init_event_bus` wired; router middleware coverage raised from 3.9% to 80%+ [`48ee40d2`]
- 30 highest-degree hubs wired across 6 batches (graph.py 9366, scanner_parsers 3975, connectors 3032, ld_provider 3320, cache_service 4027, + 25 more) [`befea111`, `db618c93`, `d6ae6ab5`, `3074e918`, `579d4d84`, `b748d645`, `64fd4a49`, `9852939d`, `c6389daf`, `b826a45a`, `a68cf0bb`]
- 16+ connectors emitting via shared `_emit` helper: snyk_oss, cspm, container_security, crowdstrike_falcon, defender_xdr, edr, sentinelone, siem, dast_pentest, commercial parsers, iam_sso, n8n, threat_intel, defectdojo, sdlc, pull_connector [`a5a08b54`, `0543d17b`, `6996a3fe`, `094b7f79`]
- Connector emit wired on findings/lifecycle, identity/credentials, CTEM/baseline, scanning/discovery, air-gap/local, threat-intel, dev-portal, SBOM paths [`926687aa`, `36c47e75`, `4016668e`, `5021b6ac`, `7593b4c7`, `01ee408b`]
- TrustGraph coverage raised from 24.4% to 38.4% (15.1% direct + 10.6% blast-radius + 12.7% middleware) [`ad453c50`]
- Visualizer updated with AQUA blast-radius color band + HTML topology report [`a68cf0bb`, `b041efc1`, `672bf293`]
- Webhook consumer federation examples (Splunk, Elastic, Slack forwarder) [`fe90b742`]

---

### Backend — LLM Closed-Loop (Phase 1 LIVE)

#### Added
- **LLM Phase 1 closed-loop subscriber** wired to TrustGraph emit events — production live [`cbd01c4d`]
- **703 council verdicts + 703 DPO pairs** populated in `data/learning_signals.db` via real fleet scans (350x growth from 2 to 703 in one session) [`d326da7b`]
- **LLM Phase 2** dataset curator + training scaffold (trl DPOConfig) + inference router (student/council routing) — DRY-RUN validated [`4904309a`]
- Live telemetry endpoint + Brain Pipeline Learning Loop tab dashboard [`f901de22`]
- `learning_signals.db` schema: `council_verdicts` table + `feedback_pairs` table — auto-created on first run, no manual migration [`d326da7b`]
- **AgentDB ↔ TrustGraph bridge** — HNSW vector search over emit events + DPO pairs, 150x speedup over linear scan [`73c05c0d`]
- MiniLM 384-dim semantic embeddings enabled in AgentDB (auto-upgrades from hash fallback) [`65cbbc93`]
- Bulk-reindex of existing AgentDB entries with MiniLM 384-dim embeddings [`a377f3c6`]
- Nightly fleet-scan cron infrastructure (4-step pipeline: ASPM scan → SBOM seed → CSPM seed → curator refresh) targeting 703 → 10K DPO pairs [`f9cf3fe8`]
- Progress checker script with ETA and ASCII bar for DPO growth tracking [`f9cf3fe8`]

---

### Federal / SCIF

#### Added
- **SCIF Stage 1 — Engineering (8/8 deliverables, 12/12 tests pass)**:
  - FIPS boot wired into FastAPI startup sequence [`69efa330`]
  - UBI9-hardened Iron Bank Dockerfile + SoftHSM PKCS#11 module [`1159ef49`]
  - Tamper-evident audit chain (SHA-256 chained log entries) [`1159ef49`]
  - Air-gap bundle script (offline `.tar.gz` with all deps, pip cache, models) [`1159ef49`]
  - Cosign image signing — closes SCIF Stage 1 blocker #2 [`aba22fff`]
  - ISSO Pilot Bundle README + STIG runbook + LLM air-gap verification script [`69efa330`]
  - All-on-prem LLM verification path (vLLM canonical, Ollama dev convenience) [`69efa330`]
- **SCIF Stage 2 — Auditor Documentation**:
  - System Security Plan (SSP), POA&M, NIST 800-53 Rev 5 control matrix (CSV), threat model, crypto datasheet, auditor quick-reference — 95% of in-scope controls implemented [`20ef9510`]
- **SCIF Stage 3 — Federal Sales**:
  - Target list (36 program sponsors), cold outreach (4 templates), discovery playbook, pilot SOW, reference architecture [`43f73eb3`]
  - Fully-automated Day 1 ISSO install script + smoke test [`2ee6e8ed`]

---

### Sales / Marketing / GTM

#### Added
- Pitch deck (12 slides) + one-pager + objection-handling guide + 7 battle cards [`bb35e502`]
- Demo script (Command → Brain → Compliance arc) + POC template + customer onboarding playbook + win/loss template [`68c0130e`]
- Analyst pack: MQ/Wave brief, ref-arch whitepaper, case-study template, anti-customer profile [`c0df3e0e`]
- Master investor pack + data room index + traction metrics [`a0f15a8b`]
- 7 persona-specific landing page copy files (CISO, DevSecOps Lead, SOC Analyst Tier 1, Compliance Officer, Federal CIO/RMF AO, AppSec Engineer, Cloud Security Engineer) [`bde8b101`]
- 5-minute demo video script + storyboard + recording setup guide [`2c394e24`]

---

### Tooling / Integrations

#### Added
- **ruflo (claude-flow) v3.5.80** integrated — 98 agent templates, AgentDB HNSW, ReasoningBank, SPARC methodology, hive-mind Byzantine consensus, ~70 new skills [`71744c25`]
- Prowler → SecurityFindingsEngine bridge + checkov `--quiet` bugfix [`dea8dd7d`]
- DAST real format parsers (OWASP ZAP + Nuclei) [`1eebfe5a`]
- CrowdStrike Falcon real format parser [`b7043c7e`]
- CSPM real (Prowler + Checkov + Trivy + CloudSploit + Agentless) [`ad727467`]
- AutoFix engine wired to GitHub App PR review (Snyk-parity) [`c76dd7e2`]
- WebSocket event push for real-time dashboard updates [`c1c235be`]
- Graphify code-only build via `.graphifyignore` (excludes docs/raw/markdown) [`dbcf0935`]
- code-review-graph per-directory builds (connectors: 1221n/3054e/50c; scripts: 2518n/5174e/110c) [`a1ad4161`]
- Session docs consolidated into `docs/INDEX.md` + strategic roadmap [`54d1fa4f`]

#### Fixed
- `_*.py` gitignore rule scoped to repo root only (was accidentally excluding `suite-core/connectors/_emit.py`) [`7861f9fe`]
- AWS-key-like fixture in tests replaced with allowlisted `AKIAIOSFODNN7EXAMPLE` [`1018fa22`]
- Dashboard render bug fixed — 5/5 routes show real page content + API calls fire [`07994f29`]
- Bulk-triage: atomic cross-org protection + Pydantic validation [`dcdb590c`]
- CSPM posture score derived from real findings DB (was magic constant) [`d9077c44`]

#### Security
- Dependabot triage: 140 alerts reviewed (2 Critical / 55 High / 59 Medium / 24 Low) [`b8f75738`]
- `dompurify` overridden to `^3.4.1` in aldeci-ui-new [`312a5795`]
- `postcss` bumped 8.5.8 → 8.5.10 [`312a5795`]
- `path-to-regexp` bumped 8.3.0 → 8.4.2 [`4b75180f`]
- `picomatch` bumped 2.3.1 → 2.3.2 [`4b75180f`]
- `follow-redirects` bumped 1.15.11 → 1.16.0 [`4b75180f`]

---

## [Unreleased — pre-0.1.0-alpha] — prior sessions

### Added
- Beast Mode v6 full stack: OMC + everything-claude-code + SwarmClaw + TrustGraph + code-review-graph + ruflo
- 334 backend engines (attack surface, SBOM, evidence, risk scoring, compliance, MPTE, FAIL, LLM council, 8 native scanners)
- 568 API router files (FastAPI, multi-tenant, RBAC enforced)
- 372 frontend pages (React 19, Vite 6, Tailwind v4) — 30 consolidated P3 heroes + 342 legacy routes with redirects
- 32 scanner normalizers, 28+ threat intel feeds, 13 PULL + 7 bidirectional connectors
- Multi-AI consensus engine (Gemini + Claude + GPT-4 + Qwen fallback)
- 12-step Brain Pipeline with cryptographic evidence chain
- MPTE 19-phase pentest orchestration
- Quantum-safe evidence signing (NIST FIPS 203/204/205 PQC)
- 30 personas, 6 RBAC roles, 7 compliance frameworks
- Multi-tenant isolation with org-scoped all APIs
- Real customer onboarding flow (15 famous GitHub apps validated)
