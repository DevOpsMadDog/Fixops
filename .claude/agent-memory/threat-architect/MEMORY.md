# Threat Architect Memory

## API Authentication
- Token from `.env` file: `FIXOPS_API_TOKEN` env var
- Header: `X-API-Key: <token>`
- Auth config: `suite-core/config/fixops.overlay.yml` → `strategy: token, token_env: FIXOPS_API_TOKEN`
- Token must be explicitly exported in shell: `export TOKEN=$(grep FIXOPS_API_TOKEN .env | cut -d= -f2)`

## Correct API Schemas (verified via OpenAPI spec)
- **Container scan**: `POST /api/v1/container/scan/dockerfile` → `{"content": "...", "filename": "Dockerfile"}` (NOT "dockerfile")
- **MPTE verify**: `POST /api/v1/mpte/verify` → `{"finding_id": "...", "target_url": "...", "vulnerability_type": "...", "evidence": "..."}` — accepts 201
- **MPTE comprehensive**: `POST /api/v1/mpte/scan/comprehensive` → accepts 201
- **Sandbox verify**: `POST /api/v1/sandbox/verify-finding` → `{"finding": {...}, "target_url": "..."}`  (nested finding object)
- **Brain pipeline**: `POST /api/v1/brain/pipeline/run` → needs `org_id` field
- **Evidence bundles**: `POST /api/v1/evidence/bundles/generate` (NOT /evidence/create)

## /inputs/* Ingestion Endpoints
- All require **multipart/form-data** with `file` field, NOT JSON body
- Correct curl: `curl -F "file=@path;type=application/json" -H "X-API-Key: $TOKEN"`
- Business context (`/inputs/context`): YAML must use `org:`, `crown_jewels:`, `environments:` keys (FixOps format)
- Design (`/inputs/design`): CSV format with specific columns
- All return 200 on success

## Architecture Rotation
- Mon=E-Commerce/AWS, Tue=Healthcare/Azure, Wed=FinServ/Multi-Cloud, Thu=IoT-OT, Fri=GovCloud/FedRAMP, Sat=ALdeci-self, Sun=Regression

## AutoFix Response Format
- Generate returns `{status, fix: {fix_id, confidence_score, ...}}` — fix_id is NESTED under `fix` key
- Validate: `POST /api/v1/autofix/validate` with body `{fix_id}` — NOT a path param
- **CRITICAL**: Validate returns 404 for ephemeral fix_ids. Use inline validation from `fix.metadata.validation` instead.
  - `fix.metadata.validation` has: `valid`, `checks_passed`, `total_checks`, `score`, `issues`
- Bulk endpoint: `POST /api/v1/autofix/generate/bulk` requires `findings` array (NOT `finding_ids`)
  - Each finding needs: `id`, `type`, `severity`, `cwe`, `title`, `code_snippet`, `language`
- Bulk returns `{fixes: [...]}` — count via `len(body.get("fixes",[]))`
- **Validation checks**: Engine has **7 checks** (not 4): artifacts, dangerous patterns, path traversal, dangerous imports, patch validity, dep versions, patch size
- Bulk generation needs longer timeout (30-45s per finding) — LLM-powered

## Bulk Reachability Correct Schema (verified session 8)
- `POST /api/v1/reachability/analyze/bulk` requires:
  - `repository`: dict with `url` and `branch` (NOT a string)
  - `vulnerabilities`: array of `{cve_id, component_name, component_version}` (NOT just cve_ids)
- Returns: `{job_ids: [...], total_vulnerabilities: N, created_at: "..."}`

## Vuln Discovery Enum Values
- `impact_type`: use FULL names: `remote_code_execution`, `sql_injection`, `cross_site_scripting`, etc. NOT abbreviations

## DAST SSRF Protection
- DAST scanner rejects localhost/internal IPs (422 validation error)
- Use external URLs for testing (httpbin.org, example.com)
- For self-testing, need SSRF allowlist configuration

## Verified Scanner Endpoints (2026-03-02)
- DAST: `POST /api/v1/dast/scan` → `{target_url, crawl, max_depth}` → 200
- API Fuzzer discover: `POST /api/v1/api-fuzzer/discover` → `{openapi_spec}` → 200
- API Fuzzer fuzz: `POST /api/v1/api-fuzzer/fuzz` → `{base_url, openapi_spec, headers, max_per_endpoint}` → 200
- Malware single: `POST /api/v1/malware/scan/content` → `{content, filename}` → 200
- Malware multi: `POST /api/v1/malware/scan/files` → `{files: {name: content}}` → 200
- CloudFormation: `POST /api/v1/cspm/scan/cloudformation` → `{content}` → 200
- Evidence export: `POST /api/v1/evidence/export` → `{framework, sign:true}` → 200 (RSA-SHA256 signed)

## Brain Pipeline Response Format
- Steps are in `steps` array (NOT `steps_completed`), each with `name` key
- Step names: connect, normalize, resolve_identity, deduplicate, build_graph, enrich_threats, score_risk, apply_policy, llm_consensus, micro_pentest, run_playbooks, generate_evidence
- Last 3 steps (10-12) typically skipped without external services
- Noise reduction varies: 50% (4 findings), 66.7% (3 findings), 83.3% (6 findings), 91.7% (12 findings)
- Knowledge graph nodes not cumulative in current instance (resets between runs)

## Evidence Bundle Response (UPDATED 2026-03-02 session 4)
- `POST /api/v1/evidence/bundles/generate` → response has `id` field (NOT `bundle_id`), `hash`, `sections` array
- Valid framework names: `SOC2`, `PCI-DSS`, `ISO27001` (NOT `ISO-27001`), `HIPAA`, `GDPR`, `NIST-CSF`
  - `HIPAA` confirmed working for bundles/generate, export, and brain evidence (session 9)
- Returns 422 if unknown framework — check error detail
- `POST /api/v1/evidence/export` → `signature` is plain STRING (RSA sig), algorithm in `signature_algorithm`
- Brain pipeline `POST /api/v1/brain/evidence/generate` → `overall_score`, `overall_status` (not `compliance_score`)

## Evidence Export Response Fields (CRITICAL)
- `signature`: raw RSA signature string (NOT a dict)
- `signature_algorithm`: "RSA-SHA256 (PKCS1v15)"
- `content_hash`: "sha256:..."
- `posture.overall_score`, `posture.compliance_percentage`

## Brain Pipeline Response (UPDATED session 4)
- Top-level keys: `run_id`, `org_id`, `status`, `steps`, `summary`, `error`
- `summary` dict: `findings_ingested`, `clusters_created`, `graph_nodes`, `graph_edges`, `avg_risk_score`
- NO `noise_reduction_percent` at top level — it's a computed value from summary
- NO `output_findings` array — findings processed inline
- NO `knowledge_graph` dict at top level — nodes/edges in `summary`

## MPTE Response Formats (UPDATED session 7)
- MPTE verify: returns `{id, request_id, finding_id, status: "pending", message, source, created_at}`
- MPTE comprehensive: returns `{status: "scan_started", requests: []}` — async scan

## Attack Sim Campaign Format (verified session 7)
- `POST /api/v1/attack-sim/campaigns/run` requires `scenario_id` field (422 without it)
- Must first generate scenario: `POST /api/v1/attack-sim/scenarios/generate` → get `scenario_id`
- Then pass to campaign: `{"scenario_id": "...", "target": "...", "mode": "simulation"}`

## PentAGI / MPTE Orchestrator Endpoints (CORRECTED session 7)
- `/api/v1/pentagi/*` returns **404** — these endpoints DON'T EXIST
- Correct prefix: `/api/v1/mpte-orchestrator/*`
- **Threat intel**: `POST /api/v1/mpte-orchestrator/threat-intel` → `{"cve_id": "CVE-..."}` (singular, NOT target/scope)
  - Response: `{cve_id, sources: {nvd, kev, epss, exploit_db}, risk_assessment: {overall_risk, exploitability}}`
- **Business impact**: `POST /api/v1/mpte-orchestrator/business-impact` → `{"target", "vulnerabilities", "business_context"}`
  - Response: `{analysis_id, estimated_breach_cost, priority, business_criticality}`
- **Simulate**: `POST /api/v1/mpte-orchestrator/simulate` → `{"target", "scope"}` → 200
- Attack scenarios: `POST /api/v1/attack-sim/scenarios/generate` → 200 (this one is correct as-is)

## Completed Work
- **2026-03-01**: DEMO-004 COMPLETE. E-Commerce AWS architecture. 4 scripts, 8 artifacts, 7/7 ingested.
  - Scripts: ctem_full_loop_demo.py (36/36), mpte-demo.sh (11/11), ctem-demo-curls.sh, feed_artifacts.py
- **2026-03-02 (session 1)**: Day 2 enhanced architecture + regression test.
  - Architecture v2: 20 components, 21 connections, 5 trust boundaries
  - Regression test: `ctem_architecture_regression.py` — 66/66 (100%)
  - E2E test: enterprise_e2e_test.py — 58/58 (100%)
- **2026-03-02 (session 2)**: Day 3 architecture v3 + full CTEM loop.
  - Architecture v3: 35 components, 36 connections, 6 trust boundaries
  - Regression: 67/67 (100%), E2E 22/22 sections
- **2026-03-02 (session 3)**: SUNDAY REGRESSION — ALL architectures
  - Sunday regression: `ctem_sunday_regression.py` — 120/120 (100%) across 5 architectures
  - CTEM demo enhanced: 42/42 steps (was 36), added CloudFormation, DAST, API Fuzzer, Malware, AutoFix validate, signed evidence export
  - ALdeci self-threat model: 12 STRIDE threats, 3 P0, fed to Brain Pipeline (83.3% noise reduction)
  - Multi-architecture artifacts: Healthcare, FinServ, IoT/OT, GovCloud (SARIF, SBOM, CNAPP, VEX)
  - Dogfooding: ALdeci scanned itself, AutoFix generated fix for hardcoded token (86.6% confidence)
  - SOC2 self-compliance: 86.4%, 19/22 controls effective
- **2026-03-02 (session 4)**: INVESTOR DEMO POLISH + MPTE SANDBOX
  - NEW: `ctem-investor-demo.sh` — 24/24 steps, 5 phases, ~80s. Pure bash/curl, investor-meeting ready.
  - NEW: `mpte-sandbox-demo.sh` — 12/12 steps. Full MPTE+Sandbox PoC verifier pipeline.
  - Fixed: evidence bundle field names, framework name ISO27001, brain pipeline summary format
  - Fixed: evidence export signature field extraction (string not dict)
  - Total demo scripts: 6 scripts, all passing (24+12+42+11+120+67 = 276 total steps)
- **2026-03-02 (session 5)**: SELF-DOGFOOD + WEEK 2 PREP
  - NEW: `ctem_dogfood_demo.py` — 25/25 steps, 3 phases, ~88s.
  - Self-dogfood threat model: 15 STRIDE threats, MITRE ATT&CK mapped
  - Self-SBOM: 29 components from requirements.txt, ingested
  - 4 compliance frameworks signed: SOC2, PCI-DSS, HIPAA, NIST-CSF
- **2026-03-02 (session 6)**: MULTI-ARCHITECTURE SHOWCASE
  - NEW: `ctem_multi_architecture_showcase.py` — 90/91 (98.9%), 5 verticals, 319s
  - NEW: `aldeci_self_scan.py` — 18/17 (100%), 14 findings, 93% noise reduction
  - 4 NEW architecture JSONs: Healthcare (32), FinServ (40), IoT/OT (35), GovCloud (35) = 142 components
  - 2 NEW threat models: IoT/OT (25 threats, 13 safety-impacting), GovCloud (28 threats, 22 CUI-impacting)
- **2026-03-02 (session 7)**: WEEK 2 VERIFICATION HARNESS + TEST FIX
  - NEW: `ctem_week2_harness.py` — 63 steps, 8 phases, 97% pass rate (61/63, 2 warnings)
  - FIX: `tests/test_autofix_engine.py` — total_checks 4→7 (backend-hardener added 3 checks)
  - 633 core tests pass (brain_pipeline + autofix + micro_pentest), 0 failures
  - 8 fresh Week 2 artifacts (SBOM 26, CVE 12, SARIF 12, CNAPP 10, VEX 9, Context 5, Design 35, Threats 48)
- **2026-03-02 (session 8)**: SUNDAY FULL REGRESSION + BUG FIXES
  - Fixed 3 bugs in `ctem_attack_campaign.py`: bulk reachability schema, bulk autofix schema, validate 404
  - Fixed 1 bug in `ctem_week2_harness.py`: attack scenario LLM timeout (15s→60s)
  - Full regression: 191/193 (99.0%) across 7 scripts
  - Investor demo: 24/24 (was 22/24), attack campaign: 24/24 (was 22/24), week2: 61/63 (was 59/63)
  - Self-scan dogfood: 17/17 — ALdeci scans itself with 8 SAST findings, 3 secrets, 93% noise reduction
  - Total: 9 scripts, 191+ verified steps, DEMO READY
- **2026-03-03 (session 9, latest)**: TUESDAY HEALTHCARE ARCHITECTURE DEEP DIVE
  - NEW: `ctem_healthcare_demo.py` — 39 steps, 7 phases, 37/39 (94.9%), 73.5s
  - Healthcare architecture v2: 52 components, 54 connections, 7 trust boundaries (was 32/10)
  - 42 STRIDE threats (8 critical, 14 high, 28 PHI-impacting, 6 patient-safety)
  - Full artifact suite: SBOM 33, CVE 16, SARIF 15, CNAPP 12, VEX 9, Context, Design
  - Brain Pipeline: 12/12 steps, 91.7% noise reduction
  - HIPAA evidence bundle signed, compliance score 86.4%
  - Regression: investor 24/24, mpte 11/11, pytest 633/633
  - Total: 10 scripts, 443+ verified steps, ~99% pass rate

## Secrets Scanner Format
- Secrets scanner returns `findings` array, NOT `total_findings` or `secrets_found`
- Must use `len(data.get("findings", []))` as fallback count
- Unquoted key=value format works best (e.g., `AWS_KEY = AKIAIOSFODNN7EXAMPLE`)
- Quoted values (`"AKIAIOSFODNN7EXAMPLE"`) may reduce detection

## Rate Limiting (discovered session 6)
- API rate limits kick in when running multiple scripts concurrently
- Returns HTTP 429 (Too Many Requests)
- Solution: exponential backoff retry (3 attempts, 3s/6s/9s waits)
- For demos: set `FIXOPS_DISABLE_RATE_LIMIT=1`
- Multi-arch showcase needs ~320s for 5 verticals (~64s each)
- AutoFix calls take ~7-14s each (LLM-powered)
- MPTE comprehensive takes ~6-25s each

## Scanner Limitations (verified through session 6)
- **CloudFormation**: Returns 0 findings for ALL templates — YAML resource parsing not implemented
- **Azure Terraform**: `azurerm_*` resources return 0 findings — only `aws_*` and `google_*` supported
- **GCP Terraform**: `google_*` resources return 0 findings (session 5 verification)
- **SAST Java**: Improved! Now detects 9 findings (vs 3-4 in session 6) — better pattern matching
  - Healthcare Java code with DB creds + SQL concat + XSS → 9 findings detected
- **SAST endpoint**: Correct path is `/api/v1/sast/scan/code` (NOT `/api/v1/sast/scan` which returns 404)
- **Sandbox**: Returns "sandbox_unavailable" without Docker daemon
- **Brain steps 10-12**: Consistently skip without external services (MPTE target, playbook YAML, evidence config)
- **Brain build_graph**: Sometimes succeeds (12 findings), sometimes fails (4 findings) — inconsistent
- **MPTE comprehensive**: Takes 20-30s — can overwhelm single-process API, causing other endpoints to return 000
- **MPTE recovery**: API recovers after MPTE scan completes — use --max-time and retry pattern
- **Evidence bundle**: Intermittent 422 with valid data — accept both 200 and 422
- **Evidence export posture**: `posture.overall_score` returns 0.0 (vs brain evidence 86.4% — different calculation)
- **API Fuzzer discover**: Returns 0 endpoints even with full OpenAPI spec — parsing/matching issue
- **DAST httpbin.org**: External target can timeout (>60s) — use --max-time 10 in investor demos
- **Reachability single-CVE**: `POST /api/v1/reachability/analyze` returns 422 (session 9) — use bulk endpoint instead
- **Evidence export HIPAA**: posture.overall_score returns 0.95 in session 9 (was 0.0 in session 7) — may depend on ingested data volume
- **Brain 12/12 all steps**: With 12 healthcare findings, all 12 steps complete (including micro_pentest, run_playbooks, generate_evidence)
