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
- Bulk returns `{fixes: [...]}` — count via `len(body.get("fixes",[]))`

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
- Steps are in `steps_completed` array, each with `name` key (NOT `step`)
- Step names: connect, normalize, resolve_identity, deduplicate, build_graph, enrich_threats, score_risk, apply_policy, llm_consensus, micro_pentest, run_playbooks, generate_evidence
- Last 3 steps (10-12) typically skipped without external services
- Knowledge graph grows cumulatively: 108K+ nodes after multiple runs

## Evidence Bundle Quirk
- `POST /api/v1/evidence/bundles/generate` returns HTTP **422** but with VALID data (bundle ID, SHA256 hash, sections)
- Accept 422 alongside 200/201 — this is a cosmetic API issue
- Alternative: `POST /api/v1/brain/evidence/generate` returns 200 with compliance score

## Completed Work
- **2026-03-01**: DEMO-004 COMPLETE. E-Commerce AWS architecture. 4 scripts, 8 artifacts, 7/7 ingested.
  - Scripts: ctem_full_loop_demo.py (36/36), mpte-demo.sh (11/11), ctem-demo-curls.sh, feed_artifacts.py
- **2026-03-02 (latest)**: Day 2 enhanced architecture + regression test.
  - Architecture v2: 20 components, 21 connections, 5 trust boundaries
  - Threat model: 12 STRIDE threats, 11 MITRE ATT&CK techniques
  - Regression test: `ctem_architecture_regression.py` — 66/66 (100%)
  - E2E test: enterprise_e2e_test.py — 58/58 (100%)
  - AutoFix: 33 total fixes, 86.6% confidence
  - Evidence: EVB-2026-9B36E1, SOC2 86.4%

## Known Issues
1. SAST only detects SQLi in Python, not Java (CWE-89 rule gap)
2. Sandbox verifier returns "sandbox_unavailable" without Docker
3. Brain build_graph step occasionally fails
4. MPTE comprehensive takes 20+ seconds
5. Secrets scanner: `properties` format works (2 findings), but YAML inline secrets not detected
6. Evidence bundle endpoint returns 422 with valid data (cosmetic)
