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

## Completed Work
- **2026-03-01**: DEMO-004 COMPLETE. E-Commerce AWS architecture. 4 scripts, 8 artifacts, 7/7 ingested.
  - Scripts: ctem_full_loop_demo.py (36/36), mpte-demo.sh (11/11), ctem-demo-curls.sh, feed_artifacts.py
  - Artifacts in: `.claude/team-state/threat-architect/feeds/` and `threat-models/`

## Known Issues
1. SAST only detects SQLi in Python, not Java
2. Sandbox verifier returns "sandbox_unavailable" without Docker
3. Brain build_graph step occasionally fails
4. MPTE comprehensive takes 20+ seconds
