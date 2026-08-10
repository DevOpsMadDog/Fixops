# FixOps — Self-Hosted Deploy Quickstart

> FixOps runs entirely inside your environment. No data leaves your perimeter.
> One container. Works on a laptop, a VM, an on-prem server, or air-gapped.

## Requirements
- Docker + Docker Compose
- (Optional) an `OPENROUTER_API_KEY` to enable the multi-model AI council.
  Without it, FixOps still ingests, dedups, scores, and produces evidence — the
  council step reports `UNVERDICTED` rather than fabricating a verdict.

## 1. Configure (create a `.env`)
```bash
FIXOPS_API_TOKEN=<pick-a-strong-token>        # your API key for all requests
FIXOPS_JWT_SECRET=<32+ random chars>          # session signing
OPENROUTER_API_KEY=sk-or-...                  # optional — enables the AI council
FIXOPS_MODE=enterprise
FIXOPS_USE_COUNCIL=1                           # turn the AI council on
ALDECI_SEED_DEMO=0                            # 0 = no demo data (real customer); 1 = demo
```

## 2. Start
```bash
docker compose up -d
curl -sf http://localhost:8000/health && echo "  ✅ up"     # ~30s to healthy
```
- API + UI: `http://localhost:8000`
- All state persists in Docker volumes (`aldeci-data`, `aldeci-state`).

## 3. Onboard your first tenant + data (the real flow, no seed data)
```bash
TOKEN=<your FIXOPS_API_TOKEN>; ORG=acme

# a) create your tenant
curl -s -X POST http://localhost:8000/api/v1/orgs \
  -H "X-API-Key: $TOKEN" -H "X-Org-ID: $ORG" -H "Content-Type: application/json" \
  -d "{\"name\":\"Acme\",\"org_id\":\"$ORG\"}"

# b) upload your real scanner output (SARIF / Snyk / Trivy / SBOM / 60+ formats)
curl -s -X POST http://localhost:8000/api/v1/scanner-ingest/upload \
  -H "X-API-Key: $TOKEN" -H "X-Org-ID: $ORG" \
  -F scanner_type=sarif -F app_id=my-app -F file=@your-scan.sarif

# c) get the prioritized findings (deduped, tenant-scoped)
curl -s http://localhost:8000/api/v1/findings -H "X-API-Key: $TOKEN" -H "X-Org-ID: $ORG"

# d) run the AI council + get a signed evidence bundle
curl -s -X POST http://localhost:8000/api/v1/pipeline/run \
  -H "X-API-Key: $TOKEN" -H "X-Org-ID: $ORG" -H "Content-Type: application/json" \
  -d '{"findings":[...from step c...],"org_id":"'$ORG'","generate_evidence":true}'
```

## 4. Verify your deployment (optional)
```bash
FIXOPS_API_TOKEN=$TOKEN python scripts/uat_core.py http://localhost:8000
# expect: 11/11 passed
```

## Air-gapped / classified notes
- Set `FIXOPS_AIRGAP_MODE=enforced` to activate the socket-level egress guard
  (blocks all outbound network — the AI council then requires an in-perimeter
  model endpoint via `OPENROUTER_BASE_URL`).
- No telemetry, no external calls in the core path. Your keys, your data, your walls.

## Cloud demo (optional, not the customer path)
A `fly.toml` is included for a hosted demo on Fly.io:
`flyctl auth login && flyctl deploy --remote-only`. The **self-hosted** path above
is the production/customer deployment.
