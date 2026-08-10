# FixOps — 5-Minute Demo Walkthrough

> For running a live demo in front of a prospect. Everything here runs against the
> real product in a container — no mocks, no slides-only. Total time ~5 min.

## Before the call (2 min setup)
```bash
export OPENROUTER_API_KEY=sk-or-...          # your key — enables the real AI council
docker compose up -d                          # API + UI on http://localhost:8000
# wait ~30s for health:
curl -sf http://localhost:8000/health && echo "  ✅ FixOps is up"
```

## The demo (run this, narrate as it goes)
```bash
FIXOPS_API_TOKEN=aldeci-demo-token python scripts/uat_core.py http://localhost:8000
```
This walks the **entire value path against the live container** and prints a pass line
for each step. Talk track, step by step:

| What prints | What to say |
|---|---|
| `UC8 NAC requires auth (401)` / `UC9 auth enforced` | "Every endpoint is authenticated and tenant-scoped — enterprise-grade from day one." |
| `UC3 ingest SARIF — findings=3` | "We point it at the scanner output you *already* produce — 60+ formats, no agents to deploy." |
| `UC4 findings — 2 findings` (from 3 ingested) | "Location-aware dedup already collapsed the duplicate noise — 3 raw → 2 distinct." |
| `UC5 tenant isolation — leaked=0` | "Strict multi-tenant isolation — org B sees zero of org A's data." |
| `UC6 AI council verdict — source=consensus` | "**This is the moat**: a 5-model cross-vendor AI council (Google, DeepSeek, Qwen, Llama, Anthropic) reaches consensus on what to actually do — and it *never fabricates*. No key, no verdict — it tells you, it doesn't guess." |
| `UC7 evidence bundle available` | "Every decision produces a signed, tamper-evident evidence bundle mapped to your compliance controls — the thing your auditor actually asks for." |
| `UC10 UI served` | "And it's all in a self-hosted UI — running entirely inside your environment. Nothing left your walls." |

## The one-liner to close on
> "Everything you just saw ran in a single container **inside your own perimeter** — no
> cloud, no data egress. That's what Wiz and Snyk structurally can't do, and it's exactly
> what an air-gapped or regulated program needs."

## To show the real council verdict live (optional, ~60s)
```bash
curl -s -X POST http://localhost:8000/api/v1/pipeline/run \
  -H "X-API-Key: aldeci-demo-token" -H "X-Org-ID: demo" -H "Content-Type: application/json" \
  -d '{"findings":[{"id":"1","title":"SQL injection in login","severity":"critical"}],"org_id":"demo"}' | jq '.verdict, .steps[] | select(.name=="llm_consensus") | .output'
```
Point at `providers_responded: 5`, `consensus_pct`, `cost_usd` (proof the models really ran),
and the verdict `decision` + reasoning.

## Verified facts you can state honestly
- 11/11 use cases pass over real HTTP against the container (`scripts/uat_core.py`).
- The 5-model council fires with real cost (~$0.002/run) — genuine multi-vendor consensus, never fabricated.
- Deploys self-hosted in one command; your keys, your data, your perimeter.
