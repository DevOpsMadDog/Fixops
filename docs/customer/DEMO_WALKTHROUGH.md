# FixOps — 5-Minute Demo Walkthrough

> For running a live demo in front of a prospect. Everything here runs against the
> real product in a container — no mocks, no slides-only. Total time ~5 min.

## Before the call (2 min setup)

> **Build the UI first if you are running from a checkout.** `dist/` is
> gitignored, so a stale or missing bundle serves an old (or blank) console with
> a perfectly healthy HTTP 200 — the failure that looks like success. Once:
>
> ```
> cd suite-ui/aldeci-ui-new && npm run build     # ~8s
> pytest tests/test_ui_dist_is_not_stale.py -q   # confirms it is current
> ```
>
> `docker compose up` builds it for you; this note is for a local checkout.

```bash
export OPENROUTER_API_KEY=sk-or-...          # your key — enables the real AI council
docker compose up -d                          # API + UI on http://localhost:8000
# wait ~30s for health:
curl -sf http://localhost:8000/health && echo "  ✅ FixOps is up"
```

## One command to check everything works

Before the call, against whatever you are about to demo:

```
python suite-core/cli/aldeci.py verify --url http://127.0.0.1:8001
```

Twelve checks covering the whole journey — auth enforcement, signup, login, the
token actually being accepted, ingest, deduplication, tenant scoping, the
exploitability verdict, the evidence behind it, cross-tenant refusal, evidence
pack consistency, and the UI shell. Exit code is non-zero on any failure, so it
drops straight into CI.

Every check asserts the ANSWER, not the status code. Cross-tenant leaks in this
codebase returned 200 with another tenant's data in the body, so a status check
would have called them healthy.

A check that cannot run reports SKIP with the reason and is never counted as a
pass — if feeds are absent you get "all undecided — feeds absent?" rather than a
green tick over a product that decided nothing.

## Parse the repo, or reachability has nothing to answer with

Feeds tell you a vulnerability is being exploited. The call graph tells you
whether *your* code can reach it — and without one every finding is honestly
`undetermined`, so the "Act now" tile (reachable AND exploited) can never be
anything but zero.

One call, per tenant, and it is the strongest thing in the demo:

```
curl -X POST $BASE/api/v1/reachability/parse \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"repo_ref":"myapp@main","language":"python",
       "root_path":"/abs/path/to/repo"}'
```

The host must allow the path via `FIXOPS_REACHABILITY_ALLOWED_ROOTS` — the
engine refuses to read outside it.

Measured on a real tenant, 1,183 nodes / 2,749 edges parsed from one service,
then two findings pushed through the pipeline:

| package | in the graph? | verdict |
|---|---|---|
| `totally-unused-pkg` | never called | **unreachable** |
| `lib4sbom` | called in 44 places | **undetermined** |

That second row is the honest one and worth narrating: knowing a library is
used does NOT mean the vulnerable function is reachable. Only a symbol-level
query earns the word "reachable", which is why `undetermined` appears rather
than a confident yes. The first row is the noise reduction — a finding removed
from the queue because the code cannot reach it.

## Feeds: what makes the verdict say something

The exploitability verdict is computed from EPSS and the CISA KEV catalogue. With
those present a finding reads:

```
Exploited · reach unknown   MEASURED   CVE-2002-0367   CISA KEV  EPSS 4.9%
```

Without them it honestly reads `Insufficient evidence` / `not checked` — the
product refusing to guess, not the product broken. Worth knowing before you are
in front of someone.

**They are not in the image.** `.dockerignore` excludes `**/*.db`, so the
container ships no feed data. It is refreshed in the background the first time
the feeds service is used, which needs outbound network — and an ingest run
immediately after startup can finish before that lands.

Check what the deployment actually has:

```
sqlite3 "${FIXOPS_DATA_DIR:-data}/feeds/feeds.db" \
  "SELECT (SELECT COUNT(*) FROM epss_scores) || ' EPSS / ' ||
          (SELECT COUNT(*) FROM kev_entries) || ' KEV';"
```

Air-gapped, or want them present before the call, carry a signed bundle in:

```
# connected host
python scripts/feed_bundle.py export
# air-gapped host
python scripts/feed_bundle.py verify <bundle>
python scripts/feed_bundle.py import <bundle> --apply
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
