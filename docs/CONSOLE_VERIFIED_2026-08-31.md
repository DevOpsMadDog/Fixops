# All nine console screens, opened against real data

Every screen in the console, loaded in a real browser against a real tenant: a
120-finding pip-audit scan deduped to 96, a 42,910-node call graph, a completed
pipeline run, and four generated evidence bundles. Not fixtures.

The server ran on `:8001` with its own `FIXOPS_DATA_DIR` **and**
`FIXOPS_BRAIN_DB_PATH`, because sharing a data directory with the `:8000`
container corrupts SQLite — that mistake cost two databases earlier.

## Result

| screen | what it showed | verdict |
|---|---|---|
| **Decide** | 96 assessed, 83% eliminated, 16 actionable, 12 undetermined, 61 asked by symbol | ✅ |
| **Prove** | 4 real bundles, SOC2, 22 controls assessed / 18 effective | ❌ → fixed |
| **Comply** | 94 control gaps across 7 frameworks | ❌ → fixed |
| **Operate** | 1,083 tenants, healthy, storage reachable | ✅ |
| **Declare** | entity types and rules, honestly empty for this tenant | ✅ |
| **Connect** | threat-intel, SIEM adapters, Falcon — three live connector endpoints | ✅ |
| **Ingest** | the real supported-scanner list from the API | ✅ |
| **Triage** | open findings with real CVEs | ✅ |
| **Coverage** | 9/10 capabilities answering | ✅ |

Zero console errors on every screen.

## The two defects, both on the screens that sell the product

**Prove called every signed bundle "unsigned".** `POST /bundles/generate` signs
each bundle — real RSA over the content hash, written to a `.sig.json` sidecar
so a third party can verify it with the public key alone. Its own response says
`signature_valid: True`. The *listing* then hardcoded `signed_by: None,
signature_valid: False` for exactly those bundles, so the console contradicted
the product's flagship claim one screen away from the API that proves it.

Two bundle sources existed — disk YAML manifests, read correctly, and generator
packs, declared unsigned by construction. Every bundle a customer generates comes
from the second. Now reads the sidecar; a missing, empty, malformed, or
other-tenant sidecar still reads "unsigned", because then it genuinely is.

**Comply reported "Open gaps 0" in green against 94 real gaps.**
`/api/v1/compliance/gaps` returns a bare array; the screen read
`.total ?? .gaps?.length ?? 0` and found neither key. A compliance officer
glancing at a green zero concludes they are clean.

This was the **second** time — Operate shipped the identical bug reading
`/api/v1/orgs`, also a bare array, and rendered "Tenants 0" against 1,029
organisations. Fixing the same defect twice in two screens means the third is
coming, so shape handling is now one function: `countOf`, which understands
arrays and envelopes and returns **null**, not 0, when the count is unknown.
Unknown renders as "— not yet known", muted. "0 gaps" and "we could not tell
you" are opposite claims.

## What the sweep did not change

Triage's `byVerdict.act_now ?? 0` and its siblings count a map built from rows
already in hand, so an absent key genuinely means zero findings with that
verdict. Not every `?? 0` is the bug, and rewriting those would have been noise
in a change whose point is honesty.

## Why loading states matter more than they look

Three screens showed a confident `0` while their request was still in flight.
None of those zeros were wrong for long — a second later the real number
arrived. But a dashboard is read at a glance, and the glance often lands during
the load. "0 evidence bundles", "0 control gaps", "0 tenants" are all
statements a customer will act on.
