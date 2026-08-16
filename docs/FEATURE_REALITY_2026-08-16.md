# FixOps — what the product is built for, and what is actually there

**Method.** Every number below came from a tool run or a live HTTP call against the
running container. Nothing is inferred from documentation. Where a claim in our own
docs did not survive testing, the measurement is what is recorded here.

The deep pass ran in three layers:

1. **Structure** — `Understand-Anything` (`Egonex-AI/Understand-Anything`) deterministic
   phases over the repo: 17,831 files, 16,691 code files, verdict `very-large`,
   **801 LLM batches** required for a full semantic pass.
2. **Code** — AST extraction of every engine class and its public surface.
3. **Behaviour** — one representative parameterless `GET` per `/api/v1` domain, **745 in
   total**, each called twice: once as tenant `default`, once as a tenant that does not
   exist. Comparing the two responses is what separates real customer data from a
   catalogue that looks like data.

---

## 1. The headline

| | Count | Share |
|---|---|---|
| API domains probed | **745** | |
| Responded `200` | **720** | 97% |
| Return data that **differs per tenant** — genuinely wired to customer data | **168** | 22% |
| Return the **same bytes for every tenant** — catalogue, status, reference | **396** | 53% |
| Respond correctly but the collection is **empty** — awaiting ingestion | **140** | 19% |
| Say honestly they have **no credentials** configured | **16** | 2% |
| **Broken** (5xx / 404 / bad request) | **25** | 3% |

**The product's real surface is the 168.** The 396 are not fake — a scanner-rule
catalogue *should* be identical for every tenant — but they are also not the product
working; they are the product describing itself.

Cross-referenced against the UI: **374 of 745 domains (50%) have a UI callsite**; the
other 371 are reachable only by someone holding the API spec.

---

## 2. The sixteen capability families, measured

Families are as defined in `docs/BIG_PICTURE_2026-06-01.md`. **REAL** = tenant-varying
data. **EMPTY** = correct response, nothing ingested yet. **CATLG** = identical for all
tenants. **CREDS** = honestly reports no API key. **BAD** = 5xx/404/4xx.

| Capability family | N | REAL | EMPTY | CATLG | CREDS | BAD | UI |
|---|---:|---:|---:|---:|---:|---:|---:|
| 1 SAST / SCA / Secrets | 15 | 2 | 2 | 11 | 0 | 0 | 6 |
| 2 DAST / API Security | 13 | 1 | 0 | 12 | 0 | 0 | 6 |
| 3 Container / IaC / Supply chain | 31 | 6 | 4 | 19 | 0 | 2 | 18 |
| 4 Cloud Security / CSPM | 43 | 5 | 7 | 29 | 1 | 1 | 19 |
| 5 Identity / CIEM / PAM | 29 | 5 | 6 | 17 | 0 | 1 | 18 |
| 6 Threat Intelligence | 31 | 8 | 6 | 13 | 3 | 1 | 15 |
| **7 Vuln Mgmt / Risk Scoring** | **59** | **25** | 14 | 19 | 0 | 1 | **39** |
| 8 IR / SOAR / SOC | 32 | 7 | 7 | 16 | 0 | 2 | 18 |
| 9 Compliance / Evidence | 43 | 8 | 12 | 22 | 0 | 1 | 24 |
| 10 Attack Sim / Red Team / MPTE | 23 | 6 | 5 | 12 | 0 | 0 | 13 |
| **11 Posture / Analytics** | **43** | **14** | 13 | 12 | 2 | 2 | 24 |
| 12 Connectors / Integrations | 24 | 2 | 2 | 15 | 0 | 5 | 5 |
| 13 Multi-LLM Council / AI | 20 | 5 | 2 | 12 | 1 | 0 | 8 |
| 14 TrustGraph / Knowledge graph | 12 | 4 | 1 | 6 | 0 | 1 | 7 |
| 15 Zero Trust / Network / Endpoint | 26 | 7 | 4 | 15 | 0 | 0 | 15 |
| 16 Platform / Auth / Admin | 21 | 4 | 3 | 10 | 1 | 3 | 9 |
| unclassified | 280 | 59 | 52 | 156 | 8 | 5 | 130 |
| **TOTAL** | **745** | **168** | **140** | **396** | **16** | **25** | **374** |

### Reading the table

**Family 7 (Vulnerability Management / Risk Scoring) is the product.** 59 domains, 25
returning real tenant data, 39 with UI — the highest on every axis. Ingest → dedup →
enrich → score → triage → case is the one path where a customer's data flows end to end.
Family 11 (Posture / Analytics) is second, because it reads from Family 7.

**Families 1 and 2 are the weakest relative to their promise.** SAST/SCA shows 2 real of
15, DAST/API 1 of 13 — almost entirely catalogue. This is expected for an ingest-first
product (we consume other scanners rather than running our own), but it means the
"SAST" and "DAST" labels oversell: what exists is a *normalizer* for those tools'
output, not a scanner. The honest description is "bring your Semgrep/Snyk/ZAP results".

**Family 12 (Connectors) carries all 5 remaining breakages** and only 5 UI callsites of
24. Every connector needs customer credentials, so empty is correct — but they should
say so rather than 503.

---

## 3. What is genuinely real (verified live)

| Capability | Evidence from the running system |
|---|---|
| Threat enrichment | 1,665 CISA KEV CVEs (20.96% ransomware-linked), 360,142 FIRST EPSS scores, 2,000 NVD CVEs |
| Pipeline enrichment | `enrichment_source="real_api"`, `kev_matches=1`, `epss_api_hits=1` |
| AI council | 5 cross-vendor models, `providers_responded=5`, real `cost_usd`, `source=consensus` |
| Copilot | `source=llm_grounded_live_data` — answers name the tenant's actual findings |
| Quantum-safe evidence | `dilithium-py` **installed** — ML-DSA-65 signing is real, not an RSA fallback |
| TrustGraph | 5 knowledge cores, 250 rows in the live store |
| MPTE | 34 steps executed on a real run |
| Tenant isolation | UAT: org B sees 0 of org A's findings |
| Auth | unauthenticated request → 401 across the board |

### And what is not

| Claim | Measured reality |
|---|---|
| MindsDB self-learning | **0 API routes.** The container runs; nothing is wired to it. Genuinely absent. |
| MPTE runs by default | **Opt-in.** `run_pentest: bool = False`; step 10 is skipped unless explicitly requested. |
| "SAST / DAST scanning" | Normalizers for other tools' output, not scanners. 2 of 15 and 1 of 13 domains carry tenant data. |
| 464 engines of capability | 544 engine classes exist and all carry docstrings, but **104 of 464 `*_engine.py` have no persistence layer at all** — they compute, they do not remember. |

---

## 4. What was broken, and is now fixed

All four found by this audit, each verified live before and after.

**1 — The Docker image shipped our own data.**
`COPY suite-*/` swept 53 local `*.db` files (~80 MB, dated April–June) into the image,
carrying 1,425 deduplication clusters and 3,047 events from our own dogfooding runs. A
customer's fresh install would have opened onto our findings. `.dockerignore` now
excludes databases; the policy bundles under `suite-api/data/policies/` stay, because
those are genuine reference data.

**2 — The data directory was not anchored.**
Engines bind their SQLite paths at import time from `FIXOPS_DATA_DIR`, whose default was
*relative* — so the store followed whatever directory the process started in. Measured
in-container: **49 database names existed in two locations, 13 with genuinely diverged
data**:

| Database | Copy A | Copy B |
|---|---:|---:|
| `clusters.db` (deduplication) | **5,898 rows** | **0 rows** |
| `feeds.db` | 329,388 | 363,810 |
| `trustgraph.db` | 38 | 250 |
| `fixops_brain.db` | 364 | 74 |
| `cve_enrichment.db` | 100 | 0 |

Anchored in **both** `sitecustomize.py` and `app.py` — a Python install that ships its
own stdlib `sitecustomize` shadows the repo's copy, so the repo hook alone is not
enough. (Verified: Homebrew's Python does exactly this.)

**3 — `GET /api/v1/tenants` listed platform storage as tenants.**
`list_tenants()` returned every subdirectory of the shared data root, so an admin saw 20
"tenants" — `backups`, `keys`, `evidence`, `uploads`, `deduplication` — and not one real
customer. `delete_tenant_data()` resolves the chosen name straight to a path and calls
`shutil.rmtree`, so deleting the "backups" entry an admin was shown would have destroyed
the platform's backups. Tenant directories now carry a marker file; deletion refuses
anything without one. Live result: `{"tenants": [], "count": 0}` — correct, because no
real tenant directories exist yet.

**4 — Two endpoints 500'd on a path off-by-one.**
`Path(__file__).resolve().parents[4]` from `suite-api/apps/api/` overshoots the repo root
onto `/`, so `security-maturity` and `threat-correlation` tried to `mkdir /.fixops_data`
and died with `PermissionError`. Exactly two files used `parents[4]`, and they were
exactly the two failing endpoints. Both now use the anchored data directory.
`/changelog/recent` returned 500 because it shells out to `git`, which the runtime image
does not ship — an absent optional source, now a 503 that says so.

**5 — EPSS was two products, and the reachable one was empty.**
`/api/v1/epss/*` carries its own importer writing a standalone `data/epss.db` with a
different schema (`epss_score`/`imported_at`) from the feed sync's `feeds.db`
(`epss`/`date`). Only the feed sync is ever run, so the platform held **360,142 EPSS
scores** while `GET /api/v1/epss/scores` returned an empty list — for the same CVE that
`GET /api/v1/feeds/epss` scored at 0.99999. Reads now serve the canonical store and fall
back to the standalone one when it is absent. Live after: `total: 360142`, correct
scores, unknown CVEs still 404.

Live after all five: `503 / 200 / 200`, `/tenants` returns 0 instead of 20 fabrications,
EPSS returns 360,142 instead of 0, **UAT 11/11**, app boots with 7,940 routes.
Regression tests added for the store-splitting and tenant-deletion classes (10 tests, all
passing, and they fail against the old code).

---

## 5. What remains

Ordered by what a customer would notice first.

**Still broken (21 domains).** Ten are 503s from connectors with no credentials
(`github`, `harbor`, `hashicorp-vault`, `kong`, `n8n`, `servicenow`, `elasticsearch`,
`deployment`, `guardrails`, `license`) — correct behaviour, wrong status code; these
should report "not configured" like the 16 domains that already do. Four are 404s on
routes that should exist (`changes/health`, `k8s/rbac`, `posture-benchmark/latest`,
`workflows/stats`).

**140 empty domains.** Every one is a real engine with no data yet. Most resolve through
ingestion rather than code, not all of them are genuinely empty — see defect 5 below for
one that was empty only because it read the wrong store.

**371 domains with no UI.** Half the backend is unreachable from the product.
`FIXOPS_CORE_MODE=1` already hides them from the API spec and the navigation;
`docs/DORMANCY_PLAN_2026-08-16.md` covers unmounting the ~290 engine-domain orphans.

**91 files still hardcode relative database paths**, ignoring `FIXOPS_DATA_DIR`
entirely. The anchoring fix does not reach them; they are correct today only because
every supported deployment starts from the app root. This is the remaining tail of
defect 2 and the most likely source of the next split store.

**MindsDB is not wired.** If self-learning via MindsDB is part of the pitch, it is
currently a claim with zero routes behind it. The DPO loop and ReasoningBank are real;
MindsDB is not.

---

## 6. The honest summary

The product is **ingest → dedup → enrich → score → triage → decide → evidence**, and
that path works end to end against real data with a real five-model council and real
threat feeds. It is Family 7 plus Family 11, roughly 100 domains, and it is genuinely
good.

Around it sit ~600 domains of breadth that respond correctly, hold no customer data, and
have no screen. They were built for competitor parity. They are not lies — they are
honest, idle scaffolding — but every one of them is surface a buyer can poke and find
hollow.

The work that remains is not building. It is **narrowing**: ship the 100 that work, hide
the rest until something reaches them, and fix the 21 that are actually broken.
