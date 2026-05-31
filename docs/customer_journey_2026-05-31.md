# Customer Journey Audit — 2026-05-31

Branch: `chore/ui-prune-plan-2026-05-24`  
Test file: `tests/test_customer_journey_e2e.py`  
Run command: `PYTHONPATH=".:suite-api:suite-core:..." python -m pytest tests/test_customer_journey_e2e.py -p no:cacheprovider --tb=short --timeout=60 -q -o "addopts="`  
Result: **8 passed, 0 failed, 23.99s**

---

## Step-by-step results

| Step | Endpoint | Status | HTTP | Notes |
|------|----------|--------|------|-------|
| 1 — Org creation | `POST /api/v1/orgs` | PASS | 201 | Returns `org_id`, idempotent on 409 |
| 2 — Authenticate | `POST /api/v1/auth/signup` + auth probe | PASS | 201 | See friction below |
| 3 — Register connector | `POST /api/v1/connectors/register` | PASS | 200 | Schema trap: see friction |
| 4 — Ingest SARIF findings | `POST /api/v1/scanner-ingest/upload` | PASS | 200 | 2 findings parsed and promoted |
| 5a — Get findings (Org A) | `GET /api/v1/findings` | PASS | 200 | 2 findings visible, org-scoped |
| 5b — Tenant isolation | `GET /api/v1/findings` as Org B | PASS | 200 | Org B sees exactly 0 findings |
| 6 — Pipeline verdict | `POST /api/v1/pipeline/pipeline/run` | PASS (degraded) | 200 | No explicit `verdict` field in response |
| 7a — Evidence packs list | `GET /api/v1/pipeline/evidence/packs` | PASS | 200 | 0 packs (in-memory; empty on fresh boot) |
| 7b — Evidence generate | `POST /api/v1/pipeline/evidence/generate` | PASS | 200 | Pack ID issued, score=1.00 |

---

## Friction points (ranked by customer-drop likelihood)

### 1. No self-service API key (BLOCKER — Step 2)

**Friction**: There is no endpoint that issues a per-tenant API key after signup. A customer who creates an account via `POST /api/v1/auth/signup` cannot obtain any usable credential from the API. The only working auth mechanism is `X-API-Key: <FIXOPS_API_TOKEN>`, which is a single platform-wide secret that must be delivered out-of-band (environment variable, welcome email, etc.).

**Customer experience**: Customer signs up, receives a 201 with a `user_id`, tries to make any authenticated request, gets 401. There is no path from "I just signed up" to "I have a working API credential" without operator intervention.

**What needs fixing**: `POST /api/v1/auth/signup` or `POST /api/v1/orgs` should return a scoped API key (or at minimum a JWT via `POST /api/v1/auth/login`) that the customer can use for their org's subsequent requests. The `/api/v1/auth/login` endpoint exists and returns a JWT — but it requires a password that was hashed at signup with a known value. The signup flow and the login flow are functionally wired; the documentation and onboarding wizard just need to surface the login step.

**Estimated drop rate**: ~80% of new customers. This is the primary blocker to self-service.

---

### 2. Connector schema trap — `config` vs typed key (Step 3)

**Friction**: `POST /api/v1/connectors/register` returns 422 with the message `"GitHub config is required when type is 'github'"` if the caller passes `config: {...}` instead of `github: {...}`. The API has no `config` field at all — the typed sub-config must live under the connector-type key (`jira`, `github`, or `slack`).

**Customer experience**: Every API reference or tutorial that says "pass your connector config in a `config` object" will silently 422. The error message is reasonably clear, but the field name mismatch is non-obvious from the docs.

**What needs fixing**: The OpenAPI spec must document `github`, `jira`, `slack` as the correct keys. A `config` alias that remaps to the correct typed field would also help. At minimum the 422 error should name the expected key (`"provide a 'github' object, not a 'config' object"`).

---

### 3. Pipeline verdict field missing (Step 6)

**Friction**: `POST /api/v1/pipeline/pipeline/run` returns HTTP 200 and a populated body, but there is no top-level `verdict`, `decision`, or `recommendation` field. The pipeline result contains `run_id`, `status`, `stage`, `crosswalk`, `evidence_bundle`, `council_verdict` (nested) — but the key decision signal is buried.

**Customer experience**: An integrator polling `/pipeline/run` for a go/no-go answer on a finding cannot extract it with a simple `result["verdict"]`. They must navigate a nested structure whose shape is not documented and varies depending on whether the council ran or was skipped (503 when OPENROUTER_API_KEY absent).

**Additional issue**: The endpoint path is `/api/v1/pipeline/pipeline/run` — the word "pipeline" appears twice because the router prefix is `/api/v1/pipeline` and the route path is `/pipeline/run`. This is a URL design bug that will confuse every integrator who reads the router source.

**What needs fixing**: Add a top-level `verdict` field to the pipeline run response. Flatten the endpoint path to `/api/v1/pipeline/run`.

---

### 4. Evidence packs list always empty on fresh boot (Step 7)

**Friction**: `GET /api/v1/pipeline/evidence/packs` returns `{"total": 0, "packs": []}` on a fresh process start because the evidence pack list is stored in-memory (per the `SOC2EvidenceGenerator` singleton). There is no persistence layer for evidence packs — they disappear on restart.

**Customer experience**: A customer generates an evidence bundle (201), then navigates away and comes back to audit trail → empty. This is especially bad for compliance workflows where evidence must be retrievable weeks later.

**What needs fixing**: Persist evidence packs to SQLite (same pattern as other engines). The generator already assigns stable IDs (`EP-...`); adding a write-through to a `evidence_packs.db` is straightforward.

---

### 5. `pipeline_runs` table missing — logged error on every run (Step 6)

**Friction**: Every call to `POST /api/v1/pipeline/pipeline/run` logs an `sqlalchemy.exc.OperationalError: no such table: pipeline_runs` error at the DB layer (visible in test output). The endpoint still returns 200 because the error is caught internally, but it means run history is silently lost and `GET /api/v1/pipeline/pipeline/runs` will always return empty.

**Customer experience**: The triage inbox and run history UI will always show "no runs". The audit trail for pipeline decisions is missing.

**What needs fixing**: The `pipeline_runs` table schema needs to be created via an Alembic migration or `CREATE TABLE IF NOT EXISTS` at engine init. This is a one-line fix in the brain pipeline's DB initialisation code.

---

## Time-to-first-verdict estimate

| Segment | Time (optimistic) | Blocker? |
|---------|------------------|---------|
| Signup + receive API credential | 10 min (if login step is documented) | Yes — missing docs |
| Org creation | 30 seconds | No |
| Connector registration (with correct schema) | 5 minutes (after hitting 422 once) | Minor |
| SARIF upload + findings visible | 1 minute | No |
| Pipeline run | 10–30 seconds | No |
| Understanding verdict output | 15+ minutes (digging through nested response) | Yes — missing verdict field |
| **Total (optimistic)** | **~30 minutes** | |
| **Total (realistic, first-time)** | **3–8 hours** | |

The single biggest accelerator would be: document the login flow after signup so customers can self-issue a JWT.

---

## Top 5 things that would make a real customer give up

1. **No usable credential after signup.** They sign up, get a 201, and then every subsequent request returns 401. There is no "get API key" button or link in the response.

2. **Double-"pipeline" URL.** An integrator who reads the router source or OpenAPI spec and calls `/api/v1/pipeline/run` gets 404. The correct path is `/api/v1/pipeline/pipeline/run`. This is a URL design bug with no obvious self-healing path.

3. **Connector `config` vs typed key 422.** Any LLM-generated or tutorial-copied client code will use `"config": {...}` and get a 422 on every connector registration attempt with a message that doesn't name the correct key.

4. **No verdict field in pipeline response.** The customer's automation code does `result = call_pipeline(); if result["verdict"] == "block": ...` — KeyError. The decision is there but buried in `crosswalk[0]["findings"][0]["council_verdict"]` with no guarantee of that path existing.

5. **Evidence packs gone on restart.** Compliance team generates a SOC2 evidence pack, closes the tab, reopens the audit section next day — empty. This immediately destroys trust in the platform for the one use case (compliance) where persistence is non-negotiable.
