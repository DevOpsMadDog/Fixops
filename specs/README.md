# ALDECI Spec System

Spec-driven requirements for every API (or API group). Each spec is the **contract** that an
implementation must satisfy and a test must verify. Specs are the unit of future extension +
maintenance, designed to be managed in **Augment Code intent IDE** and debated in **Mysti**.

## Why specs (the goal)

ALDECI's north star is an **intelligence platform**: interconnected issues → automated pen-tests →
reachability analysis → all signal into **TrustGraph** → a **per-customer local LLM** that learns.
That vision only stays maintainable if each capability has a written, testable contract. Specs are
how we extend without regressing and onboard future devs (and future agents) instantly.

## Layout

```
specs/
  README.md              # this file — the system + conventions
  TEMPLATE.md            # copy this to start a new spec
  INDEX.md               # registry: spec id → title → status → owner family
  SPEC-001-...md         # one spec per API group / capability
  SPEC-002-...md
```

## Spec lifecycle (status field)

`DRAFT → DEBATED → APPROVED → IMPLEMENTED → VERIFIED → LIVE`

- **DRAFT** — chief architect authors intent + requirements.
- **DEBATED** — run through Mysti **Debate** (architecture) + **Red-Team** (security). Record the
  verdicts/changes in the spec's "Debate Log".
- **APPROVED** — founder/architect sign-off.
- **IMPLEMENTED** — senior developer builds to the spec; links the commit.
- **VERIFIED** — tester proves every acceptance criterion against the running app (not stored tests
  alone — live behaviour, code-as-truth).
- **LIVE** — deployed + smoke-confirmed on the target environment.

## How the IDE tools plug in

- **Augment Code intent IDE**: each `SPEC-NNN-*.md` is an "intent" — Augment reads the Requirements
  (REQ-*) + Acceptance Criteria (AC-*) as the source of truth for code generation/refactor. Keep
  REQ/AC IDs stable so Augment can map code ↔ requirement over time.
- **Mysti (VS Code ext)**: before APPROVED, run the spec through Brainstorm Mode →
  **Debate** (Critic vs Defender — does the design hold?) and **Red-Team** (Proposer vs Challenger —
  what breaks it / security). Paste the spec + the relevant files (`@file`) and record outcomes in
  the Debate Log section.

## Authoring rules

1. Every requirement gets a stable id `REQ-<spec>-NN`; every acceptance criterion `AC-<spec>-NN`.
2. Acceptance criteria MUST be **executable** (a curl/pytest/observable assertion), never "works well".
3. No fake/stub data in an implementation that claims a REQ done — honest 501/503 when unconfigured.
4. Data contracts are explicit (request/response shape, status codes incl the honest 503 path).
5. Every spec names its **engine(s)** and **store(s)** so tenancy + persistence are unambiguous.
6. Cross-tenant: every tenant-scoped REQ states the org_id source + the cross-org expectation (404).

---

## Canonical tenancy pattern (REQ-007-04)

Every router that needs the caller's org must use `Depends(get_org_id)` from the canonical module.
**Never** use `Query(default="default")` or a bare `= "default"` for an org_id parameter.

### Correct pattern

```python
# Always import from ONE of these two canonical locations:
from apps.api.org_middleware import get_org_id      # preferred
# or:
from apps.api.dependencies import get_org_id        # re-export of the above

from fastapi import APIRouter, Depends

router = APIRouter(prefix="/api/v1/my-resource")

@router.get("/")
async def list_resources(org_id: str = Depends(get_org_id)):
    # org_id is now the authenticated tenant — never "default" in prod.
    return db.query(org_id=org_id)
```

### Anti-patterns — the lint gate (scripts/tenancy_lint.py) will FAIL on these

```python
# BAD — V1: Query with a "default" fallback silently accepts any tenant's data
async def list_resources(org_id: str = Query(default="default")):
    ...

# BAD — V1: bare string default, same problem
async def list_resources(org_id: str = "default"):
    ...

# BAD — V2: importing get_org_id from anywhere except the two canonical modules
from core.some_engine import get_org_id   # shadow import

# BAD — V3: defining a local get_org_id that may diverge from canonical logic
def get_org_id() -> str:
    return request.headers.get("X-Org-ID", "default")  # local shadow
```

### Why ContextVar, not threading.local

`TenantContext` (suite-core/core/tenant_isolation.py) uses `contextvars.ContextVar`.
Under asyncio every `Task` inherits a **snapshot** of the current context at creation time
and owns its own copy thereafter — concurrent requests on the same OS thread are fully
isolated.  `threading.local` had a critical bug: all coroutines on the same thread shared
one storage slot, so Request B's `TenantContext.set()` could overwrite Request A's org_id
mid-flight.

### CI gate

`scripts/tenancy_lint.py` scans `suite-api/apps/api` and `suite-core/api` for violations
and compares against `specs/tenancy_allowlist.txt` (frozen debt — **may only shrink**).
Run it locally:

```bash
# Check for new violations (exit 1 if any new ones found):
python scripts/tenancy_lint.py

# After fixing a violation, verify the count drops:
python scripts/tenancy_lint.py --generate-allowlist  # regenerate smaller allowlist
```

Tests:
- `tests/test_tenant_context_asyncio.py` — asyncio isolation proof (AC-007-01)
- `tests/test_tenancy_lint.py` — lint gate correctness (AC-007-02 / AC-007-03)
