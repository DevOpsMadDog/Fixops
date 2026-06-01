# SPEC-NNN — <Capability / API group title>

- **Status**: DRAFT
- **Owner family**: <e.g. TrustGraph / ASPM / CTEM / CSPM / Council / Pentest>
- **Routers**: `<file_router.py>` (prefix `/api/v1/...`)
- **Engines**: `<engine.py / store.py>`
- **Stores**: `<sqlite db path / table>`
- **Depends on**: <SPEC-xxx, env vars, external services>
- **Last updated**: <YYYY-MM-DD>

## 1. Intent (the why)
<One paragraph: what customer/goal outcome this enables. Tie to the platform north-star.>

## 2. Scope — endpoints
| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| GET | /api/v1/... | ... | api_key_auth | yes (org_id) |

Out of scope: <explicitly list what this spec does NOT cover>

## 3. Data contracts
Request / response shapes per endpoint, including the honest unconfigured path.
```
GET /api/v1/... → 200 {"items":[...], "total":N}  | 503 {"status":"not_configured","detail":"..."}
```

## 4. Functional requirements
- **REQ-NNN-01**: <testable statement>
- **REQ-NNN-02**: ...

## 5. Non-functional requirements
- Latency: <e.g. GET returns < 2s; no synchronous heavy compute on GET>
- Tenancy: <org_id source; cross-org → 404>
- Failure mode: <unconfigured → 503 honest, never 500/hang/fake>

## 6. Acceptance criteria (executable)
- **AC-NNN-01**: `curl ... → expect <status/field>` or `pytest tests/...::test_x passes`
- **AC-NNN-02**: ...

## 7. Debate log (Mysti)
| Date | Mode | Verdict / change |
|------|------|------------------|
| | Debate | |
| | Red-Team | |

## 8. Implementation notes
<Files touched, commit SHA, deviations from spec + why.>
