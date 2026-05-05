# ALDECI Deploy — 2026-05-04 Night

## Deploy Commands Used

```bash
# Already running via deploy_local.sh (idempotent re-run safe)
./scripts/deploy_local.sh --no-browser

# Or to start fresh:
cd /Users/devops.ai/fixops/Fixops
./scripts/deploy_local.sh --no-seed --no-browser

# Stop:
./scripts/deploy_local.sh --stop
```

## URLs

| Service | URL | Status |
|---------|-----|--------|
| UI (Vite dev) | http://localhost:5173 | LIVE (HTTP 200) |
| API | http://localhost:8000 | LIVE (healthy) |
| API Docs | http://localhost:8000/docs | LIVE (HTTP 200) |
| Health | http://localhost:8000/health | `{"status":"healthy"}` |

## Build Verification

- **UI production build**: clean, 3.53s (Vite 6, `suite-ui/aldeci-ui-new`)
- **API routes loaded**: 7,960 routes (`create_app()` verified)
- **API version**: `fixops-api v0.1.0`

## Smoke Test Results

| Check | Result |
|-------|--------|
| `GET /health` | 200 healthy |
| `GET /api/v1/health` | 200 healthy |
| `GET /api/v1/triage/stats` (X-API-Key) | 200 — real data |
| `GET /api/v1/remediation/tasks` (X-API-Key) | 200 — real data |
| `GET /api/v1/app-security/findings` (X-API-Key) | 200 — live finding (finding_id: 0699c5ea...) |
| UI root (http://localhost:5173) | HTTP 200 |

## Auth

- Header: `X-API-Key: <token>`
- Token from: `.env` → `FIXOPS_API_TOKEN`

## Screenshots

- `docs/deploy_smoke_2026-05-04/root.png` — UI root
- `docs/deploy_smoke_2026-05-04/hub1.png` — /discover/vuln-intel
- `docs/deploy_smoke_2026-05-04/hub2.png` — /discover/asset-inventory

## Blockers

None. Both services were already running from prior session. Ports 8000 and 5173 occupied by live ALDECI processes.

## Founder One-Liner

ALDECI is live at http://localhost:5173 — try /discover/vuln-intel or /discover/asset-inventory. API at http://localhost:8000/docs.
