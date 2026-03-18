# Skill: Multi-Tenancy — org_id Tenant Isolation

> How to add tenant isolation to every endpoint so Org A cannot see Org B's data.

## Current State (2026-03-17)
- 15/68 routers (22%) enforce `org_id`
- 53 routers have NO tenant isolation
- Auth is on ~95%+ endpoints (good), but auth ≠ tenant isolation

## The Pattern — get_current_org Dependency

### Step 1: The dependency (add to suite-api/apps/api/dependencies.py)
```python
from fastapi import Depends, HTTPException, Request

async def get_current_org(request: Request) -> str:
    """Extract org_id from authenticated user's JWT claims.
    
    Every data-returning endpoint MUST depend on this.
    Admin endpoints (admin:all scope) may bypass via get_current_org_or_admin.
    """
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    org_id = user.get("org_id") if isinstance(user, dict) else getattr(user, "org_id", None)
    if not org_id:
        raise HTTPException(status_code=403, detail="No organization context in token")
    
    return org_id


async def get_current_org_optional(request: Request) -> str | None:
    """For admin endpoints that may cross org boundaries.
    Returns org_id if present, None if admin with no org context."""
    user = getattr(request.state, "user", None)
    if not user:
        return None
    return user.get("org_id") if isinstance(user, dict) else getattr(user, "org_id", None)
```

### Step 2: Add to every data endpoint
```python
from apps.api.dependencies import get_current_org

@router.get("/findings")
async def list_findings(
    org_id: str = Depends(get_current_org),
    status: str = None,
    severity: str = None,
):
    # ALL queries MUST filter by org_id
    async with DatabaseManager.get_session() as session:
        query = select(Finding).where(Finding.org_id == org_id)
        if status:
            query = query.where(Finding.status == status)
        result = await session.execute(query)
        return result.scalars().all()


@router.post("/findings")
async def create_finding(
    body: CreateFindingRequest,
    org_id: str = Depends(get_current_org),
):
    # ALL inserts MUST include org_id
    finding = Finding(org_id=org_id, **body.dict())
    async with DatabaseManager.get_session() as session:
        session.add(finding)
        await session.commit()
        return finding


@router.get("/findings/{finding_id}")
async def get_finding(
    finding_id: str,
    org_id: str = Depends(get_current_org),
):
    # Single-item lookups MUST verify org_id matches
    async with DatabaseManager.get_session() as session:
        finding = await session.get(Finding, finding_id)
        if not finding or finding.org_id != org_id:
            raise HTTPException(404, "Finding not found")
        return finding
```

### Step 3: For legacy sqlite3 code (pre-migration)
If the endpoint still uses raw sqlite3 (pending DEFECT 1 migration):
```python
@router.get("/legacy-data")  
async def list_legacy(org_id: str = Depends(get_current_org)):
    conn = sqlite3.connect("data/domain.db")
    cursor = conn.cursor()
    # ADD org_id filter to EVERY query:
    cursor.execute("SELECT * FROM items WHERE org_id = ? ORDER BY created_at DESC", (org_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows
```

## Which Routers Need It

### Already have org_id (15 routers — verify they use Depends pattern):
```bash
grep -rl "org_id" suite-api/apps/api/*_router.py | sort
```

### All routers that need org_id added (53 routers):
```bash
# List routers WITHOUT org_id:
comm -23 <(ls suite-api/apps/api/*_router.py | sort) <(grep -rl "org_id" suite-api/apps/api/*_router.py | sort)
```

## Exceptions — Endpoints That Don't Need org_id

| Endpoint | Reason |
|----------|--------|
| `GET /api/v1/health/*` | System health — no tenant data |
| `POST /api/v1/auth/login` | Login — org_id comes FROM this call |
| `POST /api/v1/webhooks/receive` | Webhook ingress — uses signature verification |
| `GET /openapi.json` | API docs — no tenant data |
| Admin endpoints with `admin:all` scope | Cross-tenant by design — use `get_current_org_optional` |

## Testing Tenant Isolation

```python
# tests/test_tenant_isolation.py
import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_tenant_a_cannot_see_tenant_b_findings(app):
    async with AsyncClient(app=app, base_url="http://test") as client:
        # Create finding as Org A
        resp = await client.post(
            "/api/v1/findings",
            json={"title": "SQL Injection", "severity": "HIGH"},
            headers={"X-API-Key": ORG_A_TOKEN},
        )
        finding_id = resp.json()["id"]

        # Org B cannot see it
        resp = await client.get(
            f"/api/v1/findings/{finding_id}",
            headers={"X-API-Key": ORG_B_TOKEN},
        )
        assert resp.status_code == 404

        # Org B listing doesn't include it
        resp = await client.get(
            "/api/v1/findings",
            headers={"X-API-Key": ORG_B_TOKEN},
        )
        finding_ids = [f["id"] for f in resp.json()]
        assert finding_id not in finding_ids
```

## Validation

```bash
# Count routers with org_id (target: 68 - exceptions):
grep -rl "org_id" suite-api/apps/api/*_router.py | wc -l

# Verify no endpoint returns unfiltered data:
grep -rn "SELECT \*" suite-api/ --include="*.py" | grep -v "WHERE.*org_id\|__pycache__\|test_"

# Run tenant isolation tests:
python -m pytest tests/test_tenant_isolation.py -v --timeout=10
```
