# Skill: Endpoint Hardening — Mandatory Checklist for Every API Endpoint

> Every endpoint MUST pass this 8-point checklist before it ships.

## The 8-Point Checklist

Every endpoint must have ALL of these:

| # | Check | How to Verify |
|---|-------|---------------|
| 1 | **Auth dependency** | `Depends(_verify_api_key)` at router mount or endpoint level |
| 2 | **Tenant isolation** | `org_id = Depends(get_current_org)` → all queries filter by org_id |
| 3 | **Input validation** | Pydantic model for request body, `Path(..., regex=)` for path params |
| 4 | **Rate limiting** | Global middleware handles most; high-risk endpoints add custom limits |
| 5 | **Typed exceptions** | No bare `except Exception`; use `ALdeciError` hierarchy |
| 6 | **Structured logging** | `structlog` with `correlation_id`, `org_id`, operation name |
| 7 | **Response model** | `response_model=` specified in decorator for OpenAPI docs |
| 8 | **Test coverage** | At least 1 happy-path + 1 error-path test |

## Before You Start: Which Router?

```bash
# Find the router file for a given endpoint:
grep -rn "prefix.*your_prefix" suite-api/apps/api/app.py | head -5
grep -rn "prefix.*your_prefix" suite-core/api/ suite-attack/api/ --include="*.py" | head -5

# Find how the router is mounted:
grep -n "include_router" suite-api/apps/api/app.py | grep -i "your_router"
```

## Pattern: A Fully Hardened Endpoint

```python
from fastapi import APIRouter, Depends, Path, Query, HTTPException
from pydantic import BaseModel, Field, field_validator
from typing import Optional
import structlog
from core.exceptions import ALdeciError, DatabaseError

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])


# --- Request/Response Models ---
class FindingCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    severity: str = Field(..., pattern="^(critical|high|medium|low|info)$")
    description: Optional[str] = Field(None, max_length=10000)
    scanner_type: str = Field(..., min_length=1, max_length=100)

    @field_validator("title")
    @classmethod
    def sanitize_title(cls, v: str) -> str:
        # Strip control characters
        return "".join(c for c in v if c.isprintable())


class FindingResponse(BaseModel):
    id: str
    org_id: str
    title: str
    severity: str
    status: str


# --- Endpoints ---
@router.post(
    "/",
    response_model=FindingResponse,
    status_code=201,
    summary="Create a new finding",
    description="Creates a finding scoped to the authenticated organization.",
)
async def create_finding(
    body: FindingCreate,
    org_id: str = Depends(get_current_org),
    session = Depends(get_db_session),
):
    log = logger.bind(org_id=org_id, operation="create_finding")
    log.info("creating_finding", title=body.title, severity=body.severity)

    try:
        finding = await finding_service.create(session, org_id=org_id, data=body)
    except DatabaseError as e:
        log.error("finding_creation_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to create finding")

    log.info("finding_created", finding_id=finding.id)
    return FindingResponse(
        id=finding.id,
        org_id=org_id,
        title=finding.title,
        severity=finding.severity,
        status=finding.status,
    )


@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Get finding by ID",
)
async def get_finding(
    finding_id: str = Path(..., min_length=1, max_length=64, pattern="^[a-zA-Z0-9_-]+$"),
    org_id: str = Depends(get_current_org),
    session = Depends(get_db_session),
):
    log = logger.bind(org_id=org_id, operation="get_finding", finding_id=finding_id)

    finding = await finding_service.get_by_id(session, finding_id=finding_id, org_id=org_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return FindingResponse(
        id=finding.id,
        org_id=org_id,
        title=finding.title,
        severity=finding.severity,
        status=finding.status,
    )
```

## How to Harden an Existing Endpoint

### Step 1: Add auth (if missing)
```python
# Check current mount:
# app.include_router(some_router, dependencies=[Depends(_verify_api_key)])
#                                   ↑ If this is present, auth is handled.

# If router is mounted WITHOUT auth, add it to the endpoint:
@router.get("/something")
async def get_something(api_key: str = Depends(_verify_api_key)):
    ...
```

### Step 2: Add tenant isolation
```python
# Add org_id dependency:
async def get_something(org_id: str = Depends(get_current_org)):
    ...

# Filter EVERY database query:
query = select(Finding).where(Finding.org_id == org_id, Finding.id == finding_id)
```

### Step 3: Add input validation
```python
# Path parameters — ALWAYS validate format:
finding_id: str = Path(..., min_length=1, max_length=64, pattern="^[a-zA-Z0-9_-]+$")

# Query parameters — set bounds:
limit: int = Query(default=50, ge=1, le=1000)
offset: int = Query(default=0, ge=0)

# Body — use Pydantic model with Field constraints:
class ScanRequest(BaseModel):
    target_url: str = Field(..., pattern=r"^https?://")
    scan_type: str = Field(..., pattern="^(sast|dast|secrets|container|cspm)$")
```

### Step 4: Replace bare except
```python
# See error-handling.md skill for full patterns
except ScannerError as e:
    logger.error("scan_failed", error=str(e), target=body.target_url)
    raise HTTPException(status_code=500, detail="Scan failed")
```

### Step 5: Add response model
```python
@router.get("/findings", response_model=list[FindingResponse])
```

### Step 6: Add structured logging
```python
import structlog
logger = structlog.get_logger()

# At entry:
log = logger.bind(org_id=org_id, operation="endpoint_name")
log.info("operation_started", **relevant_params)

# At exit:
log.info("operation_completed", result_count=len(results))
```

## SQL Injection Prevention

```bash
# Find all f-string SQL (39 known):
grep -rn "f\".*SELECT\|f\".*INSERT\|f\".*UPDATE\|f\".*DELETE\|f\".*WHERE\|f'.*SELECT\|f'.*INSERT\|f'.*UPDATE\|f'.*DELETE\|f'.*WHERE" --include="*.py" suite-api/ suite-core/ suite-attack/ suite-feeds/ suite-evidence-risk/ suite-integrations/ | grep -v __pycache__
```

Replace EVERY f-string SQL:
```python
# BEFORE (SQL injection):
cursor.execute(f"SELECT * FROM findings WHERE id = '{finding_id}'")

# AFTER (parameterized):
cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))

# BEST (SQLAlchemy ORM):
result = await session.execute(select(Finding).where(Finding.id == finding_id))
```

## Priority Order for Hardening

1. **Authentication endpoints** (login, token, API key management)
2. **Data mutation endpoints** (POST, PUT, DELETE)
3. **Scanner endpoints** (accept URLs/code as input — high injection risk)
4. **Finding/evidence endpoints** (sensitive data)
5. **Dashboard/reporting** (read-only but still need tenant isolation)
6. **Admin endpoints** (powerful operations need RBAC)

## Finding Unhardened Endpoints

```bash
# Endpoints without response_model:
grep -rn "@router\.\(get\|post\|put\|delete\|patch\)" suite-api/ suite-core/api/ --include="*.py" | grep -v "response_model" | grep -v __pycache__ | wc -l

# Endpoints without org_id:
grep -rn "async def " suite-api/apps/api/ suite-core/api/ --include="*_router.py" | grep -v "org_id" | grep -v __pycache__ | wc -l

# Routers mounted without auth:
grep "include_router" suite-api/apps/api/app.py | grep -v "Depends\|_verify_api_key" | head -20
```

## Validation

After hardening a router, verify:

```bash
# 1. No bare except:
grep -n "except Exception" suite-api/apps/api/your_router.py

# 2. No f-string SQL:
grep -n "f\".*SELECT\|f'.*SELECT" suite-api/apps/api/your_router.py

# 3. All endpoints have response_model:
grep -n "@router\." suite-api/apps/api/your_router.py | grep -v "response_model"

# 4. Tests pass:
python -m pytest tests/test_your_router.py -v --timeout=10

# 5. No new test collection errors:
python -m pytest tests/ --collect-only -q 2>&1 | tail -5
```
