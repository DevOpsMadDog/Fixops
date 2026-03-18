# Skill: Error Handling — Exception Hierarchy & Bare Except Elimination

> How to replace 1,477 bare `except Exception` with typed exceptions and structured logging.

## Current State (2026-03-17)
- 1,477 bare `except Exception` across 248 files
- No custom exception hierarchy
- Errors are silently swallowed → masks security events, makes debugging impossible

## The Exception Hierarchy

Create at `suite-core/core/exceptions.py`:

```python
"""ALdeci exception hierarchy.

All custom exceptions inherit from ALdeciError.
Use the most specific exception type available.
"""
import structlog

logger = structlog.get_logger()


class ALdeciError(Exception):
    """Base exception for all ALdeci errors."""
    def __init__(self, message: str, context: dict = None):
        super().__init__(message)
        self.context = context or {}


# --- Database ---
class DatabaseError(ALdeciError):
    """Database operation failed."""

class ConnectionPoolExhausted(DatabaseError):
    """All database connections in use."""

class MigrationError(DatabaseError):
    """Database migration failed."""


# --- Auth & Tenancy ---
class AuthorizationError(ALdeciError):
    """User lacks permission for this operation."""

class TenantIsolationError(ALdeciError):
    """Cross-tenant data access attempted. ALWAYS log as security event."""
    def __init__(self, message: str, requesting_org: str, target_org: str):
        super().__init__(message, {"requesting_org": requesting_org, "target_org": target_org})
        logger.critical("tenant_isolation_violation", requesting_org=requesting_org, target_org=target_org)


# --- Scanners ---
class ScannerError(ALdeciError):
    """Scanner execution failed."""

class ScanTimeout(ScannerError):
    """Scan exceeded time limit."""

class ScanTargetUnreachable(ScannerError):
    """Scan target is not accessible."""


# --- Pipeline ---
class PipelineError(ALdeciError):
    """Brain pipeline step failed."""

class PipelineStepSkipped(PipelineError):
    """A pipeline step was skipped (non-fatal)."""

class ConsensusFailure(PipelineError):
    """Multi-LLM consensus threshold not met."""


# --- AutoFix ---
class AutoFixError(ALdeciError):
    """AutoFix operation failed."""

class FixValidationFailed(AutoFixError):
    """Generated fix failed validation checks."""

class FixConfidenceTooLow(AutoFixError):
    """Fix confidence below threshold for auto-apply."""


# --- External Integration ---
class IntegrationError(ALdeciError):
    """External service integration failed."""

class ConnectorTimeout(IntegrationError):
    """Connector timed out waiting for response."""

class ConnectorAuthFailure(IntegrationError):
    """Authentication with external service failed."""


# --- Evidence ---
class EvidenceError(ALdeciError):
    """Evidence generation or signing failed."""

class SignatureVerificationFailed(EvidenceError):
    """Cryptographic signature verification failed. ALWAYS log as security event."""
    def __init__(self, message: str, evidence_id: str = None):
        super().__init__(message, {"evidence_id": evidence_id})
        logger.critical("signature_verification_failed", evidence_id=evidence_id)
```

## How to Categorize Each `except Exception`

### Pattern 1: REPLACE with specific type (most common)
```python
# BEFORE (anti-pattern):
try:
    result = db.execute(query)
except Exception as e:
    return {"error": str(e)}

# AFTER:
from sqlalchemy.exc import SQLAlchemyError, OperationalError
try:
    result = await session.execute(query)
except OperationalError as e:
    logger.error("database_connection_failed", error=str(e), query=str(query))
    raise DatabaseError(f"Database operation failed: {e}") from e
except SQLAlchemyError as e:
    logger.error("database_query_failed", error=str(e))
    raise DatabaseError(f"Query failed: {e}") from e
```

### Pattern 2: KEEP but add logging (top-level handlers)
```python
# BEFORE (anti-pattern):
try:
    await process_finding(finding)
except Exception:
    pass  # ← SILENT FAILURE

# AFTER:
try:
    await process_finding(finding)
except ALdeciError as e:
    logger.warning("finding_processing_failed", finding_id=finding.id, error=str(e), context=e.context)
except Exception:
    logger.exception("unexpected_error_processing_finding", finding_id=finding.id)
    # Re-raise if this isn't a fire-and-forget operation
```

### Pattern 3: REMOVE unnecessary try/except
```python
# BEFORE (anti-pattern):
try:
    data = json.loads(payload)
except Exception:
    data = {}

# AFTER — let it fail visibly, or handle the specific case:
try:
    data = json.loads(payload)
except (json.JSONDecodeError, TypeError) as e:
    logger.warning("invalid_json_payload", error=str(e))
    data = {}
```

### Pattern 4: NARROW the scope
```python
# BEFORE (anti-pattern):
try:
    token = parse_jwt(header)
    user = lookup_user(token["sub"])
    org = get_org(user.org_id)
    # 50 lines of business logic
except Exception as e:
    return JSONResponse(500, {"error": "Internal error"})

# AFTER — separate concerns:
try:
    token = parse_jwt(header)
except jwt.InvalidTokenError as e:
    raise AuthorizationError(f"Invalid token: {e}") from e

try:
    user = lookup_user(token["sub"])
except KeyError:
    raise AuthorizationError("Token missing 'sub' claim")
except UserNotFoundError:
    raise AuthorizationError(f"User {token['sub']} not found")

org = get_org(user.org_id)  # Let this raise naturally if it fails
```

## Global Exception Handler (add to app.py)

```python
from fastapi import Request
from fastapi.responses import JSONResponse
from core.exceptions import ALdeciError, TenantIsolationError, AuthorizationError

@app.exception_handler(ALdeciError)
async def aldeci_error_handler(request: Request, exc: ALdeciError):
    correlation_id = getattr(request.state, "correlation_id", "unknown")
    
    # Security events get CRITICAL log level
    if isinstance(exc, (TenantIsolationError,)):
        logger.critical("security_event", error=str(exc), correlation_id=correlation_id, context=exc.context)
        return JSONResponse(status_code=403, content={"error": "Access denied", "correlation_id": correlation_id})
    
    if isinstance(exc, AuthorizationError):
        return JSONResponse(status_code=403, content={"error": str(exc), "correlation_id": correlation_id})
    
    # All other ALdeci errors → 500 with sanitized message
    logger.error("application_error", error_type=type(exc).__name__, error=str(exc), correlation_id=correlation_id, context=exc.context)
    return JSONResponse(status_code=500, content={"error": "Internal error", "correlation_id": correlation_id})


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
    correlation_id = getattr(request.state, "correlation_id", "unknown")
    logger.exception("unhandled_exception", correlation_id=correlation_id)
    return JSONResponse(status_code=500, content={"error": "Internal error", "correlation_id": correlation_id})
```

## Batch Processing Strategy

Don't try to fix all 1,477 at once. Process by domain:

```bash
# Count per suite:
echo "suite-api:" && grep -rn "except Exception" suite-api/ --include="*.py" | grep -v __pycache__ | wc -l
echo "suite-core:" && grep -rn "except Exception" suite-core/ --include="*.py" | grep -v __pycache__ | wc -l
echo "suite-attack:" && grep -rn "except Exception" suite-attack/ --include="*.py" | grep -v __pycache__ | wc -l
echo "suite-feeds:" && grep -rn "except Exception" suite-feeds/ --include="*.py" | grep -v __pycache__ | wc -l
echo "suite-evidence-risk:" && grep -rn "except Exception" suite-evidence-risk/ --include="*.py" | grep -v __pycache__ | wc -l
echo "suite-integrations:" && grep -rn "except Exception" suite-integrations/ --include="*.py" | grep -v __pycache__ | wc -l
```

Process order:
1. `suite-api/apps/api/` (routers — most user-facing)
2. `suite-core/core/` (engines — most critical)
3. `suite-attack/` (security — must not swallow pentest errors)
4. Rest

## Validation

```bash
# Count remaining bare except (target: <100):
grep -rn "except Exception" suite-api/ suite-core/ suite-attack/ suite-feeds/ suite-evidence-risk/ suite-integrations/ --include="*.py" | grep -v __pycache__ | wc -l

# Verify no silent except pass:
grep -A1 "except Exception" suite-api/ suite-core/ --include="*.py" | grep -v __pycache__ | grep "pass$" | wc -l
# Target: 0

# Run tests after changes:
python -m pytest tests/ -q --timeout=10 -x
```
