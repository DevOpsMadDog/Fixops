# Skill: Observability — OpenTelemetry, Metrics, Structured Logging, Health Checks

> How to add production-grade observability to ALdeci: traces, metrics, logs, and health checks.

## Current State (2026-03-17)
- No OpenTelemetry instrumentation
- No Prometheus `/metrics` endpoint
- Logging via `structlog` in some files, bare `print()` in others
- Basic `/health` endpoint exists but only returns `{"status": "ok"}`

## Three Pillars of Observability

### 1. Structured Logging (Foundation)

Every module should use `structlog`, not `print()` or `logging.getLogger()`:

```python
import structlog

logger = structlog.get_logger()

# Bind context that follows all subsequent calls:
log = logger.bind(
    org_id=org_id,
    operation="brain_pipeline_process",
    correlation_id=request_id,
)

# INFO for normal operations:
log.info("pipeline_started", finding_count=len(findings))

# WARNING for degraded operations:
log.warning("llm_provider_slow", provider="openai", latency_ms=3200)

# ERROR for failures that need attention:
log.error("scan_failed", scanner="sast", error=str(e), target=target_path)

# CRITICAL for security events (ALWAYS):
log.critical("tenant_isolation_breach", requesting_org="org_a", target_org="org_b")
```

#### Configure structlog (add to app startup):

```python
import structlog

def configure_logging():
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            # JSON in production, pretty in dev:
            structlog.dev.ConsoleRenderer() if os.getenv("FIXOPS_MODE") == "dev"
            else structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
```

#### Replace print() statements:

```bash
# Find print statements in production code:
grep -rn "print(" suite-api/ suite-core/ suite-attack/ suite-feeds/ suite-evidence-risk/ suite-integrations/ --include="*.py" | grep -v __pycache__ | grep -v test | wc -l

# Replace pattern:
# BEFORE: print(f"Processing finding {finding_id}")
# AFTER:  logger.info("processing_finding", finding_id=finding_id)
```

### 2. Metrics (Prometheus)

Add a `/metrics` endpoint for Prometheus scraping:

```python
# suite-core/core/metrics.py
"""Prometheus metrics for ALdeci."""
from prometheus_client import Counter, Histogram, Gauge, Info

# --- Request Metrics ---
http_requests_total = Counter(
    "aldeci_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status_code"],
)
http_request_duration_seconds = Histogram(
    "aldeci_http_request_duration_seconds",
    "HTTP request duration",
    ["method", "endpoint"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

# --- Scanner Metrics ---
scans_total = Counter(
    "aldeci_scans_total",
    "Total scans executed",
    ["scanner_type", "status"],
)
scan_duration_seconds = Histogram(
    "aldeci_scan_duration_seconds",
    "Scan execution duration",
    ["scanner_type"],
)
scan_findings_total = Counter(
    "aldeci_scan_findings_total",
    "Total findings from scans",
    ["scanner_type", "severity"],
)

# --- Pipeline Metrics ---
pipeline_executions_total = Counter(
    "aldeci_pipeline_executions_total",
    "Total brain pipeline executions",
    ["status"],
)
pipeline_step_duration_seconds = Histogram(
    "aldeci_pipeline_step_duration_seconds",
    "Duration of each pipeline step",
    ["step_name"],
)

# --- AutoFix Metrics ---
autofix_attempts_total = Counter(
    "aldeci_autofix_attempts_total",
    "Total autofix attempts",
    ["fix_type", "confidence", "status"],
)

# --- Tenant Metrics ---
active_orgs_gauge = Gauge(
    "aldeci_active_organizations",
    "Number of active organizations",
)

# --- Build Info ---
build_info = Info(
    "aldeci_build",
    "Build information",
)
```

#### Metrics Middleware:

```python
# Add to app.py:
from starlette.middleware.base import BaseHTTPMiddleware
import time
from core.metrics import http_requests_total, http_request_duration_seconds


class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start

        endpoint = request.url.path
        method = request.method
        status = str(response.status_code)

        http_requests_total.labels(method=method, endpoint=endpoint, status_code=status).inc()
        http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)

        return response

# Mount:
app.add_middleware(MetricsMiddleware)
```

#### Metrics Endpoint:

```python
# In a router or directly on app:
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from fastapi.responses import Response

@app.get("/metrics", include_in_schema=False)
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
```

### 3. Distributed Tracing (OpenTelemetry)

```python
# suite-core/core/tracing.py
"""OpenTelemetry tracing configuration."""
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
import os


def configure_tracing(app):
    """Configure OpenTelemetry tracing. Only active if OTEL_EXPORTER_OTLP_ENDPOINT is set."""
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return  # No-op in dev/air-gapped mode

    provider = TracerProvider()
    processor = BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint))
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)

    # Auto-instrument FastAPI:
    FastAPIInstrumentor.instrument_app(app)
    # Auto-instrument outgoing HTTP:
    HTTPXClientInstrumentor().instrument()


# Usage in any module:
tracer = trace.get_tracer("aldeci.brain_pipeline")

async def process_finding(finding):
    with tracer.start_as_current_span("process_finding") as span:
        span.set_attribute("finding.id", finding["id"])
        span.set_attribute("finding.severity", finding["severity"])
        # ... processing logic ...
```

## Deep Health Checks

Replace the shallow `{"status": "ok"}` with comprehensive health:

```python
# suite-api/apps/api/health_router.py
from fastapi import APIRouter
import time
import os

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check():
    """Shallow health check for load balancers. Returns quickly."""
    return {"status": "ok", "timestamp": time.time()}


@router.get("/health/deep")
async def deep_health_check():
    """Deep health check — verifies all subsystems."""
    checks = {}
    overall = "healthy"

    # Database connectivity
    try:
        from core.db.enterprise.session import get_engine
        engine = get_engine()
        async with engine.connect() as conn:
            await conn.execute("SELECT 1")
        checks["database"] = {"status": "healthy", "type": "postgresql"}
    except Exception as e:
        checks["database"] = {"status": "unhealthy", "error": str(e)}
        overall = "degraded"

    # Scanner availability
    for scanner_name in ["sast", "dast", "secrets", "container", "cspm"]:
        try:
            module = __import__(f"core.{scanner_name}_engine", fromlist=[scanner_name])
            checks[f"scanner_{scanner_name}"] = {"status": "healthy"}
        except ImportError as e:
            checks[f"scanner_{scanner_name}"] = {"status": "unhealthy", "error": str(e)}
            overall = "degraded"

    # Disk space
    stat = os.statvfs("/")
    free_gb = (stat.f_bavail * stat.f_frsize) / (1024 ** 3)
    checks["disk"] = {
        "status": "healthy" if free_gb > 1.0 else "warning",
        "free_gb": round(free_gb, 2),
    }
    if free_gb < 0.5:
        overall = "degraded"

    # Memory (basic)
    try:
        import psutil
        mem = psutil.virtual_memory()
        checks["memory"] = {
            "status": "healthy" if mem.percent < 90 else "warning",
            "used_percent": mem.percent,
        }
    except ImportError:
        checks["memory"] = {"status": "unknown", "note": "psutil not installed"}

    return {
        "status": overall,
        "timestamp": time.time(),
        "checks": checks,
        "version": os.getenv("ALDECI_VERSION", "dev"),
    }
```

## Correlation IDs

Track requests across all components:

```python
# Middleware for correlation ID:
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
import structlog

class CorrelationIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
        request.state.correlation_id = correlation_id

        # Set in structlog context for all subsequent log calls:
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(correlation_id=correlation_id)

        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response
```

## Audit Trail Logging

Security-critical operations MUST be audit-logged:

```python
AUDIT_EVENTS = [
    "user_login",
    "user_logout",
    "api_key_created",
    "api_key_revoked",
    "finding_created",
    "finding_deleted",
    "scan_started",
    "autofix_applied",
    "evidence_signed",
    "tenant_isolation_violation",
    "config_changed",
    "user_role_changed",
]

async def audit_log(event: str, actor: str, org_id: str, details: dict = None):
    """Write to immutable audit log. NEVER delete these entries."""
    logger.info(
        "audit_event",
        event=event,
        actor=actor,
        org_id=org_id,
        details=details or {},
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    # Also persist to audit DB:
    await audit_db.insert({
        "event": event,
        "actor": actor,
        "org_id": org_id,
        "details": details or {},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
```

## Implementation Priority

1. **structlog configuration** — add to app startup (1 file change)
2. **Correlation ID middleware** — add to app.py (1 file change)
3. **Deep health check** — replace shallow `/health` (1 file change)
4. **Prometheus metrics** — create metrics.py + middleware + endpoint (3 files)
5. **Replace print() statements** — batch across all suites
6. **OpenTelemetry** — optional, for when external collector is available

## Validation

```bash
# Verify structlog works:
python -c "import structlog; structlog.get_logger().info('test', key='value')"

# Check for remaining print() in production code:
grep -rn "print(" suite-api/ suite-core/ suite-attack/ --include="*.py" | grep -v __pycache__ | grep -v test_ | wc -l
# Target: < 20

# Verify /health/deep returns all subsystems:
curl -s http://localhost:8000/health/deep | python -m json.tool

# Verify /metrics returns Prometheus format:
curl -s http://localhost:8000/metrics | head -20
```
