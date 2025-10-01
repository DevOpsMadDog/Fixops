"""
Prometheus metrics for FixOps
"""
from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest

_registry = CollectorRegistry()
HTTP_REQUESTS = Counter('fixops_http_requests_total', 'Total HTTP requests', ['endpoint', 'method', 'status'], registry=_registry)
HTTP_LATENCY = Histogram('fixops_http_request_seconds', 'HTTP request duration seconds', ['endpoint'], registry=_registry, buckets=(0.01,0.025,0.05,0.1,0.25,0.5,1,2,5))
ENGINE_DECISIONS = Counter('fixops_engine_decisions_total', 'Decisions produced', ['verdict'], registry=_registry)
UPLOADS_COMPLETED = Counter('fixops_uploads_completed_total', 'Completed uploads', ['scan_type'], registry=_registry)

class FixOpsMetrics:
    @staticmethod
    def get_metrics() -> bytes:
        return generate_latest(_registry)

    @staticmethod
    def record_request(endpoint: str, method: str, status: int, duration: float):
        try:
            HTTP_REQUESTS.labels(endpoint=endpoint, method=method, status=str(status)).inc()
            HTTP_LATENCY.labels(endpoint=endpoint).observe(duration)
        except Exception:
            pass

    @staticmethod
    def record_decision(verdict: str):
        try:
            ENGINE_DECISIONS.labels(verdict=verdict).inc()
        except Exception:
            pass

    @staticmethod
    def record_upload(scan_type: str):
        try:
            UPLOADS_COMPLETED.labels(scan_type=scan_type).inc()
        except Exception:
            pass
