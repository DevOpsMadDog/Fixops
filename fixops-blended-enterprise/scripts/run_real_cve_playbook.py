#!/usr/bin/env python3
"""Run the FixOps production decision engine against real CVEs.

The script ingests one or more CVE identifiers, enriches them with intelligence
from NVD (when reachable), the bundled CISA KEV catalog, EPSS exploit
probability feed, and curated FixOps spotlight data. The resulting security
findings feed directly into the production decision engine so the full
processing layer, consensus logic, and evidence generation execute without the
simulated demo shortcuts.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import types
from pathlib import Path
from typing import Any, Dict, Iterable, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in os.sys.path:
    os.sys.path.insert(0, str(PROJECT_ROOT))

# Force production mode before importing the decision engine/settings modules.
os.environ.setdefault("DEMO_MODE", "false")

try:  # pragma: no cover - optional dependency normalisation
    import structlog  # type: ignore
except ModuleNotFoundError:
    structlog_stub = types.ModuleType("structlog")

    class _Logger:
        def bind(self, **kwargs):
            return self

        def info(self, *args, **kwargs):
            pass

        def error(self, *args, **kwargs):
            pass

        def warning(self, *args, **kwargs):
            pass

    def get_logger(*args, **kwargs):
        return _Logger()

    structlog_stub.get_logger = get_logger
    sys.modules["structlog"] = structlog_stub

try:  # pragma: no cover - optional dependency normalisation
    import redis.asyncio  # type: ignore  # noqa: F401
except ModuleNotFoundError:
    redis_pkg = types.ModuleType("redis")
    redis_async = types.ModuleType("redis.asyncio")
    redis_connection = types.ModuleType("redis.asyncio.connection")

    class _ConnectionPool:
        @classmethod
        def from_url(cls, *args, **kwargs):
            return cls()

        async def disconnect(self):  # pragma: no cover - stub behaviour
            return None

    class _Redis:
        def __init__(self, *args, **kwargs):
            self._store: Dict[str, Any] = {}

        async def ping(self):  # pragma: no cover - stub behaviour
            raise ConnectionError("redis library not available; using in-memory cache")

        async def set(self, key, value, ex=None, nx=False):
            if nx and key in self._store:
                return False
            self._store[key] = value
            return True

        async def get(self, key):
            return self._store.get(key)

        async def delete(self, key):
            return 1 if self._store.pop(key, None) is not None else 0

        async def close(self):
            self._store.clear()
            return None

    redis_connection.ConnectionPool = _ConnectionPool
    redis_async.Redis = _Redis
    redis_async.ConnectionPool = _ConnectionPool
    redis_async.connection = redis_connection
    redis_pkg.asyncio = redis_async

    sys.modules["redis"] = redis_pkg
    sys.modules["redis.asyncio"] = redis_async
    sys.modules["redis.asyncio.connection"] = redis_connection

try:  # pragma: no cover - optional dependency normalisation
    import orjson  # type: ignore  # noqa: F401
except ModuleNotFoundError:
    import json as _json

    orjson_stub = types.ModuleType("orjson")
    orjson_stub.loads = _json.loads
    orjson_stub.dumps = lambda value: _json.dumps(value).encode("utf-8")
    orjson_stub.JSONDecodeError = _json.JSONDecodeError
    sys.modules["orjson"] = orjson_stub

try:  # pragma: no cover - optional dependency normalisation
    import sqlalchemy  # type: ignore  # noqa: F401
    from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore  # noqa: F401
except ModuleNotFoundError:
    sqlalchemy_pkg = types.ModuleType("sqlalchemy")
    sqlalchemy_ext = types.ModuleType("sqlalchemy.ext")
    sqlalchemy_asyncio = types.ModuleType("sqlalchemy.ext.asyncio")
    sqlalchemy_pool = types.ModuleType("sqlalchemy.pool")

    class _AsyncSession:
        async def execute(self, query):  # pragma: no cover - stub behaviour
            class _Result:
                def scalar(self):
                    return 1

            return _Result()

        async def commit(self):
            return None

        async def rollback(self):
            return None

        async def close(self):
            return None

    class _SessionFactory:
        def __call__(self, *args, **kwargs):
            return _AsyncSession()

    def async_sessionmaker(*args, **kwargs):
        return _SessionFactory()

    class _DummyEngine:
        def __init__(self):
            self.sync_engine = self

        async def dispose(self):
            return None

    def create_async_engine(*args, **kwargs):
        return _DummyEngine()

    class _QueuePool:
        pass

    def text(value):
        return value

    def listens_for(target, identifier):
        def decorator(func):
            return func

        return decorator

    event_module = types.ModuleType("sqlalchemy.event")
    event_module.listens_for = listens_for

    sqlalchemy_pkg.event = event_module
    sqlalchemy_pkg.text = text
    sqlalchemy_ext.asyncio = sqlalchemy_asyncio
    sqlalchemy_pkg.ext = sqlalchemy_ext
    sqlalchemy_asyncio.AsyncSession = _AsyncSession
    sqlalchemy_asyncio.async_sessionmaker = async_sessionmaker
    sqlalchemy_asyncio.create_async_engine = create_async_engine
    sqlalchemy_pool.QueuePool = _QueuePool

    sys.modules["sqlalchemy"] = sqlalchemy_pkg
    sys.modules["sqlalchemy.ext"] = sqlalchemy_ext
    sys.modules["sqlalchemy.ext.asyncio"] = sqlalchemy_asyncio
    sys.modules["sqlalchemy.pool"] = sqlalchemy_pool
    sys.modules["sqlalchemy.event"] = event_module

try:  # pragma: no cover - optional dependency normalisation
    import prometheus_client  # type: ignore  # noqa: F401
except ModuleNotFoundError:
    prometheus_stub = types.ModuleType("prometheus_client")

    class _Metric:
        def __init__(self, *args, **kwargs):
            self._value = 0

        def labels(self, *args, **kwargs):
            return self

        def inc(self, value=1):
            self._value += value

        def observe(self, value):
            self._value = value

    class CollectorRegistry:
        pass

    Counter = _Metric
    Histogram = _Metric

    def generate_latest(registry=None):
        return b"prometheus_client_stub 1"

    prometheus_stub.CollectorRegistry = CollectorRegistry
    prometheus_stub.Counter = Counter
    prometheus_stub.Histogram = Histogram
    prometheus_stub.generate_latest = generate_latest
    sys.modules["prometheus_client"] = prometheus_stub

while True:
    try:
        from src.config.settings import get_settings
        break
    except ModuleNotFoundError as exc:  # pragma: no cover - import fallback
        if exc.name == "pydantic_settings":
            settings_stub = types.ModuleType("pydantic_settings")

            class _BaseSettings:  # minimal emulation
                def __init__(self, **kwargs):
                    for key, value in kwargs.items():
                        setattr(self, key, value)

            settings_stub.BaseSettings = _BaseSettings
            sys.modules["pydantic_settings"] = settings_stub
            continue
        if exc.name == "pydantic":
            pydantic_stub = types.ModuleType("pydantic")

            class _BaseModel:  # matches the demo CLI stub
                def __init__(self, **kwargs):
                    for key, value in kwargs.items():
                        setattr(self, key, value)

            def Field(default=None, **kwargs):
                return default

            def field_validator(*args, **kwargs):
                def decorator(func):
                    return func

                return decorator

            pydantic_stub.BaseModel = _BaseModel
            pydantic_stub.Field = Field
            pydantic_stub.field_validator = field_validator
            sys.modules["pydantic"] = pydantic_stub
            continue
        if exc.name == "structlog":
            structlog_stub = types.ModuleType("structlog")

            class _Logger:
                def bind(self, **kwargs):
                    return self

                def info(self, *args, **kwargs):
                    pass

                def error(self, *args, **kwargs):
                    pass

                def warning(self, *args, **kwargs):
                    pass

            def get_logger(*args, **kwargs):
                return _Logger()

            structlog_stub.get_logger = get_logger
            sys.modules["structlog"] = structlog_stub
            continue
        raise

# Ensure the cached settings pick up the CLI override.
if hasattr(get_settings, "cache_clear"):
    get_settings.cache_clear()

settings = get_settings()
if getattr(settings, "DEMO_MODE", True):
    try:
        settings.DEMO_MODE = False
    except Exception:
        pass

from src.services.decision_engine import DecisionContext, decision_engine
from src.services.cve_enrichment import CVEEnricher, summarize_findings


def _render_table(rows: List[Dict[str, Any]], headers: List[str]) -> str:
    widths = {header: len(header) for header in headers}
    for row in rows:
        for header in headers:
            widths[header] = max(widths[header], len(str(row.get(header, ""))))

    header_line = " | ".join(header.ljust(widths[header]) for header in headers)
    separator = "-+-".join("-" * widths[header] for header in headers)
    body_lines = [
        " | ".join(str(row.get(header, "")).ljust(widths[header]) for header in headers)
        for row in rows
    ]
    return "\n".join([header_line, separator, *body_lines])


def build_business_context(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "service_owner": args.service_owner,
        "customer_impact": args.customer_impact,
        "data_classification": args.data_classification,
        "compliance_requirements": args.compliance,
        "deployment_frequency": args.deployment_frequency,
    }


def _print_regression_summary(regression: Dict[str, Any]) -> None:
    status = regression.get("status", "unknown")
    coverage = regression.get("coverage_pct", 0.0)
    matched = regression.get("matched_cases", 0)
    total = regression.get("total_cases", 0)
    passed = regression.get("passed", 0)
    print(
        f"  - golden_regression: status={status}, coverage={coverage:.1f}%"
        f" ({matched}/{total} cases, {passed} matched expectations)"
    )
    failures = regression.get("failures", [])
    if failures:
        for failure in failures:
            reason = failure.get("reason", "unknown")
            cve = failure.get("cve_id", "n/a")
            expected = failure.get("expected")
            predicted = failure.get("predicted")
            detail = f"reason={reason}, cve={cve}"
            if expected and predicted:
                detail += f", expected={expected}, predicted={predicted}"
            print(f"      * {detail}")


def _print_compliance_summary(compliance: Dict[str, Any]) -> None:
    status = compliance.get("status", "unknown")
    overall = "pass" if compliance.get("overall_compliant") else "fail"
    coverage = compliance.get("coverage_pct", 0.0)
    requested = compliance.get("requested_frameworks", [])
    print(
        f"  - compliance: status={status}, overall={overall}, coverage={coverage:.1f}%"
        f" (requested={', '.join(requested) or 'none'})"
    )
    frameworks = compliance.get("frameworks", {})
    for name, details in frameworks.items():
        framework_status = details.get("status", "unknown")
        violations = details.get("violations", [])
        controls = details.get("controls_triggered", [])
        print(f"      * {name}: {framework_status}")
        if violations:
            for violation in violations:
                print(f"          - {violation}")
        if controls:
            print(f"          controls: {', '.join(controls)}")


async def run_real_playbook(args: argparse.Namespace) -> None:
    feeds_root = PROJECT_ROOT.parent / "data" / "feeds"
    enricher = CVEEnricher(feeds_root)

    try:
        await decision_engine.initialize()
    except Exception as exc:  # pragma: no cover - CLI execution path
        raise SystemExit(f"Failed to initialise decision engine: {exc}")

    if decision_engine.demo_mode:
        raise SystemExit("Decision engine initialised in demo mode; aborting real run")

    cve_records = []
    findings = []
    for cve_id in args.cves:
        try:
            record = enricher.enrich(cve_id)
        except ValueError as exc:
            if args.strict:
                raise SystemExit(str(exc))
            print(f"⚠️  {exc}")
            continue
        cve_records.append(record)
        findings.append(record.to_security_finding())

    if not findings:
        raise SystemExit("No CVE findings to evaluate")

    business_context = build_business_context(args)

    decision_context = DecisionContext(
        service_name=args.service_name,
        environment=args.environment,
        business_context=business_context,
        security_findings=findings,
        threat_model={
            "playbook": "real-cve",
            "sources": [record.source for record in cve_records],
            "notes": "Auto-generated from real CVE ingestion pipeline",
        },
        sbom_data=None,
        runtime_data={"deployment_id": args.deployment_id},
    )

    result = await decision_engine.make_decision(decision_context)

    print("\n=== Real CVE Intake Summary ===")
    table_rows = []
    for record in cve_records:
        table_rows.append(
            {
                "CVE": record.cve_id,
                "Severity": record.severity.upper(),
                "CVSS": f"{record.cvss_score:.1f}" if record.cvss_score is not None else "-",
                "EPSS": f"{record.epss_score:.2f}" if record.epss_score is not None else "-",
                "KEV": "Yes" if record.kev_flag else "No",
                "Source": record.source,
            }
        )
    print(_render_table(table_rows, ["CVE", "Severity", "CVSS", "EPSS", "KEV", "Source"]))

    aggregates = summarize_findings(cve_records)
    avg_epss = aggregates.get("average_epss")
    avg_text = f"{avg_epss:.2f}" if avg_epss is not None else "n/a"
    print(
        f"\nActionable: {aggregates['actionable']}/{aggregates['total']}"
        f" ({aggregates['actionable_pct']:.0f}%); KEV flagged: {aggregates['kev_count']}"
        f" ({aggregates['kev_pct']:.0f}%); Average EPSS: {avg_text}"
    )

    print("\n=== Decision Engine Output ===")
    print(f"Outcome     : {result.decision.value}")
    print(f"Confidence  : {result.confidence_score:.2f}")
    print(f"Evidence ID : {result.evidence_id}")
    print(f"Reasoning   : {result.reasoning}")

    if result.validation_results:
        print("\nValidation Signals:")
        regression = result.validation_results.get("golden_regression")
        compliance = result.validation_results.get("compliance")
        if isinstance(regression, dict):
            _print_regression_summary(regression)
        if isinstance(compliance, dict):
            _print_compliance_summary(compliance)
        for key, value in result.validation_results.items():
            if key in {"golden_regression", "compliance"}:
                continue
            if isinstance(value, dict):
                print(f"  - {key}: status={value.get('status', 'n/a')}")
            else:
                print(f"  - {key}: {value}")

    if result.context_sources:
        print("\nContext Sources: " + ", ".join(result.context_sources))


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cves", nargs="+", help="One or more CVE identifiers to process")
    parser.add_argument("--service-name", default="payment-api", help="Service under review")
    parser.add_argument("--environment", default="production", help="Deployment environment")
    parser.add_argument(
        "--service-owner", default="platform-security", help="Service owner for business context"
    )
    parser.add_argument(
        "--customer-impact", default="high", help="Business impact level for the affected service"
    )
    parser.add_argument(
        "--data-classification", default="restricted", help="Data classification for the workload"
    )
    parser.add_argument(
        "--compliance",
        nargs="*",
        default=["PCI-DSS", "SOC2"],
        help="Compliance frameworks relevant to the service",
    )
    parser.add_argument(
        "--deployment-frequency",
        default="daily",
        help="Release cadence for the workload (used for urgency heuristics)",
    )
    parser.add_argument(
        "--deployment-id",
        default="deployment-001",
        help="Identifier for the deployment under evaluation",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail the run if any CVE cannot be enriched from available feeds",
    )
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> None:
    args = parse_args(argv)
    asyncio.run(run_real_playbook(args))


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    main()
