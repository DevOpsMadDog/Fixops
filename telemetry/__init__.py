"""OpenTelemetry helpers for FixOps."""

from __future__ import annotations

import importlib.util
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_NOOP = False
if importlib.util.find_spec("opentelemetry") and importlib.util.find_spec(
    "opentelemetry.sdk"
):
    from opentelemetry import metrics, trace
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
        OTLPMetricExporter,
    )
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
else:  # pragma: no cover - fallback for test environments without OpenTelemetry
    from . import _noop as _otel

    metrics = _otel.metrics  # type: ignore[assignment,misc]
    trace = _otel.trace  # type: ignore[assignment,misc]
    OTLPMetricExporter = _otel.OTLPMetricExporter  # type: ignore[assignment,misc]
    OTLPSpanExporter = _otel.OTLPSpanExporter  # type: ignore[assignment,misc]
    MeterProvider = _otel.MeterProvider  # type: ignore[assignment,misc]
    PeriodicExportingMetricReader = _otel.PeriodicExportingMetricReader  # type: ignore[assignment,misc]
    Resource = _otel.Resource  # type: ignore[assignment,misc]
    TracerProvider = _otel.TracerProvider  # type: ignore[assignment,misc]
    BatchSpanProcessor = _otel.BatchSpanProcessor  # type: ignore[assignment,misc]
    _NOOP = True

_CONFIGURED = False


if not _NOOP:
    from opentelemetry.sdk.trace.export import SpanExporter

    class _SilentSpanExporter(SpanExporter):
        """Wrapper around OTLPSpanExporter that suppresses connection errors."""

        def __init__(self, exporter: SpanExporter):
            self._exporter = exporter

        def export(self, spans):
            """Export spans, suppressing connection errors."""
            try:
                return self._exporter.export(spans)
            except Exception as exc:
                logger.debug(f"Failed to export spans: {exc}")
                from opentelemetry.sdk.trace.export import SpanExportResult

                return SpanExportResult.SUCCESS

        def shutdown(self):
            """Shutdown the exporter, suppressing errors."""
            try:
                return self._exporter.shutdown()
            except Exception as exc:
                logger.debug(f"Failed to shutdown span exporter: {exc}")

        def force_flush(self, timeout_millis=None):
            """Force flush, suppressing errors."""
            try:
                return self._exporter.force_flush(timeout_millis)
            except Exception as exc:
                logger.debug(f"Failed to force flush spans: {exc}")
                return True

else:

    class _SilentSpanExporter:  # type: ignore[no-redef]
        """No-op wrapper for when OpenTelemetry is not available."""

        def __init__(self, exporter):
            self._exporter = exporter

        def export(self, spans):
            return self._exporter.export(spans)

        def shutdown(self):
            return self._exporter.shutdown()

        def force_flush(self, timeout_millis=None):
            return self._exporter.force_flush(timeout_millis)


def configure(service_name: str = "fixops-platform") -> None:
    """Configure global tracer and meter providers if not already set."""

    global _CONFIGURED
    if _CONFIGURED or os.getenv("FIXOPS_DISABLE_TELEMETRY") == "1" or _NOOP:
        return

    try:
        endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318")
        traces_endpoint = endpoint.rstrip("/")
        if not traces_endpoint.endswith("v1/traces"):
            traces_endpoint = f"{traces_endpoint}/v1/traces"
        metrics_endpoint = endpoint.rstrip("/")
        if not metrics_endpoint.endswith("v1/metrics"):
            metrics_endpoint = f"{metrics_endpoint}/v1/metrics"

        resource = Resource.create({"service.name": service_name})

        tracer_provider = TracerProvider(resource=resource)
        span_exporter = OTLPSpanExporter(endpoint=traces_endpoint, timeout=5)
        silent_exporter = _SilentSpanExporter(span_exporter)
        tracer_provider.add_span_processor(BatchSpanProcessor(silent_exporter))
        trace.set_tracer_provider(tracer_provider)

        metric_exporter = OTLPMetricExporter(endpoint=metrics_endpoint, timeout=5)
        reader = PeriodicExportingMetricReader(
            metric_exporter, export_interval_millis=60000
        )
        meter_provider = MeterProvider(resource=resource, metric_readers=[reader])
        metrics.set_meter_provider(meter_provider)

        _CONFIGURED = True
        logger.info(f"Telemetry configured for {service_name}, endpoint: {endpoint}")
    except Exception as exc:
        logger.warning(
            f"Failed to configure telemetry: {exc}. Application will continue without telemetry."
        )
        _CONFIGURED = True


def get_tracer(name: Optional[str] = None):
    configure()
    return trace.get_tracer(name or "fixops")


def get_meter(name: Optional[str] = None):
    configure()
    return metrics.get_meter(name or "fixops")


__all__ = ["configure", "get_tracer", "get_meter"]
