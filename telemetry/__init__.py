"""OpenTelemetry helpers for FixOps."""

from __future__ import annotations

import importlib.util
import os
from typing import Optional

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

    metrics = _otel.metrics
    trace = _otel.trace
    OTLPMetricExporter = _otel.OTLPMetricExporter
    OTLPSpanExporter = _otel.OTLPSpanExporter
    MeterProvider = _otel.MeterProvider
    PeriodicExportingMetricReader = _otel.PeriodicExportingMetricReader
    Resource = _otel.Resource
    TracerProvider = _otel.TracerProvider
    BatchSpanProcessor = _otel.BatchSpanProcessor
    _NOOP = True

_CONFIGURED = False


def configure(service_name: str = "fixops-platform") -> None:
    """Configure global tracer and meter providers if not already set."""

    global _CONFIGURED
    if _CONFIGURED or os.getenv("FIXOPS_DISABLE_TELEMETRY") == "1" or _NOOP:
        return

    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318")
    traces_endpoint = endpoint.rstrip("/")
    if not traces_endpoint.endswith("v1/traces"):
        traces_endpoint = f"{traces_endpoint}/v1/traces"
    metrics_endpoint = endpoint.rstrip("/")
    if not metrics_endpoint.endswith("v1/metrics"):
        metrics_endpoint = f"{metrics_endpoint}/v1/metrics"

    resource = Resource.create({"service.name": service_name})

    tracer_provider = TracerProvider(resource=resource)
    span_exporter = OTLPSpanExporter(endpoint=traces_endpoint)
    tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
    trace.set_tracer_provider(tracer_provider)

    metric_exporter = OTLPMetricExporter(endpoint=metrics_endpoint)
    reader = PeriodicExportingMetricReader(metric_exporter)
    meter_provider = MeterProvider(resource=resource, metric_readers=[reader])
    metrics.set_meter_provider(meter_provider)

    _CONFIGURED = True


def get_tracer(name: Optional[str] = None):
    configure()
    return trace.get_tracer(name or "fixops")


def get_meter(name: Optional[str] = None):
    configure()
    return metrics.get_meter(name or "fixops")


__all__ = ["configure", "get_tracer", "get_meter"]
