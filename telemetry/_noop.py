"""No-op OpenTelemetry compatibility layer for tests/offline environments."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass


class _NoopSpan:
    def set_attribute(self, *_: object, **__: object) -> None:  # pragma: no cover - no-op
        return None

    def end(self) -> None:  # pragma: no cover - no-op
        return None


@contextmanager
def _span_context() -> _NoopSpan:
    span = _NoopSpan()
    yield span


class _NoopTracer:
    def start_as_current_span(self, *_: object, **__: object):  # pragma: no cover - no-op
        return _span_context()


class _NoopMeter:
    class _Counter:
        def add(self, *_: object, **__: object) -> None:  # pragma: no cover - no-op
            return None

    def create_counter(self, *_: object, **__: object) -> "_NoopMeter._Counter":  # pragma: no cover
        return self._Counter()


class _NoopMetrics:
    def __init__(self) -> None:
        self._meter = _NoopMeter()

    def get_meter(self, *_: object, **__: object) -> _NoopMeter:  # pragma: no cover
        return self._meter

    def set_meter_provider(self, *_: object, **__: object) -> None:  # pragma: no cover
        return None


class _NoopTrace:
    def __init__(self) -> None:
        self._tracer = _NoopTracer()

    def get_tracer(self, *_: object, **__: object) -> _NoopTracer:  # pragma: no cover
        return self._tracer

    def set_tracer_provider(self, *_: object, **__: object) -> None:  # pragma: no cover
        return None


metrics = _NoopMetrics()
trace = _NoopTrace()


@dataclass
class Resource:
    attributes: dict[str, str]

    @classmethod
    def create(cls, attributes: dict[str, str]) -> "Resource":  # pragma: no cover
        return cls(attributes=attributes)


class TracerProvider:  # pragma: no cover - no-op
    def __init__(self, *_, **__):
        return None

    def add_span_processor(self, *_: object, **__: object) -> None:
        return None


class BatchSpanProcessor:  # pragma: no cover - no-op
    def __init__(self, *_: object, **__: object) -> None:
        return None


class OTLPSpanExporter:  # pragma: no cover - no-op
    def __init__(self, *_: object, **__: object) -> None:
        return None


class OTLPMetricExporter:  # pragma: no cover - no-op
    def __init__(self, *_: object, **__: object) -> None:
        return None


class PeriodicExportingMetricReader:  # pragma: no cover - no-op
    def __init__(self, *_: object, **__: object) -> None:
        return None


class MeterProvider:  # pragma: no cover - no-op
    def __init__(self, *_, **__):
        return None


__all__ = [
    "metrics",
    "trace",
    "Resource",
    "TracerProvider",
    "BatchSpanProcessor",
    "OTLPSpanExporter",
    "OTLPMetricExporter",
    "PeriodicExportingMetricReader",
    "MeterProvider",
]
