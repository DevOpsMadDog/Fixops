"""No-op FastAPI instrumentor for environments without OpenTelemetry packages."""

from __future__ import annotations


class FastAPIInstrumentor:  # pragma: no cover - simple shim
    @staticmethod
    def instrument_app(*_args, **_kwargs) -> None:
        return None
