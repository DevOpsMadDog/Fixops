"""Minimal metrics facade used by middleware."""

from __future__ import annotations

from typing import MutableMapping


class FixOpsMetrics:
    _rate_limit_triggers: int = 0
    _hot_path_latency: MutableMapping[str, float] = {}

    @classmethod
    def request_started(cls, endpoint: str) -> None:  # pragma: no cover - noop
        return None

    @classmethod
    def request_finished(cls, endpoint: str) -> None:  # pragma: no cover - noop
        return None

    @classmethod
    def record_request(cls, endpoint: str, method: str, status: int, duration: float) -> None:  # pragma: no cover
        cls._hot_path_latency[endpoint] = duration

    @classmethod
    def rate_limit_triggered(cls) -> None:
        cls._rate_limit_triggers += 1

    @classmethod
    def get_rate_limit_triggers(cls) -> int:
        return cls._rate_limit_triggers

