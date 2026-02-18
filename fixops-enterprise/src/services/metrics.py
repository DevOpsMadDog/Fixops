"""Minimal metrics facade used by middleware."""

from __future__ import annotations

from typing import MutableMapping, Optional


class FixOpsMetrics:
    _rate_limit_triggers: int = 0
    _hot_path_latency: MutableMapping[str, float] = {}
    _key_rotation_events: list[tuple[str, float, bool]] = []
    _error_counts: MutableMapping[str, int] = {}
    _request_counts: MutableMapping[str, int] = {}
    _inflight_counts: MutableMapping[str, int] = {}

    @classmethod
    def request_started(cls, endpoint: str) -> None:  # pragma: no cover - noop
        return None

    @classmethod
    def request_finished(cls, endpoint: str) -> None:  # pragma: no cover - noop
        return None

    @classmethod
    def record_request(
        cls, endpoint: str, method: str, status: int, duration: float
    ) -> None:  # pragma: no cover
        cls._hot_path_latency[endpoint] = duration

    @classmethod
    def rate_limit_triggered(cls) -> None:
        cls._rate_limit_triggers += 1

    @classmethod
    def get_rate_limit_triggers(cls) -> int:
        return cls._rate_limit_triggers

    @classmethod
    def record_key_rotation(cls, provider: str, age_days: float, healthy: bool) -> None:
        """Track key rotation health checks for observability."""

        cls._key_rotation_events.append((provider, age_days, healthy))

    @classmethod
    def get_key_rotation_health(cls, provider: str) -> Optional[bool]:
        """Get the most recent key rotation health status for a provider."""
        for p, _, healthy in reversed(cls._key_rotation_events):
            if p == provider:
                return healthy
        return None

    @classmethod
    def get_key_rotation_age(cls, provider: str) -> Optional[float]:
        """Get the most recent key rotation age in days for a provider."""
        for p, age_days, _ in reversed(cls._key_rotation_events):
            if p == provider:
                return age_days
        return None

    @classmethod
    def reset_runtime_stats(cls) -> None:
        """Reset all runtime statistics for testing."""
        cls._rate_limit_triggers = 0
        cls._hot_path_latency = {}
        cls._key_rotation_events = []
        cls._error_counts = {}
        cls._request_counts = {}
        cls._inflight_counts = {}

    @classmethod
    def get_error_ratio(cls, family: str) -> float:
        """Get the error ratio for a request family."""
        errors = cls._error_counts.get(family, 0)
        total = cls._request_counts.get(family, 0)
        if total == 0:
            return 0.0
        return errors / total

    @classmethod
    def get_hot_path_latency_us(cls, endpoint: str) -> Optional[float]:
        """Get the hot path latency in microseconds for an endpoint."""
        latency = cls._hot_path_latency.get(endpoint)
        if latency is None:
            # Try prefix match for endpoints with path parameters
            for key, value in cls._hot_path_latency.items():
                if endpoint.startswith(key) or key.startswith(endpoint):
                    return value * 1_000_000  # Convert to microseconds
            return None
        return latency * 1_000_000  # Convert to microseconds

    @classmethod
    def get_inflight(cls, family: str) -> int:
        """Get the number of inflight requests for a family."""
        return cls._inflight_counts.get(family, 0)

    @classmethod
    def increment_error(cls, family: str) -> None:
        """Increment the error count for a request family."""
        cls._error_counts[family] = cls._error_counts.get(family, 0) + 1

    @classmethod
    def increment_request(cls, family: str) -> None:
        """Increment the request count for a request family."""
        cls._request_counts[family] = cls._request_counts.get(family, 0) + 1

    @classmethod
    def increment_inflight(cls, family: str) -> None:
        """Increment the inflight count for a request family."""
        cls._inflight_counts[family] = cls._inflight_counts.get(family, 0) + 1

    @classmethod
    def decrement_inflight(cls, family: str) -> None:
        """Decrement the inflight count for a request family."""
        cls._inflight_counts[family] = max(0, cls._inflight_counts.get(family, 0) - 1)
