"""Simplified OPA engine factory used by policy regression tests."""

from __future__ import annotations

from typing import Any, Dict, Optional

from src.config.settings import get_settings


class OPAEngine:
    """Base interface for OPA engines."""

    async def evaluate_policy(
        self, policy_name: str, input_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        raise NotImplementedError

    async def health_check(self) -> bool:
        raise NotImplementedError


class DemoOPAEngine(OPAEngine):
    """Deterministic demo engine that never blocks deployments."""

    async def evaluate_policy(
        self, policy_name: str, input_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        return {
            "policy": policy_name,
            "decision": "allow",
            "rationale": "Demo OPA engine always allows",
            "demo_mode": True,
        }

    async def health_check(self) -> bool:
        return True


class ProductionOPAEngine(OPAEngine):
    """Lightweight placeholder for the production engine."""

    def __init__(self, base_url: str, token: Optional[str] = None, timeout: int = 5):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    async def evaluate_policy(
        self, policy_name: str, input_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        # In this simplified implementation we simply echo the request.
        return {
            "policy": policy_name,
            "decision": "defer",
            "rationale": "External OPA evaluation not configured in this environment",
            "submitted": input_data,
            "opa_url": self.base_url,
        }

    async def health_check(self) -> bool:
        return True


class OPAEngineFactory:
    """Factory returning demo or production engines based on settings."""

    _cached_engine: OPAEngine | None = None

    @classmethod
    def create(cls) -> OPAEngine:
        settings = get_settings()
        if getattr(settings, "DEMO_MODE", False):
            cls._cached_engine = DemoOPAEngine()
        else:
            cls._cached_engine = ProductionOPAEngine(
                base_url=getattr(settings, "OPA_SERVER_URL", "http://localhost:8181"),
                token=getattr(settings, "OPA_AUTH_TOKEN", None),
                timeout=int(getattr(settings, "OPA_REQUEST_TIMEOUT", 5)),
            )
        return cls._cached_engine


async def get_opa_engine() -> OPAEngine:
    """Return a cached OPA engine instance."""

    engine = OPAEngineFactory._cached_engine
    if engine is None:
        engine = OPAEngineFactory.create()
    return engine


__all__ = [
    "DemoOPAEngine",
    "ProductionOPAEngine",
    "OPAEngineFactory",
    "get_opa_engine",
    "OPAEngine",
]
