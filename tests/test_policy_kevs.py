"""Tests for KEV waiver enforcement in the policy API."""

from __future__ import annotations

import asyncio
import sys
import types
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Dict

from pydantic import FieldInfo
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

pydantic_settings = types.ModuleType("pydantic_settings")


class _BaseSettings:
    def __init__(self, **overrides: Any) -> None:
        for name, value in self.__class__.__dict__.items():
            if name.startswith("_") or callable(value) or isinstance(value, property):
                continue
            default = value.default if isinstance(value, FieldInfo) else value
            setattr(self, name, overrides.get(name, default))

    def model_dump(self) -> Dict[str, Any]:
        return {name: getattr(self, name) for name in dir(self) if name.isupper()}


pydantic_settings.BaseSettings = _BaseSettings
pydantic_settings.SettingsConfigDict = dict
sys.modules["pydantic_settings"] = pydantic_settings

from api.v1.policy import GateRequest, WaiverCreate, create_waiver, evaluate_gate
from core.models.enterprise import (  # noqa: F401  # Ensure metadata is populated
    security_sqlite,
)
from core.models.enterprise.base_sqlite import Base


async def _execute_with_session(
    test_fn: Callable[[AsyncSession], Awaitable[None]],
) -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        SessionLocal = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
        async with SessionLocal() as session:
            await test_fn(session)
    finally:
        await engine.dispose()


def run_with_session(test_fn: Callable[[AsyncSession], Awaitable[None]]) -> None:
    asyncio.run(_execute_with_session(test_fn))


def test_kevs_block_without_waiver() -> None:
    """KEV findings without waivers must trigger a hard block."""

    async def scenario(session: AsyncSession) -> None:
        request = GateRequest(
            decision="ALLOW",
            confidence=0.82,
            signals={"kev_count": 1, "service_name": "payments"},
            findings=[{"cve_id": "CVE-2024-1111", "kev": True, "severity": "medium"}],
        )

        response = await evaluate_gate(request, db=session)

        assert response.allow is False
        assert "CVE-2024-1111" in response.reason
        assert any("waiver" in action.lower() for action in response.required_actions)

    run_with_session(scenario)


def test_kevs_allow_with_active_waiver() -> None:
    """An approved, active waiver should allow the deployment to proceed."""

    async def scenario(session: AsyncSession) -> None:
        waiver_payload = WaiverCreate(
            cve_id="CVE-2024-1111",
            service_name="payments",
            justification="Compensating controls deployed across edge fleet",
            approved_by="security-director",
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            requested_by="security-analyst",
        )

        created = await create_waiver(waiver_payload, db=session)
        assert created.cve_id == "CVE-2024-1111"
        assert created.status == "active"

        request = GateRequest(
            decision="ALLOW",
            confidence=0.91,
            signals={"kev_count": 1, "service_name": "payments"},
            findings=[{"cve_id": "CVE-2024-1111", "kev": True, "severity": "medium"}],
        )

        response = await evaluate_gate(request, db=session)

        assert response.allow is True
        assert response.reason == "Policy checks passed"

    run_with_session(scenario)
