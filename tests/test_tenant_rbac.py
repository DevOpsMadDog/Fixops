from __future__ import annotations

import asyncio
import types

import pytest
from core.enterprise import security


def test_user_has_tenant_role(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _run() -> None:
        user = types.SimpleNamespace(
            get_tenant_roles=lambda: {"tenant-a": ["owner", "auditor"]}
        )

        async def fake_get_user(cls, user_id: str):  # type: ignore[override]
            return user

        monkeypatch.setattr(
            security.RBACManager, "_get_user", classmethod(fake_get_user)
        )

        assert await security.RBACManager.user_has_tenant_role(
            "1", "tenant-a", security.TenantPersona.AUDITOR
        )
        assert not await security.RBACManager.user_has_tenant_role(
            "1", "tenant-b", security.TenantPersona.AUDITOR
        )

    asyncio.run(_run())
