"""Tenant directories must be distinguishable from platform storage.

Tenant data and the platform's own folders share one root, so a bare directory
listing cannot tell a customer from a system folder. Measured 2026-08-16 against
the running container, ``GET /api/v1/tenants`` returned 20 entries — "backups",
"keys", "evidence", "uploads", "deduplication", "policies" and friends — every
one of them platform storage, and not a single real customer.

That is not merely cosmetic. ``delete_tenant_data()`` resolves the name straight
to a path and calls ``shutil.rmtree`` on it, so an admin deleting the "backups"
entry they were shown would destroy the platform's backups.

These tests pin the marker that separates the two.
"""

from __future__ import annotations

import importlib

import pytest


@pytest.fixture()
def isolation(tmp_path, monkeypatch):
    """Load tenant_isolation against a throwaway data root."""
    monkeypatch.setenv("ALDECI_DATA_ROOT", str(tmp_path))
    module = importlib.import_module("core.tenant_isolation")
    module = importlib.reload(module)
    monkeypatch.setattr(module, "_DATA_ROOT", tmp_path, raising=False)
    return module, tmp_path


def test_platform_directories_are_not_reported_as_tenants(isolation) -> None:
    mod, root = isolation
    for system_dir in ("backups", "keys", "evidence", "uploads", "feeds", "policies"):
        (root / system_dir).mkdir()

    assert mod.list_tenants() == [], (
        "platform storage directories were reported as tenants — this is what put "
        "'backups' and 'keys' in the admin tenant list"
    )


def test_real_tenants_are_reported(isolation) -> None:
    mod, root = isolation
    (root / "backups").mkdir()  # platform storage, must stay hidden
    mod.ensure_tenant_directory("acme-corp")
    mod.ensure_tenant_directory("globex")

    assert mod.list_tenants() == ["acme-corp", "globex"]


def test_delete_refuses_platform_storage(isolation) -> None:
    mod, root = isolation
    backups = root / "backups"
    backups.mkdir()
    (backups / "critical.db").write_text("irreplaceable", encoding="utf-8")

    with pytest.raises(ValueError, match="not a tenant directory"):
        mod.delete_tenant_data("backups")

    assert (backups / "critical.db").exists(), "platform storage was deleted"


def test_delete_still_removes_a_real_tenant(isolation) -> None:
    mod, root = isolation
    tenant = mod.ensure_tenant_directory("acme-corp")
    (tenant / "findings.db").write_text("x", encoding="utf-8")

    mod.delete_tenant_data("acme-corp")

    assert not tenant.exists()
    assert mod.list_tenants() == []


def test_ensure_tenant_directory_is_idempotent(isolation) -> None:
    mod, _ = isolation
    first = mod.ensure_tenant_directory("acme-corp")
    (first / "findings.db").write_text("keep me", encoding="utf-8")

    second = mod.ensure_tenant_directory("acme-corp")

    assert first == second
    assert (second / "findings.db").read_text(encoding="utf-8") == "keep me"
    assert mod.list_tenants() == ["acme-corp"]
