"""Test that /api/v1/pag/accounts surfaces real Okta data.

Verifies the empty-endpoint fix (triage item #13): when the org has not
registered any privileged accounts, list_privileged_accounts_with_okta_fallback
falls back to a live OktaConnector sync and projects privileged Okta users
(admins, locked-out, suspended) as derived PAG account rows.

Stubs the OktaConnector via dependency injection — no network calls.
"""
from __future__ import annotations

from typing import Any, Dict, List

import pytest

from core.privileged_access_governance_engine import (
    PrivilegedAccessGovernanceEngine,
)


class _StubOkta:
    def __init__(self, sync_result: Dict[str, Any]) -> None:
        self._result = sync_result
        self.calls: List[str] = []

    def sync(self, org_id: str, force_refresh: bool = False) -> Dict[str, Any]:
        self.calls.append(org_id)
        return self._result


@pytest.fixture
def engine(tmp_path):
    return PrivilegedAccessGovernanceEngine(
        db_path=str(tmp_path / "pag.db")
    )


def test_no_org_accounts_no_creds_returns_needs_credentials(engine):
    stub = _StubOkta({
        "status": "needs_credentials",
        "users": [],
        "hint": "Set OKTA_API_KEY and OKTA_DOMAIN.",
    })
    res = engine.list_privileged_accounts_with_okta_fallback(
        "fresh-org", okta_connector=stub
    )
    assert res["accounts"] == []
    assert res["total"] == 0
    assert res["source"] == "needs_credentials"
    assert "OKTA" in res["hint"] or "Okta" in res["hint"]
    assert stub.calls == ["fresh-org"]


def test_empty_org_falls_back_to_okta_privileged_users(engine):
    """LOCKED_OUT and admin titles → derived PAG accounts."""
    stub = _StubOkta({
        "status": "ok",
        "users": [
            {
                "okta_user_id": "00u11111",
                "email": "alice@corp.io",
                "display_name": "Alice Smith",
                "title": "Senior DevOps Engineer",
                "department": "Platform",
                "status": "ACTIVE",
                "risk_level": "low",
                "last_login": "2026-04-30T10:00:00Z",
                "created_at": "2025-01-01T00:00:00Z",
            },
            {
                "okta_user_id": "00u22222",
                "email": "bob@corp.io",
                "display_name": "Bob Jones",
                "title": "Sales Rep",          # NOT privileged
                "department": "Sales",
                "status": "ACTIVE",
                "risk_level": "low",
            },
            {
                "okta_user_id": "00u33333",
                "email": "carol@corp.io",
                "display_name": "Carol Lee",
                "title": "Marketing",            # not by title
                "department": "Marketing",
                "status": "LOCKED_OUT",          # but privileged by status
                "risk_level": "high",
            },
        ],
    })
    res = engine.list_privileged_accounts_with_okta_fallback(
        "empty-org", okta_connector=stub
    )
    assert res["source"] == "okta-derived"
    assert res["total"] == 2
    by_user = {a["username"]: a for a in res["accounts"]}
    assert "alice@corp.io" in by_user
    assert "carol@corp.io" in by_user
    assert "bob@corp.io" not in by_user

    alice = by_user["alice@corp.io"]
    assert alice["account_type"] == "admin"
    assert alice["source"] == "okta"
    assert alice["okta_user_id"] == "00u11111"
    assert alice["system"] == "okta"

    carol = by_user["carol@corp.io"]
    assert carol["account_type"] == "service"
    assert carol["okta_status"] == "LOCKED_OUT"
    assert carol["risk_score"] >= 70  # high


def test_org_registered_accounts_take_precedence(engine):
    engine.register_privileged_account(
        "tier-org",
        {"username": "manual-svc-acct", "account_type": "service"},
    )
    # Even with Okta returning data, the org-registered row must win.
    stub = _StubOkta({
        "status": "ok",
        "users": [{"okta_user_id": "x", "email": "a@b.io",
                   "title": "admin", "status": "ACTIVE",
                   "display_name": "A", "risk_level": "low"}],
    })
    res = engine.list_privileged_accounts_with_okta_fallback(
        "tier-org", okta_connector=stub
    )
    assert res["source"] == "org_registered"
    assert res["total"] == 1
    assert res["accounts"][0]["username"] == "manual-svc-acct"
    # The connector should NOT be called when org has rows.
    assert stub.calls == []


def test_account_type_filter_applies_to_derived_rows(engine):
    stub = _StubOkta({
        "status": "ok",
        "users": [
            {"okta_user_id": "1", "email": "a1@x", "title": "Admin",
             "status": "ACTIVE", "display_name": "A1", "risk_level": "low"},
            {"okta_user_id": "2", "email": "a2@x", "title": "noop",
             "status": "SUSPENDED", "display_name": "A2", "risk_level": "high"},
        ],
    })
    res = engine.list_privileged_accounts_with_okta_fallback(
        "filt-org", account_type="admin", okta_connector=stub
    )
    assert res["total"] == 1
    assert res["accounts"][0]["okta_user_id"] == "1"


def test_okta_sync_error_returns_structured_response(engine):
    class _BoomOkta:
        def sync(self, org_id, force_refresh=False):
            raise RuntimeError("Okta API 500")

    res = engine.list_privileged_accounts_with_okta_fallback(
        "boom-org", okta_connector=_BoomOkta()
    )
    assert res["source"] == "okta_error"
    assert res["total"] == 0
    assert "Okta API 500" in res["hint"]


def test_okta_returns_no_privileged_users(engine):
    """Connector ok but everybody is a regular user → empty + hint."""
    stub = _StubOkta({
        "status": "ok",
        "users": [
            {"okta_user_id": "1", "email": "u1@x", "title": "Sales",
             "status": "ACTIVE", "display_name": "U1", "risk_level": "low"},
        ],
    })
    res = engine.list_privileged_accounts_with_okta_fallback(
        "noop-org", okta_connector=stub
    )
    assert res["source"] == "okta_no_privileged_users"
    assert res["total"] == 0
    assert res["okta_users_synced"] == 1
    assert "manually" in (res["hint"] or "").lower()
