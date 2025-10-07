"""OPA integration tests for the policy evaluation endpoint."""

from __future__ import annotations

from typing import Any, Dict

import pytest

from src.api.v1 import policy
from tests.test_policy_kevs import run_with_session


class _StubEngine:
    def __init__(self, *, decision: Dict[str, Any]) -> None:
        self._decision = decision
        self.seen_payloads: list[Dict[str, Any]] = []

    async def health_check(self) -> bool:
        return True

    async def evaluate_policy(self, policy_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        self.seen_payloads.append({"name": policy_name, "payload": payload})
        return dict(self._decision)


async def _evaluate_with_stub(
    monkeypatch: pytest.MonkeyPatch,
    engine: _StubEngine,
    db_session: Any,
) -> policy.GateResponse:
    monkeypatch.setattr(policy.settings, "DEMO_MODE", False)
    monkeypatch.setattr(policy.settings, "OPA_SERVER_URL", "https://opa.example.com")

    async def _get_engine() -> _StubEngine:
        return engine

    monkeypatch.setattr(policy, "get_opa_engine", _get_engine)

    request = policy.GateRequest(
        decision="ALLOW",
        confidence=0.95,
        signals={"environment": "prod"},
        findings=[
            {
                "id": "finding-1",
                "cve_id": "CVE-2024-9999",
                "severity": "high",
                "fix_available": True,
            }
        ],
    )

    return await policy.evaluate_gate(request, db=db_session)


def test_policy_blocks_when_opa_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    """OPA block responses should fail the gate even when local checks pass."""

    async def scenario(session: Any) -> None:
        engine = _StubEngine(decision={"decision": "block", "rationale": "policy violation"})
        response = await _evaluate_with_stub(monkeypatch, engine, session)
        assert response.allow is False
        assert "OPA policy" in response.reason
        assert engine.seen_payloads and engine.seen_payloads[0]["name"] == "vulnerability"

    run_with_session(scenario)


def test_policy_allows_when_opa_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """OPA allow responses should permit the deployment when no other guardrail blocks it."""

    async def scenario(session: Any) -> None:
        engine = _StubEngine(decision={"decision": "allow", "rationale": "policy satisfied"})
        response = await _evaluate_with_stub(monkeypatch, engine, session)
        assert response.allow is True
        assert response.reason == "Policy checks passed"
        assert engine.seen_payloads

    run_with_session(scenario)
