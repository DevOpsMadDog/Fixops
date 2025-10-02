import json
import os
import sys
from pathlib import Path
from typing import Dict

sys.path.append(str(Path(__file__).resolve().parent.parent / "fixops-blended-enterprise"))
os.environ.setdefault("SECRET_KEY", "test-secret-key")

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from src.config import settings as settings_module
from src.db.session import DatabaseManager
from src.db import session as session_module
from src.models.base_sqlite import Base
import src.models.security_sqlite  # noqa: F401 - ensure models are registered
from src.models.security_sqlite import PolicyDecisionLog, PolicyRule
from src.services.decision_engine import DecisionContext, DecisionEngine
from src.services import cache_service
from src.services import real_opa_engine
from src.services import decision_engine as decision_engine_module


async def _initialize_database(db_url: str):
    engine = create_async_engine(db_url, future=True, poolclass=NullPool)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return engine


def _make_log_context(category: str) -> Dict:
    return {
        "service_name": "payments-service",
        "environment": "production",
        "business_context": {"data_classification": ["PII"]},
        "security_findings": [
            {
                "category": category,
                "severity": "CRITICAL",
                "cve": "CVE-2024-9999",
                "rule_id": "SQL001",
            }
        ],
    }


@pytest.mark.asyncio
async def test_decision_engine_uses_real_regression_stats(tmp_path, monkeypatch):
    db_file = tmp_path / "regression.db"
    db_url = f"sqlite+aiosqlite:///{db_file}"

    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")

    settings_module.get_settings.cache_clear()
    settings = settings_module.get_settings()

    session_module.settings = settings
    decision_engine_module.settings = settings
    cache_service.settings = settings
    real_opa_engine.settings = settings
    cache_service.CacheService._in_memory_cache = {}

    test_engine = await _initialize_database(settings.DATABASE_URL)
    DatabaseManager._engine = test_engine
    DatabaseManager._sessionmaker = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=True,
        autocommit=False,
    )

    async with DatabaseManager.get_session_context() as session:
        rule = PolicyRule(
            name="payments-critical-window",
            description="Regression baseline for payments",
            rule_type="python",
            rule_content="allow",
            environments=json.dumps(["production"]),
            data_classifications=json.dumps(["pii"]),
            scanner_types=json.dumps(["sast"]),
            default_decision="allow",
        )
        session.add(rule)
        await session.flush()

        base_context = _make_log_context("sql_injection")
        secondary_context = _make_log_context("auth_bypass")
        secondary_context["security_findings"].append(
            {
                "category": "sql_injection",
                "severity": "CRITICAL",
                "cve": "CVE-2024-8888",
                "rule_id": "SQL001",
            }
        )

        log_one = PolicyDecisionLog(
            policy_rule_id=rule.id,
            decision="allow",
            confidence=0.92,
            decision_rationale="Historical approval for identical scenario",
            execution_time_ms=25.1,
        )
        log_one.set_input_context(base_context)
        session.add(log_one)

        log_two = PolicyDecisionLog(
            policy_rule_id=rule.id,
            decision="defer",
            confidence=0.81,
            decision_rationale="Additional controls required",
            execution_time_ms=32.4,
        )
        log_two.set_input_context(secondary_context)
        session.add(log_two)

    real_opa_engine._opa_engine_instance = real_opa_engine.DemoOPAEngine()

    engine = DecisionEngine()
    decision_context = DecisionContext(
        service_name="payments-service",
        environment="production",
        business_context={"data_classification": ["PII"]},
        security_findings=[
            {
                "category": "sql_injection",
                "severity": "CRITICAL",
                "cve": "CVE-2024-9999",
                "rule_id": "SQL001",
                "description": "SQL injection vulnerability detected in payment workflow",
            }
        ],
    )

    result = await engine.make_decision(decision_context)

    regression = result.validation_results["golden_regression"]

    assert regression["status"] == "validated"
    assert regression["validation_passed"] is True
    assert regression["confidence"] >= 0.75
    assert len(regression["similar_cases"]) == 2

    top_case = regression["similar_cases"][0]
    assert "service" in top_case["matched_attributes"]
    assert top_case["matched_attributes"]["service"] == "payments-service"
    assert top_case["matched_attributes"]["categories"] == ["sql_injection"]

    component_scores = result.consensus_details["component_scores"]
    assert component_scores["golden_regression"] == regression["confidence"]

    await DatabaseManager.close()
    real_opa_engine._opa_engine_instance = None
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DEMO_MODE", raising=False)
    settings_module.get_settings.cache_clear()
    default_settings = settings_module.get_settings()
    session_module.settings = default_settings
    decision_engine_module.settings = default_settings
    cache_service.settings = default_settings
    real_opa_engine.settings = default_settings
