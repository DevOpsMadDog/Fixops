import asyncio
import json
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

sys.path.append(str(Path(__file__).resolve().parents[1] / "fixops-blended-enterprise"))

from src.db.metrics_repository import DecisionMetricsRepository
from src.models.base_sqlite import Base
from src.models.security_sqlite import (
    PolicyDecisionLog,
    PolicyRule,
    SecurityFinding,
    Service,
)
from src.services.decision_engine import DecisionContext, DecisionEngine


async def _provision_environment(tmp_path):
    db_path = tmp_path / "metrics.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with session_factory() as session:
        service = Service(
            name="payments",
            description="Payments gateway",
            business_capability="billing",
            data_classification=json.dumps(["pci", "pii"]),
            environment="production",
            owner_team="payments",
            owner_email="payments@example.com",
            technical_lead="lead@example.com",
            repository_url="https://example.com/payments.git",
            deployment_url="https://deploy.example.com/payments",
            documentation_url="https://docs.example.com/payments",
            internet_facing=True,
            pci_scope=True,
            dependencies=json.dumps(["auth-service"]),
            tech_stack=json.dumps({"language": "python"}),
            sla_tier="gold",
            business_criticality="high",
        )

        policy_rule = PolicyRule(
            name="allow-mitigated-critical",
            description="Allow deployments with mitigations for critical findings",
            rule_type="python",
            rule_content="return True",
            environments=json.dumps(["production"]),
            data_classifications=json.dumps(["pci"]),
            scanner_types=json.dumps(["sast", "sca"]),
            nist_ssdf_controls=json.dumps(["RV.1"]),
            priority=10,
            active=True,
            default_decision="allow",
            escalation_threshold=1,
        )

        session.add_all([service, policy_rule])
        await session.flush()

        finding_primary = SecurityFinding(
            service_id=service.id,
            scanner_type="sast",
            scanner_name="CodeQL",
            scanner_version="2.0",
            rule_id="RULE-1",
            title="SQL Injection",
            description="Detected SQL injection",
            severity="CRITICAL",
            category="injection",
            status="open",
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

        finding_secondary = SecurityFinding(
            service_id=service.id,
            scanner_type="sca",
            scanner_name="Dependabot",
            scanner_version="2024.1",
            rule_id="RULE-2",
            title="Vulnerable dependency",
            description="Outdated dependency with CVE",
            severity="HIGH",
            category="dependency",
            status="open",
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

        decision_allow = PolicyDecisionLog(
            service_id=service.id,
            policy_rule_id=policy_rule.id,
            decision="ALLOW",
            confidence=0.92,
            input_context=json.dumps(
                {
                    "service_name": service.name,
                    "environment": "production",
                    "security_findings": [
                        {"id": "F-1", "severity": "CRITICAL"},
                        {"id": "F-2", "severity": "HIGH"},
                    ],
                    "enrichment_sources": ["vector_db", "threat_intel"],
                    "evidence_id": "EVD-001",
                }
            ),
            decision_rationale="Mitigations verified",
            execution_time_ms=190.0,
            policy_version="v1.0",
        )
        decision_allow.metadata_ = json.dumps(
            {"consensus_reached": True, "context_enriched": True}
        )

        decision_defer = PolicyDecisionLog(
            service_id=service.id,
            policy_rule_id=policy_rule.id,
            decision="DEFER",
            confidence=0.61,
            input_context=json.dumps(
                {
                    "service_name": "inventory",
                    "environment": "staging",
                    "security_findings": [
                        {"id": "F-3", "severity": "MEDIUM"}
                    ],
                }
            ),
            decision_rationale="Manual review required",
            execution_time_ms=410.0,
            policy_version=None,
        )

        session.add_all(
            [finding_primary, finding_secondary, decision_allow, decision_defer]
        )
        await session.commit()

    return {
        "engine": engine,
        "session_factory": session_factory,
        "service_name": service.name,
    }


@pytest.fixture
def seeded_environment(tmp_path, request):
    env = asyncio.run(_provision_environment(tmp_path))

    def _cleanup():
        asyncio.run(env["engine"].dispose())

    request.addfinalizer(_cleanup)
    return env


def test_collect_metrics_returns_live_counts(seeded_environment):
    session_factory = seeded_environment["session_factory"]

    async def _run():
        async with session_factory() as session:
            snapshot = await DecisionMetricsRepository.collect(session)

        assert snapshot.total_decisions == 2
        assert snapshot.pending_review == 1
        assert snapshot.high_confidence_rate == pytest.approx(0.5)
        assert snapshot.context_enrichment_rate == pytest.approx(0.5)
        assert snapshot.avg_decision_latency_us == pytest.approx(300000.0)
        assert snapshot.consensus_rate == pytest.approx(0.5)
        assert snapshot.evidence_records == 2
        assert snapshot.audit_compliance == pytest.approx(0.5)
        assert snapshot.component_status["vector_db"].startswith("production_active")
        assert snapshot.component_status["policy_engine"].endswith("1 policies)")

    asyncio.run(_run())


def test_get_decision_metrics_production_snapshot(seeded_environment, monkeypatch):
    session_factory = seeded_environment["session_factory"]

    @asynccontextmanager
    async def session_ctx():
        async with session_factory() as session:
            yield session

    monkeypatch.setattr(
        "src.services.decision_engine.DatabaseManager.get_session_context",
        session_ctx,
    )

    async def _run():
        engine = DecisionEngine()
        engine.demo_mode = False

        metrics = await engine.get_decision_metrics()

        assert metrics["demo_mode"] is False
        assert metrics["total_decisions"] == 2
        assert metrics["consensus_rate"] == pytest.approx(0.5)
        assert metrics["core_components"]["vector_db"].startswith("production_active")

    asyncio.run(_run())


def test_real_golden_regression_uses_historical_logs(seeded_environment, monkeypatch):
    session_factory = seeded_environment["session_factory"]
    service_name = seeded_environment["service_name"]

    @asynccontextmanager
    async def session_ctx():
        async with session_factory() as session:
            yield session

    monkeypatch.setattr(
        "src.services.decision_engine.DatabaseManager.get_session_context",
        session_ctx,
    )

    async def _run():
        engine = DecisionEngine()
        engine.demo_mode = False

        context = DecisionContext(
            service_name=service_name,
            environment="production",
            business_context={},
            security_findings=[
                {"id": "F-1", "severity": "CRITICAL"},
                {"id": "F-2", "severity": "HIGH"},
            ],
        )

        result = await engine._real_golden_regression_validation(context)

        assert result["status"] in {"validated", "review_required"}
        assert result["similar_cases"] >= 1
        assert result["confidence"] > 0
        assert result["top_matches"]

    asyncio.run(_run())
