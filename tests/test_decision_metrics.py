import os
import sys
from pathlib import Path

import pytest
import pytest_asyncio


# Ensure the application package is importable
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(REPO_ROOT / "fixops-blended-enterprise"))

TEST_DB_PATH = REPO_ROOT / "test_decision_metrics.db"


os.environ.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{TEST_DB_PATH}")
os.environ.setdefault("DEMO_MODE", "false")
os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("SECRET_KEY", "test-secret")

from src.config.settings import get_settings

get_settings.cache_clear()
settings = get_settings()

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from src.db.session import DatabaseManager
from src.models.base_sqlite import Base
from src.models.security_sqlite import PolicyDecisionLog, PolicyRule
from src.services.decision_engine import DecisionEngine


@pytest_asyncio.fixture
async def seeded_policy_logs():
    if DatabaseManager._engine is not None:
        await DatabaseManager.close()

    engine = create_async_engine(
        os.environ["DATABASE_URL"],
        poolclass=NullPool,
        future=True,
    )
    DatabaseManager._engine = engine
    DatabaseManager._sessionmaker = async_sessionmaker(  # type: ignore[attr-defined]
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=True,
        autocommit=False,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with DatabaseManager.get_session_context() as session:
        rule = PolicyRule(
            name="payment-sla",
            description="Test policy rule",
            rule_type="python",
            rule_content="print('enforce')",
            priority=100,
            active=True,
            default_decision="ALLOW",
        )
        rule.set_environments(["production"])
        rule.set_data_classifications(["pci"])

        session.add(rule)
        await session.flush()

        log_allow = PolicyDecisionLog(
            policy_rule_id=rule.id,
            decision="ALLOW",
            confidence=0.92,
            decision_rationale="Meets policy requirements",
            execution_time_ms=10.0,
            policy_version="1.0",
        )
        log_allow.set_input_context({"enriched": True})

        log_block = PolicyDecisionLog(
            policy_rule_id=rule.id,
            decision="BLOCK",
            confidence=0.85,
            decision_rationale="Violates policy",
            execution_time_ms=20.0,
            policy_version="1.0",
        )
        log_block.set_input_context({"enriched": True, "sources": ["sbom"]})

        log_defer = PolicyDecisionLog(
            policy_rule_id=rule.id,
            decision="DEFER",
            confidence=0.55,
            decision_rationale="Needs manual review",
            execution_time_ms=40.0,
            policy_version="1.0",
        )
        log_defer.set_input_context({})

        session.add_all([log_allow, log_block, log_defer])

    yield

    await DatabaseManager.close()
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()


@pytest.mark.asyncio
async def test_get_decision_metrics_production(seeded_policy_logs):
    engine = DecisionEngine()
    engine.demo_mode = False

    metrics = await engine.get_decision_metrics()

    assert metrics["demo_mode"] is False
    assert metrics["total_decisions"] == 3
    assert metrics["pending_review"] == 1
    assert metrics["high_confidence_rate"] == pytest.approx(2 / 3)
    assert metrics["consensus_rate"] == pytest.approx(2 / 3)
    assert metrics["context_enrichment_rate"] == pytest.approx(2 / 3)
    assert metrics["avg_decision_latency_us"] == pytest.approx((10 + 20 + 40) / 3 * 1000)

    percentiles = metrics["latency_percentiles_us"]
    assert percentiles["p50"] == pytest.approx(20_000.0)
    assert percentiles["p95"] == pytest.approx(38_000.0)
    assert percentiles["p99"] == pytest.approx(39_600.0)


@pytest.mark.asyncio
async def test_get_decision_metrics_demo_mode():
    engine = DecisionEngine()
    engine.demo_mode = True
    await engine._initialize_demo_mode()

    metrics = await engine.get_decision_metrics()

    assert metrics["demo_mode"] is True
    assert metrics["total_decisions"] == 234
    assert metrics["mode_indicator"] == "🎭 DEMO MODE"
