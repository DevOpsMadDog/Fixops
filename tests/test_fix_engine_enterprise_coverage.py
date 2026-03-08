"""Tests for enterprise FixEngine — automated remediation recommendations."""
import asyncio

from core.services.enterprise.fix_engine import FixEngine, FixRecommendation


class TestFixRecommendation:
    def test_create_basic(self):
        rec = FixRecommendation(
            fix_id="FIX-001",
            title="Update package",
            description="Update to latest version",
            fix_type="dependency_update",
            confidence=0.95,
            effort_estimate="low",
            automated=True,
        )
        assert rec.fix_id == "FIX-001"
        assert rec.confidence == 0.95
        assert rec.automated is True

    def test_optional_fields(self):
        rec = FixRecommendation(
            fix_id="FIX-002",
            title="Apply patch",
            description="Security patch",
            fix_type="code_change",
            confidence=0.8,
            effort_estimate="high",
            automated=False,
        )
        assert rec.fix_content is None
        assert rec.validation_steps is None

    def test_with_fix_content(self):
        rec = FixRecommendation(
            fix_id="FIX-003",
            title="Config change",
            description="Update config",
            fix_type="config_change",
            confidence=0.7,
            effort_estimate="low",
            automated=True,
            fix_content="set secure=true",
            validation_steps=["Test login", "Check headers"],
        )
        assert rec.fix_content == "set secure=true"
        assert len(rec.validation_steps) == 2

    def test_fix_types(self):
        for ft in ["code_change", "config_change", "dependency_update"]:
            rec = FixRecommendation(
                fix_id="FIX-t", title="T", description="D",
                fix_type=ft, confidence=0.5, effort_estimate="medium",
                automated=False,
            )
            assert rec.fix_type == ft

    def test_effort_estimates(self):
        for effort in ["low", "medium", "high"]:
            rec = FixRecommendation(
                fix_id="FIX-e", title="T", description="D",
                fix_type="code_change", confidence=0.5,
                effort_estimate=effort, automated=False,
            )
            assert rec.effort_estimate == effort


class TestFixEngine:
    def test_init(self):
        engine = FixEngine()
        assert engine.initialized is False

    def test_initialize(self):
        engine = FixEngine()
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(engine.initialize())
        finally:
            loop.close()
        assert engine.initialized is True

    def test_get_fix_recommendations(self):
        engine = FixEngine()
        loop = asyncio.new_event_loop()
        try:
            recs = loop.run_until_complete(
                engine.get_fix_recommendations("CVE-2024-1234")
            )
        finally:
            loop.close()
        assert len(recs) == 2
        assert all(isinstance(r, FixRecommendation) for r in recs)
        assert recs[0].fix_id == "FIX-CVE-2024-1234-001"

    def test_get_fix_recommendations_auto_initializes(self):
        engine = FixEngine()
        assert engine.initialized is False
        loop = asyncio.new_event_loop()
        try:
            recs = loop.run_until_complete(
                engine.get_fix_recommendations("test-finding")
            )
        finally:
            loop.close()
        assert engine.initialized is True
        assert len(recs) > 0

    def test_apply_automated_fix(self):
        engine = FixEngine()
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                engine.apply_automated_fix("FIX-001")
            )
        finally:
            loop.close()
        assert isinstance(result, dict)
