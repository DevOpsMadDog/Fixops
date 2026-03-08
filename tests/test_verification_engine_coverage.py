"""Tests for core.verification_engine — multi-stage CVE verification pipeline."""

import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.verification_engine import (  # noqa: E402
    CONFIDENCE_WEIGHTS,
    MINIMUM_CONFIDENCE_THRESHOLD,
    StageResult,
    VerificationResult,
    VerificationStage,
)


# ---------------------------------------------------------------------------
# VerificationStage enum
# ---------------------------------------------------------------------------


class TestVerificationStage:
    def test_all_stages(self):
        assert VerificationStage.PRODUCT_DETECTION.value == "product_detection"
        assert VerificationStage.VERSION_FINGERPRINT.value == "version_fingerprint"
        assert VerificationStage.EXPLOIT_VERIFICATION.value == "exploit_verification"
        assert VerificationStage.DIFFERENTIAL_CONFIRMATION.value == "differential_confirmation"
        assert len(VerificationStage) == 4


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestConfidenceWeights:
    def test_weights_sum_to_one(self):
        total = sum(CONFIDENCE_WEIGHTS.values())
        assert abs(total - 1.0) < 0.01

    def test_all_stages_have_weights(self):
        for stage in VerificationStage:
            assert stage in CONFIDENCE_WEIGHTS

    def test_minimum_threshold(self):
        assert MINIMUM_CONFIDENCE_THRESHOLD == 0.60


# ---------------------------------------------------------------------------
# StageResult
# ---------------------------------------------------------------------------


class TestStageResult:
    def test_passed(self):
        r = StageResult(
            stage=VerificationStage.PRODUCT_DETECTION,
            passed=True,
            confidence_contribution=0.15,
            evidence={"product": "nginx", "detected": True},
            detail="Detected nginx/1.21.0",
        )
        assert r.passed is True
        assert r.confidence_contribution == 0.15
        assert r.evidence["product"] == "nginx"

    def test_failed(self):
        r = StageResult(
            stage=VerificationStage.EXPLOIT_VERIFICATION,
            passed=False,
            confidence_contribution=0.0,
        )
        assert r.passed is False
        assert r.detail == ""

    def test_defaults(self):
        r = StageResult(
            stage=VerificationStage.VERSION_FINGERPRINT,
            passed=True,
            confidence_contribution=0.25,
        )
        assert r.evidence == {}
        assert r.detail == ""


# ---------------------------------------------------------------------------
# VerificationResult
# ---------------------------------------------------------------------------


class TestVerificationResult:
    def test_vulnerable_result(self):
        stages = [
            StageResult(VerificationStage.PRODUCT_DETECTION, True, 0.15),
            StageResult(VerificationStage.VERSION_FINGERPRINT, True, 0.25),
            StageResult(VerificationStage.EXPLOIT_VERIFICATION, True, 0.35),
            StageResult(VerificationStage.DIFFERENTIAL_CONFIRMATION, True, 0.25),
        ]
        result = VerificationResult(
            vulnerable=True,
            confidence=1.0,
            stages=stages,
            evidence={"cve": "CVE-2024-1234"},
        )
        assert result.vulnerable is True
        assert result.confidence == 1.0
        assert len(result.stages) == 4

    def test_not_vulnerable(self):
        result = VerificationResult(
            vulnerable=False,
            confidence=0.15,
            stages=[StageResult(VerificationStage.PRODUCT_DETECTION, True, 0.15)],
        )
        assert result.vulnerable is False
        assert result.confidence < MINIMUM_CONFIDENCE_THRESHOLD

    def test_summary(self):
        stages = [
            StageResult(VerificationStage.PRODUCT_DETECTION, True, 0.15),
            StageResult(VerificationStage.VERSION_FINGERPRINT, False, 0.0),
        ]
        result = VerificationResult(
            vulnerable=False, confidence=0.15, stages=stages,
        )
        summary = result.summary()
        assert "product_detection" in summary
        assert "version_fingerprint" in summary
        assert "✓" in summary
        assert "✗" in summary

    def test_empty_stages(self):
        result = VerificationResult(vulnerable=False, confidence=0.0)
        assert result.stages == []
        assert result.summary() == "[0%] "

    def test_verification_chain(self):
        result = VerificationResult(
            vulnerable=True, confidence=0.75,
            verification_chain="sha256:abc123",
        )
        assert result.verification_chain == "sha256:abc123"

    def test_all_stages_pass(self):
        """Full confidence when all stages pass."""
        confidence = sum(CONFIDENCE_WEIGHTS.values())
        stages = [
            StageResult(stage, True, CONFIDENCE_WEIGHTS[stage])
            for stage in VerificationStage
        ]
        result = VerificationResult(
            vulnerable=True, confidence=confidence, stages=stages,
        )
        assert result.confidence >= MINIMUM_CONFIDENCE_THRESHOLD

    def test_only_product_not_enough(self):
        """Product detection alone is not enough for vulnerable status."""
        result = VerificationResult(
            vulnerable=False,
            confidence=CONFIDENCE_WEIGHTS[VerificationStage.PRODUCT_DETECTION],
        )
        assert result.confidence < MINIMUM_CONFIDENCE_THRESHOLD
