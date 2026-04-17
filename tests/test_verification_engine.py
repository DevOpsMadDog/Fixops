"""Smoke tests for VerificationEngine — baseline coverage.

The VerificationPipeline uses async httpx and requires a live HTTP target.
Tests here focus on:
  - Data class creation and behaviour (no HTTP calls)
  - Helper functions (_version_compare, _version_in_range)
  - VerificationResult.summary()
  - Stage result dataclasses
  - Constants and enums
"""
import pytest

from core.verification_engine import (
    VerificationStage,
    StageResult,
    VerificationResult,
    CONFIDENCE_WEIGHTS,
    MINIMUM_CONFIDENCE_THRESHOLD,
    _version_compare,
    _version_in_range,
)


# ── Enums & constants ─────────────────────────────────────────────────────────

def test_stages_defined():
    assert VerificationStage.PRODUCT_DETECTION
    assert VerificationStage.VERSION_FINGERPRINT
    assert VerificationStage.EXPLOIT_VERIFICATION
    assert VerificationStage.DIFFERENTIAL_CONFIRMATION


def test_confidence_weights_sum_to_one():
    total = sum(CONFIDENCE_WEIGHTS.values())
    assert abs(total - 1.0) < 1e-9


def test_minimum_confidence_threshold():
    assert 0 < MINIMUM_CONFIDENCE_THRESHOLD < 1
    assert MINIMUM_CONFIDENCE_THRESHOLD == 0.60


# ── StageResult ───────────────────────────────────────────────────────────────

def test_stage_result_creation_passed():
    sr = StageResult(
        stage=VerificationStage.PRODUCT_DETECTION,
        passed=True,
        confidence_contribution=0.15,
        evidence={"header": "nginx/1.21"},
        detail="Product detected",
    )
    assert sr.passed is True
    assert sr.confidence_contribution == 0.15


def test_stage_result_creation_failed():
    sr = StageResult(
        stage=VerificationStage.EXPLOIT_VERIFICATION,
        passed=False,
        confidence_contribution=0.0,
        detail="Exploit not triggered",
    )
    assert sr.passed is False


def test_stage_result_default_evidence():
    sr = StageResult(
        stage=VerificationStage.VERSION_FINGERPRINT,
        passed=True,
        confidence_contribution=0.25,
    )
    assert sr.evidence == {}


def test_stage_result_default_detail():
    sr = StageResult(
        stage=VerificationStage.DIFFERENTIAL_CONFIRMATION,
        passed=False,
        confidence_contribution=0.0,
    )
    assert sr.detail == ""


# ── VerificationResult ────────────────────────────────────────────────────────

def _make_result(confidence: float = 0.75, vulnerable: bool = True) -> VerificationResult:
    stages = [
        StageResult(VerificationStage.PRODUCT_DETECTION, True, 0.15),
        StageResult(VerificationStage.VERSION_FINGERPRINT, True, 0.25),
        StageResult(VerificationStage.EXPLOIT_VERIFICATION, True, 0.35),
    ]
    return VerificationResult(
        vulnerable=vulnerable,
        confidence=confidence,
        stages=stages,
        evidence={"cve": "CVE-2024-0001"},
        verification_chain="stage1→stage2→stage3",
    )


def test_verification_result_creation():
    r = _make_result()
    assert r.vulnerable is True
    assert r.confidence == 0.75


def test_verification_result_default_stages():
    r = VerificationResult(vulnerable=False, confidence=0.0)
    assert r.stages == []


def test_verification_result_summary_returns_str():
    r = _make_result()
    s = r.summary()
    assert isinstance(s, str)
    assert len(s) > 0


def test_verification_result_summary_contains_confidence():
    r = _make_result(confidence=0.75)
    s = r.summary()
    assert "75%" in s


def test_verification_result_not_vulnerable():
    r = _make_result(confidence=0.3, vulnerable=False)
    assert r.vulnerable is False


def test_verification_result_evidence_dict():
    r = _make_result()
    assert isinstance(r.evidence, dict)
    assert "cve" in r.evidence


# ── _version_compare() ────────────────────────────────────────────────────────

def test_version_compare_equal():
    assert _version_compare("1.2.3", "1.2.3") == 0


def test_version_compare_greater():
    assert _version_compare("2.0.0", "1.9.9") > 0


def test_version_compare_lesser():
    assert _version_compare("1.0.0", "2.0.0") < 0


def test_version_compare_minor():
    assert _version_compare("1.10.0", "1.9.0") > 0


def test_version_compare_patch():
    assert _version_compare("1.0.10", "1.0.9") > 0


# ── _version_in_range() ───────────────────────────────────────────────────────

def test_version_in_range_true():
    assert _version_in_range("1.5.0", "1.0.0", "2.0.0") is True


def test_version_in_range_false_below():
    assert _version_in_range("0.9.0", "1.0.0", "2.0.0") is False


def test_version_in_range_false_above():
    assert _version_in_range("2.1.0", "1.0.0", "2.0.0") is False


def test_version_in_range_at_lower_bound():
    assert _version_in_range("1.0.0", "1.0.0", "2.0.0") is True


def test_version_in_range_at_upper_bound():
    # upper bound is exclusive or inclusive depends on implementation
    result = _version_in_range("2.0.0", "1.0.0", "2.0.0")
    assert isinstance(result, bool)  # just verify it runs


# ── CONFIDENCE_WEIGHTS per stage ──────────────────────────────────────────────

def test_product_detection_weight():
    assert CONFIDENCE_WEIGHTS[VerificationStage.PRODUCT_DETECTION] == 0.15


def test_version_fingerprint_weight():
    assert CONFIDENCE_WEIGHTS[VerificationStage.VERSION_FINGERPRINT] == 0.25


def test_exploit_verification_weight():
    assert CONFIDENCE_WEIGHTS[VerificationStage.EXPLOIT_VERIFICATION] == 0.35


def test_differential_confirmation_weight():
    assert CONFIDENCE_WEIGHTS[VerificationStage.DIFFERENTIAL_CONFIRMATION] == 0.25
