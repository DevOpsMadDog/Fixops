"""
Comprehensive tests for Supply Chain Security Engine.

Covers:
- SBOM parsing (CycloneDX + SPDX)
- Dependency risk scoring (all dimensions)
- Supply chain attack detection (typosquatting, dependency confusion, version bumps)
- Provenance verification (SLSA levels, attestation parsing, signature stubs)
- Policy engine (license, CVE, depth, provenance, risk score rules)
- Vendor risk assessment (creation, concentration risk, listing)
- Full engine integration (ingest -> score -> detect -> policy)
- REST API endpoints (via FastAPI TestClient)

All tests use in-memory SQLite (tmp_path). No network calls. No external deps.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict
from unittest.mock import patch

import pytest

os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.supply_chain_security import (
    AttackDetector,
    AttackType,
    DependencyRiskScorer,
    LicenseRisk,
    PolicyAction,
    PolicyEngine,
    ProvenanceLevel,
    ProvenanceVerifier,
    RiskLevel,
    SBOMComponent,
    SBOMFormat,
    SupplyChainEngine,
    SupplyChainPolicy,
    VendorRiskAssessment,
    VendorTier,
    _classify_license_risk,
    _detect_sbom_format,
    _levenshtein,
    _parse_cyclonedx,
    _parse_spdx,
    _parse_version_tuple,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_db(tmp_path):
    return str(tmp_path / "test_supply_chain.db")


@pytest.fixture()
def engine(tmp_db):
    return SupplyChainEngine(db_path=tmp_db)


@pytest.fixture()
def scorer():
    return DependencyRiskScorer()


@pytest.fixture()
def detector():
    return AttackDetector()


@pytest.fixture()
def verifier():
    return ProvenanceVerifier()


@pytest.fixture()
def policy_engine():
    return PolicyEngine()


def _make_component(**kwargs) -> SBOMComponent:
    defaults = dict(
        name="requests",
        version="2.28.0",
        ecosystem="pypi",
        license_id="Apache-2.0",
        license_risk=LicenseRisk.LOW,
        sbom_id=str(uuid.uuid4()),
    )
    defaults.update(kwargs)
    return SBOMComponent(**defaults)


def _cyclonedx_payload(components=None) -> Dict[str, Any]:
    comps = components or [
        {"name": "requests", "version": "2.28.0", "purl": "pkg:pypi/requests@2.28.0",
         "licenses": [{"license": {"id": "Apache-2.0"}}]},
        {"name": "flask", "version": "2.3.0", "purl": "pkg:pypi/flask@2.3.0",
         "licenses": [{"license": {"id": "BSD-3-Clause"}}]},
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"name": "my-app", "version": "1.0.0"}},
        "components": comps,
    }


def _spdx_payload(packages=None) -> Dict[str, Any]:
    pkgs = packages or [
        {
            "name": "my-app",
            "versionInfo": "1.0.0",
            "licenseConcluded": "MIT",
            "licenseDeclared": "MIT",
        },
        {
            "name": "numpy",
            "versionInfo": "1.24.0",
            "licenseConcluded": "BSD-3-Clause",
            "licenseDeclared": "BSD-3-Clause",
            "externalRefs": [{"referenceLocator": "pkg:pypi/numpy@1.24.0"}],
        },
    ]
    return {
        "spdxVersion": "SPDX-2.3",
        "name": "my-spdx-app",
        "packages": pkgs,
    }


# ---------------------------------------------------------------------------
# 1. Utility helpers
# ---------------------------------------------------------------------------


class TestLevenshtein:
    def test_identical(self):
        assert _levenshtein("abc", "abc") == 0

    def test_single_substitution(self):
        assert _levenshtein("cat", "bat") == 1

    def test_single_insertion(self):
        assert _levenshtein("abc", "abcd") == 1

    def test_single_deletion(self):
        assert _levenshtein("abcd", "abc") == 1

    def test_empty_strings(self):
        assert _levenshtein("", "") == 0

    def test_one_empty(self):
        assert _levenshtein("abc", "") == 3

    def test_typosquat_example(self):
        # requets vs requests — distance 1
        assert _levenshtein("requets", "requests") == 1


class TestClassifyLicenseRisk:
    def test_apache_is_low(self):
        assert _classify_license_risk("Apache-2.0") == LicenseRisk.LOW

    def test_mit_is_low(self):
        assert _classify_license_risk("MIT") == LicenseRisk.LOW

    def test_gpl2_is_high(self):
        assert _classify_license_risk("GPL-2.0") == LicenseRisk.HIGH

    def test_agpl_is_high(self):
        assert _classify_license_risk("AGPL-3.0") == LicenseRisk.HIGH

    def test_mpl_is_medium(self):
        assert _classify_license_risk("MPL-2.0") == LicenseRisk.MEDIUM

    def test_unknown_is_unknown(self):
        assert _classify_license_risk("UNKNOWN") == LicenseRisk.UNKNOWN

    def test_empty_is_unknown(self):
        assert _classify_license_risk("") == LicenseRisk.UNKNOWN

    def test_bsd3_is_low(self):
        assert _classify_license_risk("BSD-3-Clause") == LicenseRisk.LOW


class TestParseVersionTuple:
    def test_semver(self):
        assert _parse_version_tuple("1.2.3") == (1, 2, 3)

    def test_partial(self):
        assert _parse_version_tuple("2.0") == (2, 0, 0)

    def test_single(self):
        assert _parse_version_tuple("3") == (3, 0, 0)

    def test_with_suffix(self):
        v = _parse_version_tuple("1.2.3-alpha")
        assert v[0] == 1 and v[1] == 2 and v[2] == 3

    def test_empty(self):
        assert _parse_version_tuple("") == (0, 0, 0)


# ---------------------------------------------------------------------------
# 2. SBOM Format Detection
# ---------------------------------------------------------------------------


class TestSBOMFormatDetection:
    def test_detect_cyclonedx(self):
        assert _detect_sbom_format({"bomFormat": "CycloneDX"}) == SBOMFormat.CYCLONEDX

    def test_detect_spdx_via_version(self):
        assert _detect_sbom_format({"spdxVersion": "SPDX-2.3"}) == SBOMFormat.SPDX

    def test_detect_cyclonedx_via_components(self):
        assert _detect_sbom_format({"components": []}) == SBOMFormat.CYCLONEDX

    def test_unknown_format(self):
        assert _detect_sbom_format({"foo": "bar"}) == SBOMFormat.UNKNOWN


# ---------------------------------------------------------------------------
# 3. SBOM Parsing
# ---------------------------------------------------------------------------


class TestCycloneDXParser:
    def test_basic_parse(self):
        sbom_id = str(uuid.uuid4())
        record, components = _parse_cyclonedx(_cyclonedx_payload(), sbom_id)
        assert record.format == SBOMFormat.CYCLONEDX
        assert record.name == "my-app"
        assert record.version == "1.0.0"
        assert len(components) == 2

    def test_component_names(self):
        sbom_id = str(uuid.uuid4())
        _, components = _parse_cyclonedx(_cyclonedx_payload(), sbom_id)
        names = {c.name for c in components}
        assert "requests" in names
        assert "flask" in names

    def test_license_extracted(self):
        sbom_id = str(uuid.uuid4())
        _, components = _parse_cyclonedx(_cyclonedx_payload(), sbom_id)
        req = next(c for c in components if c.name == "requests")
        assert req.license_id == "Apache-2.0"

    def test_purl_extracted(self):
        sbom_id = str(uuid.uuid4())
        _, components = _parse_cyclonedx(_cyclonedx_payload(), sbom_id)
        req = next(c for c in components if c.name == "requests")
        assert req.purl == "pkg:pypi/requests@2.28.0"

    def test_ecosystem_from_purl(self):
        sbom_id = str(uuid.uuid4())
        _, components = _parse_cyclonedx(_cyclonedx_payload(), sbom_id)
        req = next(c for c in components if c.name == "requests")
        assert req.ecosystem == "pypi"

    def test_hashes_extracted(self):
        payload = _cyclonedx_payload([
            {"name": "pkg", "version": "1.0", "hashes": [{"alg": "SHA-256", "content": "abc123"}]}
        ])
        sbom_id = str(uuid.uuid4())
        _, components = _parse_cyclonedx(payload, sbom_id)
        assert components[0].hashes.get("sha256") == "abc123"

    def test_spec_version(self):
        sbom_id = str(uuid.uuid4())
        record, _ = _parse_cyclonedx(_cyclonedx_payload(), sbom_id)
        assert record.spec_version == "1.5"

    def test_empty_components(self):
        payload = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
        sbom_id = str(uuid.uuid4())
        _, components = _parse_cyclonedx(payload, sbom_id)
        assert components == []


class TestSPDXParser:
    def test_basic_parse(self):
        sbom_id = str(uuid.uuid4())
        record, components = _parse_spdx(_spdx_payload(), sbom_id)
        assert record.format == SBOMFormat.SPDX
        assert record.name == "my-spdx-app"
        assert len(components) == 2

    def test_license_extracted(self):
        sbom_id = str(uuid.uuid4())
        _, components = _parse_spdx(_spdx_payload(), sbom_id)
        app = next(c for c in components if c.name == "my-app")
        assert app.license_id == "MIT"

    def test_noassertion_falls_back_to_declared(self):
        payload = _spdx_payload([{
            "name": "pkg",
            "versionInfo": "1.0",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "Apache-2.0",
        }])
        sbom_id = str(uuid.uuid4())
        _, components = _parse_spdx(payload, sbom_id)
        assert components[0].license_id == "Apache-2.0"

    def test_both_noassertion_gives_unknown(self):
        payload = _spdx_payload([{
            "name": "pkg",
            "versionInfo": "1.0",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
        }])
        sbom_id = str(uuid.uuid4())
        _, components = _parse_spdx(payload, sbom_id)
        assert components[0].license_id == "UNKNOWN"

    def test_purl_from_external_refs(self):
        sbom_id = str(uuid.uuid4())
        _, components = _parse_spdx(_spdx_payload(), sbom_id)
        np = next(c for c in components if c.name == "numpy")
        assert np.purl == "pkg:pypi/numpy@1.24.0"


# ---------------------------------------------------------------------------
# 4. Risk Scorer
# ---------------------------------------------------------------------------


class TestDependencyRiskScorer:
    def test_clean_component_low_score(self, scorer):
        comp = _make_component()
        score = scorer.score(comp, cve_count=0, days_since_last_commit=30, weekly_downloads=1_000_000)
        assert score.overall_score < 35
        assert score.risk_level in (RiskLevel.LOW, RiskLevel.INFO)

    def test_critical_cves_raise_score(self, scorer):
        comp = _make_component()
        score = scorer.score(comp, cve_count=3, critical_cve_count=3)
        assert score.overall_score > 35

    def test_stale_repo_raises_score(self, scorer):
        comp = _make_component()
        score_fresh = scorer.score(comp, days_since_last_commit=10)
        score_stale = scorer.score(comp, days_since_last_commit=800)
        assert score_stale.overall_score > score_fresh.overall_score

    def test_high_license_risk_raises_score(self, scorer):
        comp_safe = _make_component(license_id="MIT", license_risk=LicenseRisk.LOW)
        comp_risky = _make_component(license_id="GPL-3.0", license_risk=LicenseRisk.HIGH)
        score_safe = scorer.score(comp_safe)
        score_risky = scorer.score(comp_risky)
        assert score_risky.overall_score > score_safe.overall_score

    def test_deep_transitive_raises_score(self, scorer):
        comp_direct = _make_component(transitive_depth=0)
        comp_deep = _make_component(transitive_depth=6)
        score_direct = scorer.score(comp_direct)
        score_deep = scorer.score(comp_deep)
        assert score_deep.overall_score > score_direct.overall_score

    def test_low_downloads_raises_score(self, scorer):
        comp = _make_component()
        score_popular = scorer.score(comp, weekly_downloads=500_000)
        score_obscure = scorer.score(comp, weekly_downloads=10)
        assert score_obscure.overall_score > score_popular.overall_score

    def test_slsa3_lowers_score(self, scorer):
        comp = _make_component()
        score_slsa0 = scorer.score(comp, provenance_level=ProvenanceLevel.SLSA_0)
        score_slsa3 = scorer.score(comp, provenance_level=ProvenanceLevel.SLSA_3)
        assert score_slsa3.overall_score < score_slsa0.overall_score

    def test_score_breakdown_keys(self, scorer):
        comp = _make_component()
        score = scorer.score(comp)
        assert set(score.score_breakdown.keys()) == {"cve", "maintenance", "license", "depth", "popularity", "provenance"}

    def test_score_bounded(self, scorer):
        comp = _make_component(license_id="GPL-3.0", license_risk=LicenseRisk.HIGH, transitive_depth=10)
        score = scorer.score(comp, cve_count=10, critical_cve_count=10)
        assert 0.0 <= score.overall_score <= 100.0

    def test_critical_risk_level(self, scorer):
        comp = _make_component(license_id="GPL-3.0", license_risk=LicenseRisk.HIGH, transitive_depth=5)
        score = scorer.score(comp, cve_count=5, critical_cve_count=4, weekly_downloads=5)
        assert score.risk_level == RiskLevel.CRITICAL


# ---------------------------------------------------------------------------
# 5. Attack Detector
# ---------------------------------------------------------------------------


class TestAttackDetector:
    def test_exact_match_not_flagged(self, detector):
        comp = _make_component(name="requests")
        sig = detector.detect_typosquatting(comp)
        assert sig is None

    def test_typosquat_detected(self, detector):
        comp = _make_component(name="requets")  # 1 edit from "requests"
        sig = detector.detect_typosquatting(comp)
        assert sig is not None
        assert sig.attack_type == AttackType.TYPOSQUATTING
        assert sig.similar_package == "requests"

    def test_far_name_not_flagged(self, detector):
        comp = _make_component(name="zzzz_completely_different")
        sig = detector.detect_typosquatting(comp)
        assert sig is None

    def test_typosquat_confidence_positive(self, detector):
        comp = _make_component(name="requets")
        sig = detector.detect_typosquatting(comp)
        assert sig.confidence > 0

    def test_dependency_confusion_internal_public_match(self, detector):
        comp = _make_component(name="requests", is_internal=True)
        sig = detector.detect_dependency_confusion(comp, internal_namespaces=[])
        assert sig is not None
        assert sig.attack_type == AttackType.DEPENDENCY_CONFUSION
        assert sig.confidence > 0.5

    def test_dependency_confusion_external_not_flagged(self, detector):
        comp = _make_component(name="requests", is_internal=False)
        sig = detector.detect_dependency_confusion(comp, internal_namespaces=[])
        assert sig is None

    def test_dependency_confusion_unique_internal_not_flagged(self, detector):
        comp = _make_component(name="my-unique-internal-lib", is_internal=True)
        sig = detector.detect_dependency_confusion(comp, internal_namespaces=["my-"])
        assert sig is None

    def test_version_bump_minor_not_flagged(self, detector):
        comp = _make_component(version="1.1.0")
        sig = detector.detect_version_bump(comp, previous_version="1.0.0")
        assert sig is None

    def test_version_bump_major_flagged(self, detector):
        comp = _make_component(version="3.0.0")
        sig = detector.detect_version_bump(comp, previous_version="1.0.0")
        assert sig is not None
        assert sig.attack_type == AttackType.VERSION_BUMP
        assert sig.evidence["major_jump"] == 2

    def test_version_bump_no_previous_not_flagged(self, detector):
        comp = _make_component(version="3.0.0")
        sig = detector.detect_version_bump(comp, previous_version=None)
        assert sig is None

    def test_scan_components_returns_list(self, detector):
        comps = [
            _make_component(name="requets"),          # typosquat
            _make_component(name="requests"),          # clean
            _make_component(name="flask", version="5.0.0"),  # version bump possible
        ]
        signals = detector.scan_components(comps, version_history={"flask": "2.0.0"})
        assert isinstance(signals, list)
        # At least the typosquat should be detected
        types = {s.attack_type for s in signals}
        assert AttackType.TYPOSQUATTING in types

    def test_scan_sets_org_id(self, detector):
        comps = [_make_component(name="requets")]
        signals = detector.scan_components(comps, org_id="acme")
        assert all(s.org_id == "acme" for s in signals)


# ---------------------------------------------------------------------------
# 6. Provenance Verifier
# ---------------------------------------------------------------------------


class TestProvenanceVerifier:
    def test_no_attestation_gives_slsa0(self, verifier):
        record = verifier.verify_attestation("pkg", "1.0")
        assert record.slsa_level == ProvenanceLevel.SLSA_0
        assert len(record.verification_errors) > 0

    def test_invalid_json_records_error(self, verifier):
        record = verifier.verify_attestation("pkg", "1.0", attestation_json="not-json")
        assert any("parse" in e.lower() or "json" in e.lower() for e in record.verification_errors)

    def test_github_builder_gives_slsa3(self, verifier):
        att = json.dumps({
            "predicate": {
                "builder": {"id": "https://github.com/actions/runner"},
                "buildType": "https://github.com/actions/workflow/v1",
            }
        })
        record = verifier.verify_attestation("pkg", "1.0", attestation_json=att)
        assert record.slsa_level == ProvenanceLevel.SLSA_3
        assert record.builder_id is not None

    def test_unknown_builder_gives_slsa1(self, verifier):
        att = json.dumps({
            "predicate": {
                "builder": {"id": "https://custom-builder.example.com"},
                "buildType": "custom",
            }
        })
        record = verifier.verify_attestation("pkg", "1.0", attestation_json=att)
        assert record.slsa_level == ProvenanceLevel.SLSA_1

    def test_signature_stub_no_match(self, verifier):
        record = verifier.verify_attestation(
            "pkg", "1.0",
            attestation_json=json.dumps({"predicate": {}}),
            signature="sig-xyz",
            expected_keyid="keyid-abc",
        )
        assert record.signature_verified is False

    def test_signature_stub_match(self, verifier):
        record = verifier.verify_attestation(
            "pkg", "1.0",
            attestation_json=json.dumps({"predicate": {}}),
            signature="contains-keyid-abc",
            expected_keyid="keyid-abc",
        )
        assert record.signature_verified is True
        assert record.signature_keyid == "keyid-abc"

    def test_record_has_component_name(self, verifier):
        record = verifier.verify_attestation("mypackage", "2.0")
        assert record.component_name == "mypackage"
        assert record.component_version == "2.0"


# ---------------------------------------------------------------------------
# 7. Policy Engine
# ---------------------------------------------------------------------------


class TestPolicyEngine:
    def _default_policy(self, **kwargs) -> SupplyChainPolicy:
        defaults = dict(
            name="test-policy",
            blocked_licenses=["GPL-2.0", "GPL-3.0", "AGPL-3.0"],
            max_critical_cves=0,
            max_overall_risk_score=80.0,
            action=PolicyAction.WARN,
        )
        defaults.update(kwargs)
        return SupplyChainPolicy(**defaults)

    def _score_for(self, comp, **kwargs):
        return DependencyRiskScorer().score(comp, **kwargs)

    def test_clean_component_no_violations(self, policy_engine):
        comp = _make_component()
        score = self._score_for(comp)
        policy = self._default_policy()
        violations = policy_engine.evaluate(comp, score, [policy])
        assert violations == []

    def test_blocked_license_triggers_violation(self, policy_engine):
        comp = _make_component(license_id="GPL-3.0", license_risk=LicenseRisk.HIGH)
        score = self._score_for(comp)
        policy = self._default_policy()
        violations = policy_engine.evaluate(comp, score, [policy])
        assert any("GPL-3.0" in v.reason or "license" in v.reason.lower() for v in violations)

    def test_critical_cve_triggers_violation(self, policy_engine):
        comp = _make_component()
        score = self._score_for(comp, critical_cve_count=2)
        policy = self._default_policy(max_critical_cves=0)
        violations = policy_engine.evaluate(comp, score, [policy])
        assert any("critical CVE" in v.reason for v in violations)

    def test_depth_limit_triggers_violation(self, policy_engine):
        comp = _make_component(transitive_depth=5)
        score = self._score_for(comp)
        policy = self._default_policy(max_transitive_depth=3)
        violations = policy_engine.evaluate(comp, score, [policy])
        assert any("depth" in v.reason.lower() for v in violations)

    def test_depth_within_limit_no_violation(self, policy_engine):
        comp = _make_component(transitive_depth=2)
        score = self._score_for(comp)
        policy = self._default_policy(max_transitive_depth=5)
        violations = policy_engine.evaluate(comp, score, [policy])
        assert not any("depth" in v.reason.lower() for v in violations)

    def test_risk_score_exceeds_max_triggers_violation(self, policy_engine):
        comp = _make_component(license_id="GPL-3.0", license_risk=LicenseRisk.HIGH, transitive_depth=5)
        score = self._score_for(comp, cve_count=5, critical_cve_count=4, weekly_downloads=5)
        policy = self._default_policy(max_overall_risk_score=10.0)
        violations = policy_engine.evaluate(comp, score, [policy])
        assert any("score" in v.reason.lower() for v in violations)

    def test_disabled_policy_not_evaluated(self, policy_engine):
        comp = _make_component(license_id="GPL-3.0", license_risk=LicenseRisk.HIGH)
        score = self._score_for(comp)
        policy = self._default_policy(enabled=False)
        violations = policy_engine.evaluate(comp, score, [policy])
        assert violations == []

    def test_no_provenance_violates_slsa_policy(self, policy_engine):
        comp = _make_component()
        score = self._score_for(comp)
        policy = self._default_policy(required_provenance_level=ProvenanceLevel.SLSA_2)
        violations = policy_engine.evaluate(comp, score, [policy], provenance=None)
        assert any("provenance" in v.reason.lower() or "slsa" in v.reason.lower() for v in violations)

    def test_action_carried_through(self, policy_engine):
        comp = _make_component(license_id="GPL-3.0", license_risk=LicenseRisk.HIGH)
        score = self._score_for(comp)
        policy = self._default_policy(action=PolicyAction.BLOCK)
        violations = policy_engine.evaluate(comp, score, [policy])
        assert all(v.action == PolicyAction.BLOCK for v in violations)


# ---------------------------------------------------------------------------
# 8. SupplyChainEngine — integration tests
# ---------------------------------------------------------------------------


class TestSupplyChainEngine:
    def test_ingest_cyclonedx(self, engine):
        record, comps, signals = engine.ingest_sbom(_cyclonedx_payload())
        assert record.format == SBOMFormat.CYCLONEDX
        assert record.component_count == 2
        assert len(comps) == 2

    def test_ingest_spdx(self, engine):
        record, comps, signals = engine.ingest_sbom(_spdx_payload())
        assert record.format == SBOMFormat.SPDX
        assert len(comps) == 2

    def test_ingest_unknown_format_raises(self, engine):
        with pytest.raises(ValueError, match="Unrecognised SBOM format"):
            engine.ingest_sbom({"foo": "bar"})

    def test_ingest_stores_sha256(self, engine):
        record, _, _ = engine.ingest_sbom(_cyclonedx_payload())
        assert len(record.sha256) == 64  # sha256 hex

    def test_ingest_source_repo(self, engine):
        record, _, _ = engine.ingest_sbom(_cyclonedx_payload(), source_repo="https://github.com/org/repo")
        assert record.source_repo == "https://github.com/org/repo"

    def test_list_components_returns_ingested(self, engine):
        engine.ingest_sbom(_cyclonedx_payload())
        comps = engine.list_components()
        assert len(comps) == 2
        names = {c["name"] for c in comps}
        assert "requests" in names

    def test_list_components_includes_risk_score(self, engine):
        engine.ingest_sbom(_cyclonedx_payload())
        comps = engine.list_components()
        assert all("risk_score" in c for c in comps)

    def test_risk_dashboard_empty(self, engine):
        dash = engine.get_risk_dashboard()
        assert dash.total_components == 0
        assert dash.total_sboms == 0

    def test_risk_dashboard_after_ingest(self, engine):
        engine.ingest_sbom(_cyclonedx_payload())
        dash = engine.get_risk_dashboard()
        assert dash.total_components == 2
        assert dash.total_sboms == 1

    def test_scan_repo_returns_job(self, engine):
        result = engine.scan_repo("https://github.com/org/repo")
        assert result["status"] == "queued"
        assert "scan_id" in result
        assert result["repo_url"] == "https://github.com/org/repo"

    def test_create_and_list_policy(self, engine):
        policy = SupplyChainPolicy(name="test-p", org_id="default")
        engine.create_policy(policy)
        policies = engine.list_policies()
        assert len(policies) == 1
        assert policies[0].name == "test-p"

    def test_create_policy_idempotent(self, engine):
        policy = SupplyChainPolicy(name="test-p", org_id="default")
        engine.create_policy(policy)
        engine.create_policy(policy)  # same ID = upsert
        policies = engine.list_policies()
        assert len(policies) == 1

    def test_get_policy_not_found(self, engine):
        result = engine.get_policy("nonexistent-id")
        assert result is None

    def test_upsert_and_list_vendor(self, engine):
        vendor = VendorRiskAssessment(vendor_name="Acme Corp", org_id="default")
        engine.upsert_vendor(vendor)
        vendors = engine.list_vendors()
        assert len(vendors) == 1
        assert vendors[0].vendor_name == "Acme Corp"

    def test_vendor_concentration_risk_critical(self, engine):
        vendor = VendorRiskAssessment(vendor_name="BigCo", component_count=60)
        result = engine.upsert_vendor(vendor)
        assert result.concentration_risk == RiskLevel.CRITICAL

    def test_vendor_concentration_risk_low(self, engine):
        vendor = VendorRiskAssessment(vendor_name="SmallCo", component_count=2)
        result = engine.upsert_vendor(vendor)
        assert result.concentration_risk == RiskLevel.LOW

    def test_verify_provenance_stored(self, engine):
        record = engine.verify_provenance("mypkg", "1.0")
        assert record.component_name == "mypkg"
        stored = engine.get_provenance("mypkg", "1.0")
        assert stored is not None
        assert stored.component_name == "mypkg"

    def test_get_provenance_not_found(self, engine):
        result = engine.get_provenance("nonexistent-pkg")
        assert result is None

    def test_org_isolation(self, engine):
        engine.ingest_sbom(_cyclonedx_payload(), org_id="org-a")
        engine.ingest_sbom(_spdx_payload(), org_id="org-b")
        comps_a = engine.list_components(org_id="org-a")
        comps_b = engine.list_components(org_id="org-b")
        assert len(comps_a) == 2
        assert len(comps_b) == 2

    def test_attack_signals_persisted(self, engine):
        # Ingest a typosquat package
        payload = _cyclonedx_payload([
            {"name": "requets", "version": "2.28.0"}  # typosquat
        ])
        _, _, signals = engine.ingest_sbom(payload)
        if signals:
            stored = engine.list_attack_signals()
            assert len(stored) >= 1

    def test_list_attack_signals_empty(self, engine):
        signals = engine.list_attack_signals()
        assert signals == []


# ---------------------------------------------------------------------------
# 9. REST API endpoints
# ---------------------------------------------------------------------------


@pytest.fixture()
def api_client(tmp_db):
    """FastAPI TestClient with a fresh engine injected and auth bypassed."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import apps.api.supply_chain_router as scr

    # Inject a fresh isolated engine
    scr._engine = SupplyChainEngine(db_path=tmp_db)

    app = FastAPI()
    app.include_router(scr.router)

    # Override auth dependency so tests run without needing valid tokens
    try:
        from apps.api.auth_deps import api_key_auth

        async def _auth_bypass():
            return None

        app.dependency_overrides[api_key_auth] = _auth_bypass
    except ImportError:
        pass

    return TestClient(app)


class TestSupplyChainAPI:
    def test_upload_cyclonedx_sbom(self, api_client):
        resp = api_client.post("/api/v1/supply-chain/sbom/upload", json={
            "sbom": _cyclonedx_payload(),
            "org_id": "default",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["component_count"] == 2
        assert data["format"] == "cyclonedx"

    def test_upload_spdx_sbom(self, api_client):
        resp = api_client.post("/api/v1/supply-chain/sbom/upload", json={
            "sbom": _spdx_payload(),
            "org_id": "default",
        })
        assert resp.status_code == 201
        assert resp.json()["format"] == "spdx"

    def test_upload_invalid_sbom(self, api_client):
        resp = api_client.post("/api/v1/supply-chain/sbom/upload", json={
            "sbom": {"garbage": "data"},
            "org_id": "default",
        })
        assert resp.status_code == 422

    def test_list_components_empty(self, api_client):
        resp = api_client.get("/api/v1/supply-chain/components")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_components_after_upload(self, api_client):
        api_client.post("/api/v1/supply-chain/sbom/upload", json={
            "sbom": _cyclonedx_payload(), "org_id": "default"
        })
        resp = api_client.get("/api/v1/supply-chain/components")
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    def test_risk_dashboard(self, api_client):
        resp = api_client.get("/api/v1/supply-chain/risks")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_components" in data
        assert "attack_signals" in data

    def test_trigger_scan(self, api_client):
        resp = api_client.post("/api/v1/supply-chain/scan", json={
            "repo_url": "https://github.com/org/repo",
            "branch": "main",
            "org_id": "default",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "queued"
        assert "scan_id" in data

    def test_list_policies_empty(self, api_client):
        resp = api_client.get("/api/v1/supply-chain/policies")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_policy(self, api_client):
        resp = api_client.post("/api/v1/supply-chain/policies", json={
            "name": "No GPL",
            "action": "block",
            "blocked_licenses": ["GPL-3.0"],
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "No GPL"
        assert data["action"] == "block"

    def test_list_policies_after_create(self, api_client):
        api_client.post("/api/v1/supply-chain/policies", json={"name": "P1", "action": "warn"})
        resp = api_client.get("/api/v1/supply-chain/policies")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    def test_list_vendors_empty(self, api_client):
        resp = api_client.get("/api/v1/supply-chain/vendors")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_vendor(self, api_client):
        resp = api_client.post("/api/v1/supply-chain/vendors", json={
            "vendor_name": "Acme Corp",
            "security_score": 75.0,
            "component_count": 10,
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["vendor_name"] == "Acme Corp"
        assert data["security_score"] == 75.0

    def test_list_vendors_after_create(self, api_client):
        api_client.post("/api/v1/supply-chain/vendors", json={"vendor_name": "V1", "security_score": 50.0})
        resp = api_client.get("/api/v1/supply-chain/vendors")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    def test_provenance_not_found(self, api_client):
        resp = api_client.get("/api/v1/supply-chain/provenance/unknown-pkg")
        assert resp.status_code == 200
        data = resp.json()
        assert data["found"] is False
        assert data["component_name"] == "unknown-pkg"

    def test_sbom_upload_returns_sha256(self, api_client):
        resp = api_client.post("/api/v1/supply-chain/sbom/upload", json={
            "sbom": _cyclonedx_payload(), "org_id": "default"
        })
        assert resp.status_code == 201
        assert len(resp.json()["sha256"]) == 64
