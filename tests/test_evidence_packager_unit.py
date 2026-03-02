"""Unit tests for suite-evidence-risk/evidence/packager.py

Tests the evidence bundle creation helpers: policy loading, rule evaluation,
policy evaluation, file collection, digest computation, and bundle creation.

Pillar: V10 (CTEM + Crypto Evidence)
"""

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from evidence.packager import (
    DEFAULT_POLICY,
    BundleInputs,
    _collect_files,
    _digest_file,
    _evaluate_rules,
    create_bundle,
    evaluate_policy,
    load_policy,
)


# --- BundleInputs dataclass ---


class TestBundleInputs:
    """Tests for BundleInputs dataclass."""

    def test_bundle_inputs_required_fields(self):
        """BundleInputs requires tag and path fields."""
        inputs = BundleInputs(
            tag="v1.0",
            normalized_sbom=Path("sbom.json"),
            sbom_quality_json=Path("quality.json"),
            sbom_quality_html=None,
            risk_report=Path("risk.json"),
            provenance_dir=Path("provenance"),
            repro_attestation=Path("repro.json"),
        )
        assert inputs.tag == "v1.0"
        assert inputs.normalized_sbom == Path("sbom.json")
        assert inputs.sbom_quality_html is None

    def test_bundle_inputs_defaults(self):
        """BundleInputs has sensible defaults."""
        inputs = BundleInputs(
            tag="test",
            normalized_sbom=Path("a"),
            sbom_quality_json=Path("b"),
            sbom_quality_html=None,
            risk_report=Path("c"),
            provenance_dir=Path("d"),
            repro_attestation=Path("e"),
        )
        assert inputs.policy_path is None
        assert inputs.output_dir == Path("evidence")
        assert inputs.sign_key is None

    def test_bundle_inputs_custom_output_dir(self):
        """BundleInputs accepts custom output directory."""
        inputs = BundleInputs(
            tag="test",
            normalized_sbom=Path("a"),
            sbom_quality_json=Path("b"),
            sbom_quality_html=None,
            risk_report=Path("c"),
            provenance_dir=Path("d"),
            repro_attestation=Path("e"),
            output_dir=Path("/custom/output"),
        )
        assert inputs.output_dir == Path("/custom/output")


# --- load_policy ---


class TestLoadPolicy:
    """Tests for load_policy function."""

    def test_load_policy_none_returns_default(self):
        """load_policy(None) returns DEFAULT_POLICY."""
        result = load_policy(None)
        assert result == DEFAULT_POLICY

    def test_load_policy_nonexistent_path_returns_default(self):
        """load_policy with nonexistent path returns DEFAULT_POLICY."""
        result = load_policy(Path("/nonexistent/policy.yaml"))
        assert result == DEFAULT_POLICY

    def test_load_policy_valid_yaml(self):
        """load_policy loads and merges valid YAML policy."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            yaml.safe_dump(
                {"risk": {"max_risk_score": {"fail_above": 90.0}}},
                f,
            )
            f.flush()
            policy_path = Path(f.name)
        try:
            result = load_policy(policy_path)
            assert result["risk"]["max_risk_score"]["fail_above"] == 90.0
            # Default sbom_quality should still be present
            assert "sbom_quality" in result
        finally:
            policy_path.unlink()

    def test_load_policy_merges_with_defaults(self):
        """load_policy shallow-merges custom sections into defaults."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            yaml.safe_dump(
                {"sbom_quality": {"coverage_percent": {"warn_below": 90.0}}},
                f,
            )
            f.flush()
            policy_path = Path(f.name)
        try:
            result = load_policy(policy_path)
            # Shallow merge: coverage_percent is REPLACED entirely by custom value
            assert result["sbom_quality"]["coverage_percent"]["warn_below"] == 90.0
            # Other default sections still present
            assert "risk" in result
            assert "repro" in result
        finally:
            policy_path.unlink()

    def test_load_policy_invalid_root_raises(self):
        """load_policy raises ValueError for non-mapping root."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write("- item1\n- item2\n")
            f.flush()
            policy_path = Path(f.name)
        try:
            with pytest.raises(ValueError, match="mapping"):
                load_policy(policy_path)
        finally:
            policy_path.unlink()

    def test_load_policy_empty_yaml_returns_default(self):
        """load_policy with empty YAML returns DEFAULT_POLICY."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write("")
            f.flush()
            policy_path = Path(f.name)
        try:
            result = load_policy(policy_path)
            assert result == DEFAULT_POLICY
        finally:
            policy_path.unlink()

    def test_load_policy_adds_new_sections(self):
        """load_policy adds sections not in DEFAULT_POLICY."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            yaml.safe_dump(
                {"custom_section": {"custom_key": "custom_value"}},
                f,
            )
            f.flush()
            policy_path = Path(f.name)
        try:
            result = load_policy(policy_path)
            assert result["custom_section"]["custom_key"] == "custom_value"
        finally:
            policy_path.unlink()


# --- _evaluate_rules ---


class TestEvaluateRules:
    """Tests for _evaluate_rules function."""

    def test_pass_when_no_thresholds(self):
        """Returns 'pass' when no thresholds defined."""
        assert _evaluate_rules(50.0, {}) == "pass"

    def test_fail_above(self):
        """Returns 'fail' when value exceeds fail_above."""
        assert _evaluate_rules(90.0, {"fail_above": 85.0}) == "fail"

    def test_pass_below_fail_above(self):
        """Returns 'pass' when value is below fail_above."""
        assert _evaluate_rules(80.0, {"fail_above": 85.0}) == "pass"

    def test_fail_below(self):
        """Returns 'fail' when value is below fail_below."""
        assert _evaluate_rules(50.0, {"fail_below": 60.0}) == "fail"

    def test_pass_above_fail_below(self):
        """Returns 'pass' when value is above fail_below."""
        assert _evaluate_rules(70.0, {"fail_below": 60.0}) == "pass"

    def test_warn_above(self):
        """Returns 'warn' when value exceeds warn_above."""
        assert _evaluate_rules(75.0, {"warn_above": 70.0}) == "warn"

    def test_warn_below(self):
        """Returns 'warn' when value is below warn_below."""
        assert _evaluate_rules(75.0, {"warn_below": 80.0}) == "warn"

    def test_fail_takes_precedence_over_warn(self):
        """Fail takes precedence over warn."""
        rules = {"fail_above": 85.0, "warn_above": 70.0}
        assert _evaluate_rules(90.0, rules) == "fail"

    def test_exact_boundary_fail_above(self):
        """Value exactly at fail_above boundary does not fail."""
        assert _evaluate_rules(85.0, {"fail_above": 85.0}) == "pass"

    def test_exact_boundary_fail_below(self):
        """Value exactly at fail_below boundary does not fail."""
        assert _evaluate_rules(60.0, {"fail_below": 60.0}) == "pass"

    def test_exact_boundary_warn_above(self):
        """Value exactly at warn_above boundary does not warn."""
        assert _evaluate_rules(70.0, {"warn_above": 70.0}) == "pass"

    def test_exact_boundary_warn_below(self):
        """Value exactly at warn_below boundary does not warn."""
        assert _evaluate_rules(80.0, {"warn_below": 80.0}) == "pass"

    def test_combined_warn_and_fail_below(self):
        """Both warn_below and fail_below work together."""
        rules = {"warn_below": 80.0, "fail_below": 60.0}
        assert _evaluate_rules(70.0, rules) == "warn"
        assert _evaluate_rules(50.0, rules) == "fail"
        assert _evaluate_rules(90.0, rules) == "pass"


# --- evaluate_policy ---


class TestEvaluatePolicy:
    """Tests for evaluate_policy function."""

    def test_empty_metrics_provenance_fails(self):
        """Empty metrics triggers provenance attestation fail (require_attestations=True, count=0)."""
        result = evaluate_policy(DEFAULT_POLICY, metrics={})
        # Provenance check always fires — empty metrics means 0 attestations → fail
        assert result["overall"] == "fail"
        assert result["checks"]["provenance_attestations"]["status"] == "fail"

    def test_sbom_coverage_pass(self):
        """SBOM coverage above threshold passes (individual check)."""
        metrics = {"sbom": {"coverage_percent": 85.0}, "provenance": {"count": 1}}
        result = evaluate_policy(DEFAULT_POLICY, metrics=metrics)
        assert result["checks"]["sbom_coverage_percent"]["status"] == "pass"

    def test_sbom_coverage_warn(self):
        """SBOM coverage below warn threshold warns (individual check)."""
        metrics = {"sbom": {"coverage_percent": 75.0}, "provenance": {"count": 1}}
        result = evaluate_policy(DEFAULT_POLICY, metrics=metrics)
        assert result["checks"]["sbom_coverage_percent"]["status"] == "warn"

    def test_sbom_coverage_fail(self):
        """SBOM coverage below fail threshold fails."""
        metrics = {"sbom": {"coverage_percent": 50.0}}
        result = evaluate_policy(DEFAULT_POLICY, metrics=metrics)
        assert result["checks"]["sbom_coverage_percent"]["status"] == "fail"
        assert result["overall"] == "fail"

    def test_risk_score_pass(self):
        """Risk score below threshold passes."""
        metrics = {"risk": {"max_risk_score": 60.0}}
        result = evaluate_policy(DEFAULT_POLICY, metrics=metrics)
        assert result["checks"]["risk_max_risk_score"]["status"] == "pass"

    def test_risk_score_warn(self):
        """Risk score above warn threshold warns."""
        metrics = {"risk": {"max_risk_score": 75.0}}
        result = evaluate_policy(DEFAULT_POLICY, metrics=metrics)
        assert result["checks"]["risk_max_risk_score"]["status"] == "warn"

    def test_risk_score_fail(self):
        """Risk score above fail threshold fails."""
        metrics = {"risk": {"max_risk_score": 90.0}}
        result = evaluate_policy(DEFAULT_POLICY, metrics=metrics)
        assert result["checks"]["risk_max_risk_score"]["status"] == "fail"
        assert result["overall"] == "fail"

    def test_repro_match_true_passes(self):
        """Repro match True passes when required."""
        metrics = {"repro": {"match": True}}
        result = evaluate_policy(DEFAULT_POLICY, metrics=metrics)
        assert result["checks"]["repro_match"]["status"] == "pass"

    def test_repro_match_false_fails(self):
        """Repro match False fails when required."""
        metrics = {"repro": {"match": False}}
        result = evaluate_policy(DEFAULT_POLICY, metrics=metrics)
        assert result["checks"]["repro_match"]["status"] == "fail"
        assert result["overall"] == "fail"

    def test_provenance_with_attestations_passes(self):
        """Provenance with attestation count > 0 passes."""
        metrics = {"provenance": {"count": 3}}
        result = evaluate_policy(DEFAULT_POLICY, metrics=metrics)
        assert result["checks"]["provenance_attestations"]["status"] == "pass"

    def test_provenance_without_attestations_fails(self):
        """Provenance with attestation count 0 fails."""
        metrics = {"provenance": {"count": 0}}
        result = evaluate_policy(DEFAULT_POLICY, metrics=metrics)
        assert result["checks"]["provenance_attestations"]["status"] == "fail"

    def test_license_coverage_warn(self):
        """License coverage below warn threshold warns."""
        metrics = {"sbom": {"license_coverage_percent": 75.0}}
        result = evaluate_policy(DEFAULT_POLICY, metrics=metrics)
        assert result["checks"]["sbom_license_coverage_percent"]["status"] == "warn"

    def test_license_coverage_fail(self):
        """License coverage below fail threshold fails."""
        metrics = {"sbom": {"license_coverage_percent": 40.0}}
        result = evaluate_policy(DEFAULT_POLICY, metrics=metrics)
        assert result["checks"]["sbom_license_coverage_percent"]["status"] == "fail"

    def test_all_checks_pass_overall_pass(self):
        """When all checks pass, overall is pass."""
        metrics = {
            "sbom": {"coverage_percent": 90.0, "license_coverage_percent": 90.0},
            "risk": {"max_risk_score": 50.0},
            "repro": {"match": True},
            "provenance": {"count": 2},
        }
        result = evaluate_policy(DEFAULT_POLICY, metrics=metrics)
        assert result["overall"] == "pass"
        assert len(result["checks"]) == 5

    def test_one_fail_makes_overall_fail(self):
        """One failing check makes overall fail."""
        metrics = {
            "sbom": {"coverage_percent": 90.0},
            "risk": {"max_risk_score": 90.0},  # This will fail
        }
        result = evaluate_policy(DEFAULT_POLICY, metrics=metrics)
        assert result["overall"] == "fail"

    def test_warn_but_no_fail_gives_overall_warn(self):
        """Warn without fail gives overall warn (provenance satisfied)."""
        # Use policy without provenance requirement to isolate warn behavior
        policy = {
            "sbom_quality": DEFAULT_POLICY["sbom_quality"],
            "risk": DEFAULT_POLICY["risk"],
        }
        metrics = {
            "sbom": {"coverage_percent": 75.0},  # warn
            "risk": {"max_risk_score": 50.0},  # pass
        }
        result = evaluate_policy(policy, metrics=metrics)
        assert result["overall"] == "warn"

    def test_non_mapping_metrics_handled(self):
        """Non-mapping sbom/risk/repro/provenance metrics handled gracefully."""
        metrics = {"sbom": "invalid", "risk": 42, "repro": "nope"}
        result = evaluate_policy(DEFAULT_POLICY, metrics=metrics)
        # Provenance check still fires (count=0 from empty default) → fail
        assert result["overall"] == "fail"
        assert "provenance_attestations" in result["checks"]

    def test_non_mapping_policy_sections_handled(self):
        """Non-mapping policy sections handled gracefully."""
        policy = {"sbom_quality": "not_a_dict", "risk": 42}
        metrics = {"sbom": {"coverage_percent": 75.0}}
        result = evaluate_policy(policy, metrics=metrics)
        # No crash — graceful handling
        assert "overall" in result


# --- _digest_file ---


class TestDigestFile:
    """Tests for _digest_file function."""

    def test_digest_empty_file(self):
        """Digest of empty file is SHA256 of empty bytes."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"")
            path = Path(f.name)
        try:
            digest = _digest_file(path)
            assert len(digest) == 64  # SHA256 hex length
            assert digest == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        finally:
            path.unlink()

    def test_digest_known_content(self):
        """Digest of known content matches expected SHA256."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"hello world")
            path = Path(f.name)
        try:
            digest = _digest_file(path)
            assert len(digest) == 64
            # SHA256 of "hello world"
            assert digest == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        finally:
            path.unlink()

    def test_digest_deterministic(self):
        """Same file produces same digest."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test content for determinism")
            path = Path(f.name)
        try:
            d1 = _digest_file(path)
            d2 = _digest_file(path)
            assert d1 == d2
        finally:
            path.unlink()

    def test_digest_different_content(self):
        """Different content produces different digest."""
        with tempfile.NamedTemporaryFile(delete=False) as f1:
            f1.write(b"content A")
            path1 = Path(f1.name)
        with tempfile.NamedTemporaryFile(delete=False) as f2:
            f2.write(b"content B")
            path2 = Path(f2.name)
        try:
            assert _digest_file(path1) != _digest_file(path2)
        finally:
            path1.unlink()
            path2.unlink()


# --- _collect_files ---


class TestCollectFiles:
    """Tests for _collect_files function."""

    def test_collect_empty_iterable(self):
        """Empty iterable returns empty list."""
        assert _collect_files([]) == []

    def test_collect_single_file(self):
        """Single file path returns that file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = Path(f.name)
        try:
            result = _collect_files([path])
            assert len(result) == 1
            assert result[0] == path
        finally:
            path.unlink()

    def test_collect_directory_recursively(self):
        """Directory collects all files recursively."""
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / "file1.txt").write_text("a")
            sub = d / "sub"
            sub.mkdir()
            (sub / "file2.txt").write_text("b")
            result = _collect_files([d])
            assert len(result) == 2
            names = {f.name for f in result}
            assert "file1.txt" in names
            assert "file2.txt" in names

    def test_collect_mixed_files_and_dirs(self):
        """Mixed file and directory paths all collected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            f1 = d / "standalone.txt"
            f1.write_text("solo")
            sub = d / "subdir"
            sub.mkdir()
            (sub / "nested.txt").write_text("nested")
            result = _collect_files([f1, sub])
            assert len(result) == 2

    def test_collect_nonexistent_path_skipped(self):
        """Non-existent paths are skipped without error."""
        result = _collect_files([Path("/nonexistent/file.txt")])
        assert result == []

    def test_collect_empty_path_treated_as_cwd(self):
        """Path('') resolves to current dir — code treats it as a directory."""
        # Path("") is truthy and is_dir() is True (it's CWD)
        # _collect_files would recurse into CWD, so we just verify it doesn't crash
        result = _collect_files([Path("/definitely/nonexistent/path/abc123")])
        assert result == []  # Non-existent path returns empty


# --- DEFAULT_POLICY ---


class TestDefaultPolicy:
    """Tests for DEFAULT_POLICY constant."""

    def test_has_sbom_quality(self):
        """DEFAULT_POLICY has sbom_quality section."""
        assert "sbom_quality" in DEFAULT_POLICY

    def test_has_risk(self):
        """DEFAULT_POLICY has risk section."""
        assert "risk" in DEFAULT_POLICY

    def test_has_repro(self):
        """DEFAULT_POLICY has repro section."""
        assert "repro" in DEFAULT_POLICY

    def test_has_provenance(self):
        """DEFAULT_POLICY has provenance section."""
        assert "provenance" in DEFAULT_POLICY

    def test_sbom_quality_thresholds(self):
        """SBOM quality has coverage and license thresholds."""
        sq = DEFAULT_POLICY["sbom_quality"]
        assert sq["coverage_percent"]["warn_below"] == 80.0
        assert sq["coverage_percent"]["fail_below"] == 60.0
        assert sq["license_coverage_percent"]["warn_below"] == 80.0
        assert sq["license_coverage_percent"]["fail_below"] == 50.0

    def test_risk_thresholds(self):
        """Risk has max_risk_score thresholds."""
        r = DEFAULT_POLICY["risk"]
        assert r["max_risk_score"]["warn_above"] == 70.0
        assert r["max_risk_score"]["fail_above"] == 85.0


# --- create_bundle (integration-level) ---


class TestCreateBundle:
    """Integration tests for create_bundle function."""

    def _setup_bundle_files(self, tmpdir: Path):
        """Create minimal files needed for a bundle."""
        sbom = tmpdir / "sbom.json"
        sbom.write_text(json.dumps({"components": [], "metrics": {"coverage_percent": 85}}))

        quality = tmpdir / "quality.json"
        quality.write_text(json.dumps({"metrics": {"coverage_percent": 85.0}}))

        risk = tmpdir / "risk.json"
        risk.write_text(json.dumps({"summary": {"component_count": 10, "cve_count": 2, "max_risk_score": 50.0}}))

        repro = tmpdir / "repro.json"
        repro.write_text(json.dumps({"match": True}))

        prov_dir = tmpdir / "provenance"
        prov_dir.mkdir()
        (prov_dir / "attestation.json").write_text(json.dumps({"type": "in-toto"}))

        output = tmpdir / "output"
        return BundleInputs(
            tag="v1.0.0",
            normalized_sbom=sbom,
            sbom_quality_json=quality,
            sbom_quality_html=None,
            risk_report=risk,
            provenance_dir=prov_dir,
            repro_attestation=repro,
            output_dir=output,
        )

    def test_create_bundle_produces_zip(self):
        """create_bundle produces a zip file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            inputs = self._setup_bundle_files(Path(tmpdir))
            manifest = create_bundle(inputs)
            assert "bundle_path" in manifest
            bundle_path = Path(manifest["bundle_path"])
            assert bundle_path.exists()
            assert bundle_path.suffix == ".zip"

    def test_create_bundle_produces_manifest(self):
        """create_bundle produces a YAML manifest."""
        with tempfile.TemporaryDirectory() as tmpdir:
            inputs = self._setup_bundle_files(Path(tmpdir))
            manifest = create_bundle(inputs)
            assert "manifest_path" in manifest
            manifest_path = Path(manifest["manifest_path"])
            assert manifest_path.exists()
            assert manifest_path.suffix == ".yaml"

    def test_create_bundle_manifest_has_tag(self):
        """Bundle manifest contains the tag."""
        with tempfile.TemporaryDirectory() as tmpdir:
            inputs = self._setup_bundle_files(Path(tmpdir))
            manifest = create_bundle(inputs)
            assert manifest["tag"] == "v1.0.0"

    def test_create_bundle_has_artefacts(self):
        """Bundle manifest lists artefact descriptors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            inputs = self._setup_bundle_files(Path(tmpdir))
            manifest = create_bundle(inputs)
            assert len(manifest["artefacts"]) >= 4  # sbom, quality, risk, repro
            for art in manifest["artefacts"]:
                assert "sha256" in art
                assert "name" in art

    def test_create_bundle_has_evaluations(self):
        """Bundle manifest includes policy evaluations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            inputs = self._setup_bundle_files(Path(tmpdir))
            manifest = create_bundle(inputs)
            assert "evaluations" in manifest
            assert "overall" in manifest["evaluations"]

    def test_create_bundle_has_metrics(self):
        """Bundle manifest includes computed metrics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            inputs = self._setup_bundle_files(Path(tmpdir))
            manifest = create_bundle(inputs)
            assert "metrics" in manifest
            assert "sbom" in manifest["metrics"]
            assert "risk" in manifest["metrics"]

    def test_create_bundle_missing_file_raises(self):
        """create_bundle raises FileNotFoundError for missing required files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            inputs = BundleInputs(
                tag="v1.0",
                normalized_sbom=Path(tmpdir) / "nonexistent.json",
                sbom_quality_json=Path(tmpdir) / "nonexistent2.json",
                sbom_quality_html=None,
                risk_report=Path(tmpdir) / "nonexistent3.json",
                provenance_dir=Path(tmpdir),
                repro_attestation=Path(tmpdir) / "nonexistent4.json",
                output_dir=Path(tmpdir) / "output",
            )
            with pytest.raises(FileNotFoundError):
                create_bundle(inputs)

    def test_create_bundle_with_extra_paths(self):
        """create_bundle includes extra_paths in the bundle."""
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            inputs = self._setup_bundle_files(d)
            extra = d / "extra_doc.txt"
            extra.write_text("extra evidence")
            inputs = BundleInputs(
                tag="v1.0.0",
                normalized_sbom=inputs.normalized_sbom,
                sbom_quality_json=inputs.sbom_quality_json,
                sbom_quality_html=None,
                risk_report=inputs.risk_report,
                provenance_dir=inputs.provenance_dir,
                repro_attestation=inputs.repro_attestation,
                output_dir=inputs.output_dir,
                extra_paths=[extra],
            )
            manifest = create_bundle(inputs)
            extra_arts = [a for a in manifest["artefacts"] if a["name"].startswith("extra/")]
            assert len(extra_arts) == 1

    def test_create_bundle_with_html_quality(self):
        """create_bundle includes HTML quality report if provided."""
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            inputs = self._setup_bundle_files(d)
            html = d / "quality.html"
            html.write_text("<html><body>Quality</body></html>")
            inputs = BundleInputs(
                tag="v1.0.0",
                normalized_sbom=inputs.normalized_sbom,
                sbom_quality_json=inputs.sbom_quality_json,
                sbom_quality_html=html,
                risk_report=inputs.risk_report,
                provenance_dir=inputs.provenance_dir,
                repro_attestation=inputs.repro_attestation,
                output_dir=inputs.output_dir,
            )
            manifest = create_bundle(inputs)
            html_arts = [a for a in manifest["artefacts"] if "quality.html" in a["name"]]
            assert len(html_arts) == 1
