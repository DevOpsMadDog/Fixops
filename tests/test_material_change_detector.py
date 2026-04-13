"""Tests for the Material Change Detector module.

Covers:
- MaterialClassification enum values
- classify_change for COSMETIC, MATERIAL, and BREAKING categories
- get_risk_multiplier values
- analyze_diff with multi-file diffs
- compute_blast_radius with mock filesystem
- ChangeAnalysis Pydantic model validation
- Webhook payload parsing logic
- Edge cases (empty diff, new file, deleted file, migration)

Usage:
    pytest tests/test_material_change_detector.py -v --timeout=10
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite-core is on the path
_suite_core = str(Path(__file__).parent.parent / "suite-core")
if _suite_core not in sys.path:
    sys.path.insert(0, _suite_core)

from core.material_change_detector import (
    ChangeAnalysis,
    MaterialChangeDetector,
    MaterialClassification,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def detector() -> MaterialChangeDetector:
    return MaterialChangeDetector()


# ---------------------------------------------------------------------------
# 1. Enum & model tests
# ---------------------------------------------------------------------------


def test_classification_values():
    assert MaterialClassification.COSMETIC == "COSMETIC"
    assert MaterialClassification.MATERIAL == "MATERIAL"
    assert MaterialClassification.BREAKING == "BREAKING"


def test_change_analysis_model():
    a = ChangeAnalysis(
        file_path="core/foo.py",
        classification=MaterialClassification.MATERIAL,
        risk_delta=0.5,
        blast_radius=["other.py"],
        reason="test",
    )
    assert a.file_path == "core/foo.py"
    assert a.risk_delta == 0.5
    assert a.blast_radius == ["other.py"]


def test_change_analysis_risk_delta_bounds():
    with pytest.raises(Exception):
        ChangeAnalysis(
            file_path="f.py",
            classification=MaterialClassification.COSMETIC,
            risk_delta=1.5,  # out of range
            blast_radius=[],
            reason="bad",
        )


# ---------------------------------------------------------------------------
# 2. Risk multiplier tests
# ---------------------------------------------------------------------------


def test_risk_multiplier_cosmetic(detector):
    assert detector.get_risk_multiplier(MaterialClassification.COSMETIC) == 0.0


def test_risk_multiplier_material(detector):
    assert detector.get_risk_multiplier(MaterialClassification.MATERIAL) == 0.5


def test_risk_multiplier_breaking(detector):
    assert detector.get_risk_multiplier(MaterialClassification.BREAKING) == 1.0


# ---------------------------------------------------------------------------
# 3. classify_change — COSMETIC
# ---------------------------------------------------------------------------


def test_classify_readme_is_cosmetic(detector):
    assert detector.classify_change("README.md", []) == MaterialClassification.COSMETIC


def test_classify_txt_file_is_cosmetic(detector):
    assert detector.classify_change("docs/notes.txt", []) == MaterialClassification.COSMETIC


def test_classify_rst_is_cosmetic(detector):
    assert detector.classify_change("docs/index.rst", []) == MaterialClassification.COSMETIC


def test_classify_license_file_is_cosmetic(detector):
    assert detector.classify_change("LICENSE", []) == MaterialClassification.COSMETIC


def test_classify_comment_only_diff_is_cosmetic(detector):
    hunks = [
        "-# Old comment about this function",
        "+# New comment about this function",
    ]
    assert detector.classify_change("core/utils.py", hunks) == MaterialClassification.COSMETIC


def test_classify_whitespace_only_is_cosmetic(detector):
    hunks = [
        "-    ",
        "+",
        "-",
        "+    ",
    ]
    assert detector.classify_change("core/utils.py", hunks) == MaterialClassification.COSMETIC


def test_classify_docstring_only_is_cosmetic(detector):
    hunks = [
        '-    """Old docstring."""',
        '+    """New improved docstring."""',
    ]
    assert detector.classify_change("core/service.py", hunks) == MaterialClassification.COSMETIC


# ---------------------------------------------------------------------------
# 4. classify_change — MATERIAL
# ---------------------------------------------------------------------------


def test_classify_requirements_txt_is_material(detector):
    assert detector.classify_change("requirements.txt", ["+requests==2.31.0"]) == MaterialClassification.MATERIAL


def test_classify_yaml_config_is_material(detector):
    assert detector.classify_change("config/settings.yml", ["+timeout: 30"]) == MaterialClassification.MATERIAL


def test_classify_json_config_is_material(detector):
    assert detector.classify_change("package.json", ['+"version": "2.0.0"']) == MaterialClassification.MATERIAL


def test_classify_env_file_is_material(detector):
    assert detector.classify_change(".env", ["+DATABASE_URL=postgres://..."]) == MaterialClassification.MATERIAL


def test_classify_new_file_is_material(detector):
    # Only additions = new file
    hunks = [
        "+def hello():",
        "+    return 'world'",
    ]
    assert detector.classify_change("core/hello.py", hunks) == MaterialClassification.MATERIAL


def test_classify_function_body_change_is_material(detector):
    hunks = [
        "-    result = old_calculation(x)",
        "+    result = new_calculation(x)",
    ]
    assert detector.classify_change("core/engine.py", hunks) == MaterialClassification.MATERIAL


def test_classify_new_import_is_material(detector):
    hunks = [
        "+import structlog",
    ]
    assert detector.classify_change("core/service.py", hunks) == MaterialClassification.MATERIAL


def test_classify_toml_is_material(detector):
    assert detector.classify_change("pyproject.toml", ["+python_requires = '>=3.11'"]) == MaterialClassification.MATERIAL


# ---------------------------------------------------------------------------
# 5. classify_change — BREAKING
# ---------------------------------------------------------------------------


def test_classify_deleted_public_function_is_breaking(detector):
    hunks = [
        "-def compute_risk(finding):",
        "-    return finding['score'] * 2",
    ]
    assert detector.classify_change("core/risk.py", hunks) == MaterialClassification.BREAKING


def test_classify_deleted_public_class_is_breaking(detector):
    hunks = [
        "-class RiskEngine:",
        "-    pass",
    ]
    assert detector.classify_change("core/risk.py", hunks) == MaterialClassification.BREAKING


def test_classify_changed_function_signature_is_breaking(detector):
    hunks = [
        "-def process(finding, tenant_id):",
        "+def process(finding, tenant_id, dry_run=False):",
    ]
    assert detector.classify_change("core/pipeline.py", hunks) == MaterialClassification.BREAKING


def test_classify_removed_api_route_is_breaking(detector):
    hunks = [
        '-@router.post("/api/v1/findings/ingest")',
    ]
    assert detector.classify_change("api/ingest_router.py", hunks) == MaterialClassification.BREAKING


def test_classify_migration_file_is_breaking(detector):
    assert (
        detector.classify_change("migrations/0001_add_tenant_id.py", [])
        == MaterialClassification.BREAKING
    )


def test_classify_alembic_migration_is_breaking(detector):
    assert (
        detector.classify_change("alembic/versions/abc123_add_column.py", [])
        == MaterialClassification.BREAKING
    )


def test_classify_init_export_removed_is_breaking(detector):
    hunks = [
        "-from core.risk import RiskEngine",
    ]
    assert detector.classify_change("core/__init__.py", hunks) == MaterialClassification.BREAKING


def test_classify_private_function_deleted_not_breaking(detector):
    # Private functions (underscore prefix) do NOT trigger BREAKING
    hunks = [
        "-def _internal_helper(x):",
        "-    return x",
    ]
    result = detector.classify_change("core/utils.py", hunks)
    # Private deletion is MATERIAL (logic change) not BREAKING
    assert result != MaterialClassification.BREAKING


# ---------------------------------------------------------------------------
# 6. analyze_diff — multi-file
# ---------------------------------------------------------------------------

_SAMPLE_DIFF = """\
diff --git a/README.md b/README.md
index abc1234..def5678 100644
--- a/README.md
+++ b/README.md
@@ -1,3 +1,3 @@
-# Old title
+# New title
diff --git a/core/risk.py b/core/risk.py
index 111..222 100644
--- a/core/risk.py
+++ b/core/risk.py
@@ -10,6 +10,6 @@
-def compute_risk(finding):
-    return finding['score']
+def compute_risk(finding, multiplier=1.0):
+    return finding['score'] * multiplier
diff --git a/requirements.txt b/requirements.txt
index 333..444 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,3 @@
+requests==2.31.0
 fastapi==0.110.0
"""


def test_analyze_diff_returns_correct_count(detector):
    results = detector.analyze_diff(_SAMPLE_DIFF)
    assert len(results) == 3


def test_analyze_diff_readme_is_cosmetic(detector):
    results = detector.analyze_diff(_SAMPLE_DIFF)
    readme = next(r for r in results if r.file_path == "README.md")
    assert readme.classification == MaterialClassification.COSMETIC
    assert readme.risk_delta == 0.0


def test_analyze_diff_risk_file_is_breaking(detector):
    results = detector.analyze_diff(_SAMPLE_DIFF)
    risk = next(r for r in results if r.file_path == "core/risk.py")
    assert risk.classification == MaterialClassification.BREAKING
    assert risk.risk_delta == 1.0


def test_analyze_diff_requirements_is_material(detector):
    results = detector.analyze_diff(_SAMPLE_DIFF)
    req = next(r for r in results if r.file_path == "requirements.txt")
    assert req.classification == MaterialClassification.MATERIAL
    assert req.risk_delta == 0.5


def test_analyze_diff_empty_returns_empty(detector):
    assert detector.analyze_diff("") == []
    assert detector.analyze_diff("   ") == []


def test_analyze_diff_reason_populated(detector):
    results = detector.analyze_diff(_SAMPLE_DIFF)
    for r in results:
        assert r.reason and len(r.reason) > 5


# ---------------------------------------------------------------------------
# 7. compute_blast_radius
# ---------------------------------------------------------------------------


def test_compute_blast_radius_finds_importer(detector, tmp_path):
    # Create a module file and a file that imports it
    (tmp_path / "core").mkdir()
    target = tmp_path / "core" / "risk.py"
    target.write_text("def compute_risk(): pass\n")

    importer = tmp_path / "api" / "risk_router.py"
    importer.parent.mkdir()
    importer.write_text("from core.risk import compute_risk\n")

    unrelated = tmp_path / "api" / "other.py"
    unrelated.write_text("# nothing here\n")

    blast = detector.compute_blast_radius("core/risk.py", str(tmp_path))
    assert any("risk_router.py" in b for b in blast)
    assert not any("other.py" in b for b in blast)


def test_compute_blast_radius_non_python_file(detector, tmp_path):
    # Non-.py files have no importers
    blast = detector.compute_blast_radius("README.md", str(tmp_path))
    assert blast == []


def test_compute_blast_radius_returns_sorted(detector, tmp_path):
    (tmp_path / "core").mkdir()
    (tmp_path / "core" / "engine.py").write_text("pass\n")
    for name in ["b_file.py", "a_file.py", "c_file.py"]:
        f = tmp_path / name
        f.write_text("from core.engine import x\n")

    blast = detector.compute_blast_radius("core/engine.py", str(tmp_path))
    assert blast == sorted(blast)


# ---------------------------------------------------------------------------
# 8. Webhook payload parsing (via router logic tested directly)
# ---------------------------------------------------------------------------


def test_webhook_payload_structure():
    """Validate a GitHub push event payload can be parsed correctly."""
    payload = {
        "ref": "refs/heads/main",
        "head_commit": {"id": "abc123def456"},
        "commits": [
            {
                "id": "abc123def456",
                "added": ["core/new_feature.py"],
                "modified": ["requirements.txt"],
                "removed": ["core/old_module.py"],
            }
        ],
    }
    all_files: List[str] = []
    for commit in payload.get("commits", []):
        all_files.extend(commit.get("added", []))
        all_files.extend(commit.get("modified", []))
        all_files.extend(commit.get("removed", []))

    assert "core/new_feature.py" in all_files
    assert "requirements.txt" in all_files
    assert "core/old_module.py" in all_files


def test_webhook_classifies_files_correctly(detector):
    """Check that webhook file classification uses correct tiers."""
    files = ["README.md", "requirements.txt", "core/old_api.py"]
    results = []
    for fp in files:
        c = detector.classify_change(fp, [])
        results.append((fp, c))

    readme = next(r for r in results if r[0] == "README.md")
    req = next(r for r in results if r[0] == "requirements.txt")

    assert readme[1] == MaterialClassification.COSMETIC
    assert req[1] == MaterialClassification.MATERIAL


def test_webhook_highest_risk_aggregation(detector):
    """Highest risk across files should be MATERIAL when mix of COSMETIC+MATERIAL."""
    files = ["README.md", "docs/guide.txt", "requirements.txt"]
    tier_order = {"COSMETIC": 0, "MATERIAL": 1, "BREAKING": 2}
    highest = "COSMETIC"
    for fp in files:
        c = detector.classify_change(fp, [])
        if tier_order.get(c.value, 0) > tier_order.get(highest, 0):
            highest = c.value
    assert highest == "MATERIAL"


# ---------------------------------------------------------------------------
# 9. PushEventAnalyzer — blast radius categorization
# ---------------------------------------------------------------------------

from core.material_change_detector import (  # noqa: E402
    BlastRadius,
    BlastRadiusCategory,
    MaterialChangeResult,
    PushEventAnalyzer,
)


@pytest.fixture
def analyzer() -> PushEventAnalyzer:
    return PushEventAnalyzer(webhook_secret="test-secret")


def test_blast_radius_critical_auth_file(analyzer):
    br = analyzer._get_blast_radius(["core/auth_middleware.py"])
    assert br.category == BlastRadiusCategory.CRITICAL
    assert "core/auth_middleware.py" in br.critical_files


def test_blast_radius_critical_crypto_file(analyzer):
    br = analyzer._get_blast_radius(["core/crypto_utils.py"])
    assert br.category == BlastRadiusCategory.CRITICAL


def test_blast_radius_critical_payment_file(analyzer):
    br = analyzer._get_blast_radius(["billing/payment_processor.py"])
    assert br.category == BlastRadiusCategory.CRITICAL


def test_blast_radius_high_router_file(analyzer):
    br = analyzer._get_blast_radius(["apps/api/findings_router.py"])
    assert br.category == BlastRadiusCategory.HIGH
    assert "apps/api/findings_router.py" in br.high_files


def test_blast_radius_high_database_file(analyzer):
    br = analyzer._get_blast_radius(["core/database_models.py"])
    assert br.category == BlastRadiusCategory.HIGH


def test_blast_radius_medium_business_logic(analyzer):
    br = analyzer._get_blast_radius(["core/risk_engine.py"])
    assert br.category == BlastRadiusCategory.MEDIUM
    assert "core/risk_engine.py" in br.medium_files


def test_blast_radius_low_test_file(analyzer):
    br = analyzer._get_blast_radius(["tests/test_something.py"])
    assert br.category == BlastRadiusCategory.LOW
    assert "tests/test_something.py" in br.low_files


def test_blast_radius_low_markdown(analyzer):
    br = analyzer._get_blast_radius(["docs/README.md"])
    assert br.category == BlastRadiusCategory.LOW


def test_blast_radius_mixed_uses_highest(analyzer):
    """When critical + low files present, category is CRITICAL."""
    br = analyzer._get_blast_radius(["docs/notes.md", "core/auth_manager.py"])
    assert br.category == BlastRadiusCategory.CRITICAL


def test_blast_radius_security_critical_ratio(analyzer):
    """auth files count toward security_critical_ratio."""
    br = analyzer._get_blast_radius(["core/auth.py", "core/auth2.py", "README.md"])
    assert br.security_critical_ratio > 0.0


def test_blast_radius_to_dict(analyzer):
    br = analyzer._get_blast_radius(["core/auth.py"])
    d = br.to_dict()
    assert d["category"] == "CRITICAL"
    assert "critical_files" in d
    assert "security_critical_ratio" in d


# ---------------------------------------------------------------------------
# 10. PushEventAnalyzer — materiality assessment
# ---------------------------------------------------------------------------


def test_assess_materiality_critical_blast_radius(analyzer):
    br = BlastRadius(
        category=BlastRadiusCategory.CRITICAL,
        changed_files=["core/auth.py"],
        critical_files=["core/auth.py"],
    )
    is_mat, reasons = analyzer._assess_materiality([], br)
    assert is_mat is True
    assert any("blast_radius_critical" in r for r in reasons)


def test_assess_materiality_high_blast_radius(analyzer):
    br = BlastRadius(
        category=BlastRadiusCategory.HIGH,
        changed_files=["api/router.py"],
        high_files=["api/router.py"],
    )
    is_mat, reasons = analyzer._assess_materiality([], br)
    assert is_mat is True
    assert any("blast_radius_high" in r for r in reasons)


def test_assess_materiality_medium_no_sast_not_material(analyzer):
    br = BlastRadius(
        category=BlastRadiusCategory.MEDIUM,
        changed_files=["core/service.py"],
        medium_files=["core/service.py"],
    )
    is_mat, reasons = analyzer._assess_materiality([], br)
    assert is_mat is False
    assert reasons == []


def test_assess_materiality_high_sast_finding(analyzer):
    br = BlastRadius(
        category=BlastRadiusCategory.LOW,
        changed_files=["tests/test_x.py"],
        low_files=["tests/test_x.py"],
    )
    findings = [{"severity": "HIGH", "title": "Hardcoded credential", "tool": "regex_sast"}]
    is_mat, reasons = analyzer._assess_materiality(findings, br)
    assert is_mat is True
    assert any("sast" in r for r in reasons)


def test_assess_materiality_20pct_threshold(analyzer):
    """If ≥20% of changed files are security-critical, change is material."""
    br = BlastRadius(
        category=BlastRadiusCategory.MEDIUM,
        changed_files=["core/auth.py", "core/service.py", "core/other.py"],
        medium_files=["core/service.py", "core/other.py"],
        security_critical_ratio=0.33,
    )
    is_mat, reasons = analyzer._assess_materiality([], br)
    assert is_mat is True
    assert any("security_critical_ratio" in r for r in reasons)


# ---------------------------------------------------------------------------
# 11. PushEventAnalyzer — HMAC webhook verification
# ---------------------------------------------------------------------------


def test_hmac_verification_valid(analyzer):
    import hashlib
    import hmac as _hmac

    payload = b'{"ref": "refs/heads/main"}'
    sig = "sha256=" + _hmac.new(b"test-secret", payload, hashlib.sha256).hexdigest()
    assert analyzer.verify_webhook_signature(payload, sig) is True


def test_hmac_verification_invalid(analyzer):
    payload = b'{"ref": "refs/heads/main"}'
    assert analyzer.verify_webhook_signature(payload, "sha256=badhash") is False


def test_hmac_verification_no_secret():
    """Without a secret, all signatures are accepted (dev mode)."""
    a = PushEventAnalyzer(webhook_secret="")
    assert a.verify_webhook_signature(b"any payload", "sha256=whatever") is True


def test_hmac_verification_missing_prefix(analyzer):
    payload = b"payload"
    # Missing sha256= prefix
    assert analyzer.verify_webhook_signature(payload, "badhashwithoutprefix") is False


# ---------------------------------------------------------------------------
# 12. PushEventAnalyzer — analyze_push_event integration
# ---------------------------------------------------------------------------


def _make_push_payload(files: List[str], sha: str = "abc123") -> dict:
    return {
        "after": sha,
        "ref": "refs/heads/main",
        "repository": {"full_name": "org/repo"},
        "pusher": {"name": "dev"},
        "commits": [
            {"id": sha, "added": files, "modified": [], "removed": []}
        ],
    }


def test_analyze_push_event_no_commits(analyzer):
    payload = {"after": "abc", "ref": "refs/heads/main", "repository": {"full_name": "org/repo"}, "commits": []}
    result = analyzer.analyze_push_event(payload)
    assert isinstance(result, MaterialChangeResult)
    assert result.changed_files == []
    assert result.is_material is False


def test_analyze_push_event_low_risk_not_material(tmp_path):
    """Low-risk files with no SAST findings → not material."""
    a = PushEventAnalyzer(repo_root=str(tmp_path), webhook_secret="s")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "guide.md").write_text("# Guide\nSome docs.\n")
    (tmp_path / "README.md").write_text("# README\nHello world.\n")
    payload = _make_push_payload(["docs/guide.md", "README.md"])
    result = a.analyze_push_event(payload)
    assert result.blast_radius is not None
    assert result.blast_radius.category == BlastRadiusCategory.LOW
    assert result.is_material is False


def test_analyze_push_event_critical_is_material(analyzer):
    payload = _make_push_payload(["core/auth_service.py"])
    result = analyzer.analyze_push_event(payload)
    assert result.is_material is True
    assert result.blast_radius.category == BlastRadiusCategory.CRITICAL
    assert result.incident_id is None or isinstance(result.incident_id, str)


def test_analyze_push_event_deduplicates_files(analyzer):
    payload = {
        "after": "abc",
        "ref": "refs/heads/main",
        "repository": {"full_name": "org/repo"},
        "pusher": {"name": "dev"},
        "commits": [
            {"id": "c1", "added": ["core/auth.py"], "modified": [], "removed": []},
            {"id": "c2", "added": ["core/auth.py"], "modified": [], "removed": []},
        ],
    }
    result = analyzer.analyze_push_event(payload)
    assert result.changed_files.count("core/auth.py") == 1


def test_analyze_push_event_result_has_id(analyzer):
    payload = _make_push_payload(["README.md"])
    result = analyzer.analyze_push_event(payload)
    assert result.id and len(result.id) > 0


def test_analyze_push_event_to_dict(analyzer):
    payload = _make_push_payload(["core/auth.py"])
    result = analyzer.analyze_push_event(payload)
    d = result.to_dict()
    assert "id" in d
    assert "is_material" in d
    assert "blast_radius" in d
    assert "sast_findings" in d


# ---------------------------------------------------------------------------
# 13. PushEventAnalyzer — list_recent / get_by_id
# ---------------------------------------------------------------------------


def test_list_recent_returns_list(analyzer, tmp_path, monkeypatch):
    import core.material_change_detector as mcd
    monkeypatch.setattr(mcd, "_MC_DB_PATH", tmp_path / "mc_test.db")
    payload = _make_push_payload(["README.md"])
    analyzer.analyze_push_event(payload)
    items = analyzer.list_recent(limit=10)
    assert isinstance(items, list)
    assert len(items) >= 1


def test_get_by_id_returns_record(analyzer, tmp_path, monkeypatch):
    import core.material_change_detector as mcd
    monkeypatch.setattr(mcd, "_MC_DB_PATH", tmp_path / "mc_test2.db")
    payload = _make_push_payload(["README.md"])
    result = analyzer.analyze_push_event(payload)
    fetched = analyzer.get_by_id(result.id)
    assert fetched is not None
    assert fetched["id"] == result.id


def test_get_by_id_missing_returns_none(analyzer):
    item = analyzer.get_by_id("nonexistent-id-xyz")
    assert item is None


# ---------------------------------------------------------------------------
# 14. PushEventAnalyzer — regex SAST heuristics
# ---------------------------------------------------------------------------


def test_regex_sast_detects_hardcoded_credential(analyzer, tmp_path):
    f = tmp_path / "config.py"
    f.write_text('password = "supersecret123"\n')
    findings = analyzer._run_regex_sast(["config.py"], str(tmp_path))
    assert any(r["title"] == "Hardcoded credential" for r in findings)
    assert any(r["severity"] == "HIGH" for r in findings)


def test_regex_sast_detects_eval(analyzer, tmp_path):
    f = tmp_path / "handler.py"
    f.write_text("result = eval(user_input)\n")
    findings = analyzer._run_regex_sast(["handler.py"], str(tmp_path))
    assert any("eval" in r["title"].lower() for r in findings)


def test_regex_sast_clean_file_no_findings(analyzer, tmp_path):
    f = tmp_path / "clean.py"
    f.write_text("def hello():\n    return 'world'\n")
    findings = analyzer._run_regex_sast(["clean.py"], str(tmp_path))
    assert findings == []


def test_regex_sast_missing_file_skipped(analyzer, tmp_path):
    """Non-existent files are skipped gracefully."""
    findings = analyzer._run_regex_sast(["does_not_exist.py"], str(tmp_path))
    assert findings == []
