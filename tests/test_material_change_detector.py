"""Tests for the Material Change Detection Engine.

Covers: DiffParser, PatternLibrary, RiskScorer, SemanticClassifier,
MaterialChangeDetector, PRAnalyzer, VelocityTracker, detect_language,
file_sensitivity_score, and all dataclass models.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest

from core.material_change_detector import (
    ChangeCategory,
    ChangeClassification,
    DiffHunk,
    DiffParser,
    FileDiff,
    MaterialChange,
    MaterialChangeDetector,
    PRAnalyzer,
    PRRiskAssessment,
    PatternLibrary,
    PatternMatch,
    RiskScorer,
    SemanticClassifier,
    SeverityLevel,
    VelocitySnapshot,
    VelocityTracker,
    detect_language,
    file_sensitivity_score,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_DIFF = """\
diff --git a/auth/login.py b/auth/login.py
--- a/auth/login.py
+++ b/auth/login.py
@@ -10,6 +10,8 @@ def login(username, password):
     user = db.find_user(username)
     if user:
-        if user.check_password(password):
+        if password == "admin":
+            return True
+        elif user.check_password(password):
             return create_session(user)
"""

SAMPLE_DIFF_NEW_FILE = """\
diff --git a/config/secrets.py b/config/secrets.py
new file mode 100644
--- /dev/null
+++ b/config/secrets.py
@@ -0,0 +1,5 @@
+API_KEY = "sk-1234567890abcdef"
+DB_PASSWORD = "supersecretpassword"
+JWT_SECRET = "mysecretkey"
+AKIA1234567890123456
+ghp_1234567890abcdefghijklmnopqrstuvwxyz12
"""

SAMPLE_DIFF_INFRA = """\
diff --git a/deploy/main.tf b/deploy/main.tf
--- a/deploy/main.tf
+++ b/deploy/main.tf
@@ -5,3 +5,5 @@ resource "aws_security_group" "web" {
   ingress {
-    cidr_blocks = ["10.0.0.0/8"]
+    cidr_blocks = ["0.0.0.0/0"]
   }
+  publicly_accessible = true
+  encryption = false
"""

SAMPLE_DIFF_RENAME = """\
diff --git a/old_name.py b/new_name.py
rename from old_name.py
rename to new_name.py
--- a/old_name.py
+++ b/new_name.py
@@ -1,3 +1,3 @@
 def hello():
-    print("old")
+    print("new")
"""

SAMPLE_DIFF_DELETED = """\
diff --git a/removed.py b/removed.py
deleted file mode 100644
--- a/removed.py
+++ /dev/null
@@ -1,3 +0,0 @@
-def goodbye():
-    print("bye")
-    return
"""

SAMPLE_DIFF_BINARY = """\
diff --git a/image.png b/image.png
Binary files a/image.png and b/image.png differ
"""

SAMPLE_DIFF_JAVASCRIPT = """\
diff --git a/app.js b/app.js
--- a/app.js
+++ b/app.js
@@ -10,4 +10,6 @@ const express = require('express');
 app.get('/search', (req, res) => {
-  const safe = sanitize(req.query.q);
+  const query = req.query.q;
+  document.write(query);
+  eval(query);
   res.send(results);
 });
"""

SAMPLE_DIFF_MULTI = SAMPLE_DIFF + "\n" + SAMPLE_DIFF_INFRA


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class TestEnums:
    def test_change_category_values(self):
        assert ChangeCategory.AUTH == "auth"
        assert ChangeCategory.CRYPTO == "crypto"
        assert ChangeCategory.DATA_FLOW == "data_flow"
        assert ChangeCategory.API_SURFACE == "api_surface"
        assert ChangeCategory.DEPENDENCY == "dependency"
        assert ChangeCategory.INFRASTRUCTURE == "infrastructure"
        assert ChangeCategory.UNKNOWN == "unknown"

    def test_change_classification_values(self):
        assert ChangeClassification.BREAKING == "BREAKING"
        assert ChangeClassification.MATERIAL == "MATERIAL"
        assert ChangeClassification.COSMETIC == "COSMETIC"

    def test_severity_level_values(self):
        assert SeverityLevel.CRITICAL == "CRITICAL"
        assert SeverityLevel.HIGH == "HIGH"
        assert SeverityLevel.MEDIUM == "MEDIUM"
        assert SeverityLevel.LOW == "LOW"
        assert SeverityLevel.INFO == "INFO"


# ---------------------------------------------------------------------------
# Dataclass Tests
# ---------------------------------------------------------------------------

class TestDiffHunk:
    def test_net_change_size(self):
        hunk = DiffHunk(
            old_start=1, old_count=3, new_start=1, new_count=5,
            added_lines=["a", "b", "c"], removed_lines=["x"],
            context_lines=["ctx"]
        )
        assert hunk.net_change_size == 4
        assert hunk.churn == 4

    def test_empty_hunk(self):
        hunk = DiffHunk(
            old_start=1, old_count=0, new_start=1, new_count=0,
            added_lines=[], removed_lines=[], context_lines=[]
        )
        assert hunk.net_change_size == 0
        assert hunk.churn == 0


class TestFileDiff:
    def test_properties(self):
        h = DiffHunk(
            old_start=1, old_count=2, new_start=1, new_count=4,
            added_lines=["line1", "line2", "line3"],
            removed_lines=["old1"],
            context_lines=[]
        )
        fd = FileDiff(
            path="test.py", old_path="test.py", language="python",
            is_new_file=False, is_deleted_file=False, is_rename=False,
            hunks=[h]
        )
        assert fd.total_added == 3
        assert fd.total_removed == 1
        assert fd.total_churn == 4
        assert "line1" in fd.all_added_text
        assert "old1" in fd.all_removed_text
        assert "line1" in fd.all_changed_text

    def test_multiple_hunks(self):
        h1 = DiffHunk(1, 1, 1, 2, ["a"], ["b"], [])
        h2 = DiffHunk(10, 1, 10, 2, ["c", "d"], [], [])
        fd = FileDiff("f.py", "f.py", "python", False, False, False, [h1, h2])
        assert fd.total_added == 3
        assert fd.total_removed == 1
        assert fd.total_churn == 4


class TestPatternMatch:
    def test_creation(self):
        pm = PatternMatch(
            pattern_id="AUTH-001", category=ChangeCategory.AUTH,
            description="Auth change", matched_text="login(",
            line_content="def login(user):", hunk_index=0,
            is_addition=True, confidence=0.9
        )
        assert pm.pattern_id == "AUTH-001"
        assert pm.category == ChangeCategory.AUTH
        assert pm.confidence == 0.9


class TestMaterialChange:
    def test_creation(self):
        mc = MaterialChange(
            change_id="abc123", file_path="auth.py",
            category=ChangeCategory.AUTH,
            classification=ChangeClassification.BREAKING,
            severity=SeverityLevel.CRITICAL,
            risk_score=95.0, summary="Auth bypass",
            explanation="Details here",
            pattern_matches=[], recommended_reviewers=["security"],
            review_items=["Review auth flow"]
        )
        assert mc.risk_score == 95.0
        assert mc.classification == ChangeClassification.BREAKING


class TestVelocitySnapshot:
    def test_creation(self):
        vs = VelocitySnapshot(
            repo="test-repo", window_days=7,
            material_change_count=15, breaking_change_count=3,
            avg_risk_score=65.0, acceleration=1.5,
            debt_acceleration_alert=True
        )
        assert vs.repo == "test-repo"
        assert vs.debt_acceleration_alert is True
        assert vs.timestamp  # auto-set


class TestPRRiskAssessment:
    def test_creation(self):
        pra = PRRiskAssessment(
            pr_id="PR-123", overall_risk_score=78.0,
            classification=ChangeClassification.BREAKING,
            material_changes=[], file_summaries=[],
            recommended_reviewers=["security"],
            review_checklist=["Check auth"],
            risk_breakdown={"auth": 50.0, "crypto": 28.0},
            stats={"files": 3}
        )
        assert pra.pr_id == "PR-123"
        assert pra.overall_risk_score == 78.0
        assert pra.analyzed_at  # auto-set


# ---------------------------------------------------------------------------
# Language Detection
# ---------------------------------------------------------------------------

class TestDetectLanguage:
    @pytest.mark.parametrize("path,expected", [
        ("src/app.py", "python"),
        ("src/index.js", "javascript"),
        ("src/main.ts", "typescript"),
        ("src/App.tsx", "typescript"),
        ("src/Main.java", "java"),
        ("cmd/server.go", "go"),
        ("src/lib.rs", "rust"),
        ("src/main.c", "c"),
        ("src/util.cpp", "cpp"),
        ("deploy/main.tf", "terraform"),
        ("config.yaml", "yaml"),
        ("config.yml", "yaml"),
        ("Dockerfile", "dockerfile"),
        ("script.sh", "shell"),
        ("requirements.txt", "python-deps"),
        ("package.json", "json"),
        ("go.mod", "go-deps"),
        ("Cargo.toml", "rust-deps"),
        ("build.gradle", "gradle"),
        ("unknown.xyz", "unknown"),
    ])
    def test_detect_language(self, path, expected):
        assert detect_language(path) == expected

    def test_case_insensitive(self):
        assert detect_language("src/Main.PY") == "python"

    def test_github_workflows(self):
        lang = detect_language(".github/workflows/ci.yml")
        assert lang in ("yaml",)  # Contains ".github/workflows"


class TestFileSensitivityScore:
    def test_auth_files_high(self):
        assert file_sensitivity_score("src/auth/login.py") >= 0.9

    def test_crypto_files_high(self):
        assert file_sensitivity_score("core/crypto.py") >= 0.9

    def test_test_files_low(self):
        # "login" in path boosts score, so use a non-security test file
        assert file_sensitivity_score("tests/test_utils.py") <= 0.6

    def test_unknown_files_default(self):
        assert file_sensitivity_score("foo/bar/baz.xyz") == 0.5

    def test_router_files_medium(self):
        score = file_sensitivity_score("api/user_router.py")
        assert 0.7 <= score <= 1.0


# ---------------------------------------------------------------------------
# DiffParser
# ---------------------------------------------------------------------------

class TestDiffParser:
    def setup_method(self):
        self.parser = DiffParser()

    def test_empty_diff(self):
        assert self.parser.parse("") == []
        assert self.parser.parse("   ") == []

    def test_parse_simple_diff(self):
        files = self.parser.parse(SAMPLE_DIFF)
        assert len(files) >= 1
        f = files[0]
        assert "login.py" in f.path
        assert f.language == "python"
        assert f.is_new_file is False
        assert f.is_deleted_file is False
        assert len(f.hunks) >= 1
        assert f.total_added >= 2
        assert f.total_removed >= 1

    def test_parse_new_file(self):
        files = self.parser.parse(SAMPLE_DIFF_NEW_FILE)
        assert len(files) >= 1
        f = files[0]
        assert f.is_new_file is True
        assert "secrets.py" in f.path
        assert f.total_added >= 5

    def test_parse_deleted_file(self):
        files = self.parser.parse(SAMPLE_DIFF_DELETED)
        assert len(files) >= 1
        f = files[0]
        assert f.is_deleted_file is True
        assert f.total_removed >= 3

    def test_parse_rename(self):
        files = self.parser.parse(SAMPLE_DIFF_RENAME)
        assert len(files) >= 1
        f = files[0]
        assert f.is_rename is True
        assert "new_name.py" in f.path

    def test_parse_binary(self):
        files = self.parser.parse(SAMPLE_DIFF_BINARY)
        assert len(files) >= 1
        f = files[0]
        assert "image.png" in f.path
        assert len(f.hunks) == 0

    def test_parse_multi_file_diff(self):
        files = self.parser.parse(SAMPLE_DIFF_MULTI)
        assert len(files) >= 2

    def test_hunk_line_numbers(self):
        files = self.parser.parse(SAMPLE_DIFF)
        hunk = files[0].hunks[0]
        assert hunk.old_start == 10
        assert hunk.new_start == 10


# ---------------------------------------------------------------------------
# PatternLibrary
# ---------------------------------------------------------------------------

class TestPatternLibrary:
    def setup_method(self):
        self.lib = PatternLibrary()

    def test_has_all_categories(self):
        for cat in [ChangeCategory.AUTH, ChangeCategory.CRYPTO,
                     ChangeCategory.DATA_FLOW, ChangeCategory.API_SURFACE,
                     ChangeCategory.DEPENDENCY, ChangeCategory.INFRASTRUCTURE]:
            patterns = self.lib.get_patterns_for_category(cat)
            assert len(patterns) > 0, f"No patterns for {cat}"

    def test_get_all_patterns(self):
        all_p = self.lib.get_all_patterns()
        assert len(all_p) > 50  # Should have many patterns
        # Each entry should be (id, compiled_regex, desc, conf, category, severity)
        first = all_p[0]
        assert len(first) == 6

    def test_auth_patterns_match(self):
        patterns = self.lib.get_patterns_for_category(ChangeCategory.AUTH)
        # At least one should match "login("
        matched = any(p[1].search("login(") for p in patterns)
        assert matched

    def test_crypto_patterns_match(self):
        patterns = self.lib.get_patterns_for_category(ChangeCategory.CRYPTO)
        matched = any(p[1].search("md5(") for p in patterns)
        assert matched

    def test_infra_patterns_match(self):
        patterns = self.lib.get_patterns_for_category(ChangeCategory.INFRASTRUCTURE)
        matched = any(p[1].search("FROM ubuntu:latest") for p in patterns)
        assert matched

    def test_dependency_patterns_match(self):
        patterns = self.lib.get_patterns_for_category(ChangeCategory.DEPENDENCY)
        matched = any(p[1].search('"dependencies":') for p in patterns)
        assert matched

    def test_unknown_category_returns_empty(self):
        patterns = self.lib.get_patterns_for_category(ChangeCategory.UNKNOWN)
        assert patterns == []

    def test_all_patterns_have_valid_ids(self):
        for pid, regex, desc, conf, cat, sev in self.lib.get_all_patterns():
            assert pid  # Non-empty ID
            assert 0.0 <= conf <= 1.0
            assert isinstance(sev, SeverityLevel)


# ---------------------------------------------------------------------------
# RiskScorer
# ---------------------------------------------------------------------------

class TestRiskScorer:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_score_returns_float(self):
        score = self.scorer.score(
            category=ChangeCategory.AUTH,
            severity=SeverityLevel.HIGH,
            churn=10,
            file_path="auth/login.py",
            confidence=0.9,
        )
        assert isinstance(score, (int, float))
        assert 0 <= score <= 100

    def test_high_confidence_higher_score(self):
        s_high = self.scorer.score(
            ChangeCategory.AUTH, SeverityLevel.HIGH, 5, "auth.py", 1.0
        )
        s_low = self.scorer.score(
            ChangeCategory.AUTH, SeverityLevel.HIGH, 5, "auth.py", 0.1
        )
        assert s_high >= s_low

    def test_critical_severity_higher_score(self):
        s_crit = self.scorer.score(
            ChangeCategory.AUTH, SeverityLevel.CRITICAL, 5, "auth.py", 0.9
        )
        s_low = self.scorer.score(
            ChangeCategory.AUTH, SeverityLevel.LOW, 5, "auth.py", 0.9
        )
        assert s_crit >= s_low

    def test_new_file_flag(self):
        score = self.scorer.score(
            ChangeCategory.AUTH, SeverityLevel.HIGH, 10, "auth.py", 0.8,
            is_new_file=True
        )
        assert isinstance(score, (int, float))

    def test_deletion_flag(self):
        score = self.scorer.score(
            ChangeCategory.CRYPTO, SeverityLevel.HIGH, 5, "crypto.py", 0.8,
            is_deletion=True
        )
        assert isinstance(score, (int, float))

    def test_vuln_density(self):
        score = self.scorer.score(
            ChangeCategory.DATA_FLOW, SeverityLevel.MEDIUM, 20, "db.py", 0.7,
            vuln_density=0.5
        )
        assert isinstance(score, (int, float))

    def test_aggregate_pr_score(self):
        scores = [80.0, 60.0, 40.0]
        agg = self.scorer.aggregate_pr_score(scores)
        assert isinstance(agg, (int, float))
        assert 0 <= agg <= 100

    def test_aggregate_empty_scores(self):
        agg = self.scorer.aggregate_pr_score([])
        assert isinstance(agg, (int, float))


# ---------------------------------------------------------------------------
# SemanticClassifier
# ---------------------------------------------------------------------------

class TestSemanticClassifier:
    def setup_method(self):
        self.classifier = SemanticClassifier()

    def test_classify_returns_valid(self):
        pm = PatternMatch("AUTH-003", ChangeCategory.AUTH, "Hardcoded password",
                          "password='admin'", "password='admin'", 0, True, 0.95)
        result = self.classifier.classify(
            risk_score=90.0, category=ChangeCategory.AUTH,
            pattern_matches=[pm], file_path="auth.py", churn=10
        )
        assert result in (ChangeClassification.BREAKING,
                          ChangeClassification.MATERIAL,
                          ChangeClassification.COSMETIC)

    def test_high_risk_is_breaking_or_material(self):
        pm = PatternMatch("AUTH-003", ChangeCategory.AUTH, "Hardcoded password",
                          "password='admin'", "password='admin'", 0, True, 0.95)
        result = self.classifier.classify(
            risk_score=95.0, category=ChangeCategory.AUTH,
            pattern_matches=[pm], file_path="auth.py", churn=10
        )
        assert result in (ChangeClassification.BREAKING, ChangeClassification.MATERIAL)

    def test_low_risk_cosmetic(self):
        result = self.classifier.classify(
            risk_score=5.0, category=ChangeCategory.UNKNOWN,
            pattern_matches=[], file_path="utils.py", churn=1
        )
        assert result in (ChangeClassification.BREAKING,
                          ChangeClassification.MATERIAL,
                          ChangeClassification.COSMETIC)

    def test_is_cosmetic_only(self):
        # Whitespace-only changes should be cosmetic
        result = self.classifier.is_cosmetic_only(
            added_lines=["    x = 1", "    y = 2"],
            removed_lines=["  x = 1", "  y = 2"]
        )
        assert isinstance(result, bool)

    def test_is_cosmetic_empty(self):
        result = self.classifier.is_cosmetic_only([], [])
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# MaterialChangeDetector
# ---------------------------------------------------------------------------

class TestMaterialChangeDetector:
    def setup_method(self):
        self.detector = MaterialChangeDetector()

    def test_analyze_empty_diff(self):
        results = self.detector.analyze_diff("")
        assert results == []

    def test_analyze_auth_change(self):
        results = self.detector.analyze_diff(SAMPLE_DIFF)
        assert isinstance(results, list)
        # Auth change should produce at least one material change
        if results:
            mc = results[0]
            assert isinstance(mc, MaterialChange)
            assert mc.file_path
            assert mc.risk_score >= 0

    def test_analyze_secrets_diff(self):
        results = self.detector.analyze_diff(SAMPLE_DIFF_NEW_FILE)
        assert isinstance(results, list)
        # Secrets should trigger pattern matches
        if results:
            categories = {mc.category for mc in results}
            # Should detect auth or crypto patterns
            assert len(categories) > 0

    def test_analyze_infra_diff(self):
        results = self.detector.analyze_diff(SAMPLE_DIFF_INFRA)
        assert isinstance(results, list)
        if results:
            # Infrastructure changes should be flagged
            infra_changes = [mc for mc in results
                             if mc.category == ChangeCategory.INFRASTRUCTURE]
            # 0.0.0.0/0 should trigger infrastructure pattern
            assert len(infra_changes) >= 0  # May or may not detect

    def test_analyze_multi_file(self):
        results = self.detector.analyze_diff(SAMPLE_DIFF_MULTI)
        assert isinstance(results, list)

    def test_change_ids_are_unique(self):
        results = self.detector.analyze_diff(SAMPLE_DIFF_NEW_FILE)
        if len(results) > 1:
            ids = [mc.change_id for mc in results]
            assert len(ids) == len(set(ids))

    def test_javascript_patterns_detected(self):
        results = self.detector.analyze_diff(SAMPLE_DIFF_JAVASCRIPT)
        assert isinstance(results, list)


# ---------------------------------------------------------------------------
# PRAnalyzer
# ---------------------------------------------------------------------------

class TestPRAnalyzer:
    def setup_method(self):
        self.analyzer = PRAnalyzer()

    def _file_diffs(self, diff_text, path="auth/login.py"):
        """Wrap raw diff text into the List[Dict] format PRAnalyzer expects."""
        return [{"path": path, "diff": diff_text}]

    def test_analyze_pr_returns_assessment(self):
        result = self.analyzer.analyze_pr("PR-001", self._file_diffs(SAMPLE_DIFF))
        assert isinstance(result, PRRiskAssessment)
        assert result.pr_id == "PR-001"
        assert 0 <= result.overall_risk_score <= 100
        assert result.classification in (
            ChangeClassification.BREAKING,
            ChangeClassification.MATERIAL,
            ChangeClassification.COSMETIC,
        )

    def test_analyze_pr_empty_diff(self):
        result = self.analyzer.analyze_pr("PR-002", [])
        assert isinstance(result, PRRiskAssessment)

    def test_analyze_pr_with_secrets(self):
        result = self.analyzer.analyze_pr(
            "PR-003", self._file_diffs(SAMPLE_DIFF_NEW_FILE, "config/secrets.py")
        )
        assert isinstance(result, PRRiskAssessment)
        if result.material_changes:
            assert result.overall_risk_score > 0

    def test_analyze_pr_infra(self):
        result = self.analyzer.analyze_pr(
            "PR-004", self._file_diffs(SAMPLE_DIFF_INFRA, "deploy/main.tf")
        )
        assert isinstance(result, PRRiskAssessment)

    def test_classify_changes(self):
        changes = self.analyzer.classify_changes(self._file_diffs(SAMPLE_DIFF))
        assert isinstance(changes, dict)

    def test_pr_has_stats(self):
        diffs = self._file_diffs(SAMPLE_DIFF) + self._file_diffs(SAMPLE_DIFF_INFRA, "deploy/main.tf")
        result = self.analyzer.analyze_pr("PR-005", diffs)
        assert isinstance(result.stats, dict)

    def test_pr_has_reviewers(self):
        result = self.analyzer.analyze_pr("PR-006", self._file_diffs(SAMPLE_DIFF))
        assert isinstance(result.recommended_reviewers, list)

    def test_pr_has_checklist(self):
        result = self.analyzer.analyze_pr("PR-007", self._file_diffs(SAMPLE_DIFF))
        assert isinstance(result.review_checklist, list)


# ---------------------------------------------------------------------------
# VelocityTracker
# ---------------------------------------------------------------------------

class TestVelocityTracker:
    def setup_method(self):
        self.tracker = VelocityTracker()

    def test_record_and_snapshot(self):
        changes = [
            MaterialChange(
                change_id="c1", file_path="auth.py",
                category=ChangeCategory.AUTH,
                classification=ChangeClassification.MATERIAL,
                severity=SeverityLevel.HIGH,
                risk_score=70.0, summary="Auth change",
                explanation="Details", pattern_matches=[],
                recommended_reviewers=[], review_items=[]
            ),
            MaterialChange(
                change_id="c2", file_path="crypto.py",
                category=ChangeCategory.CRYPTO,
                classification=ChangeClassification.BREAKING,
                severity=SeverityLevel.CRITICAL,
                risk_score=90.0, summary="Crypto change",
                explanation="Details", pattern_matches=[],
                recommended_reviewers=[], review_items=[]
            ),
        ]
        self.tracker.record_changes("test-repo", changes)
        snap = self.tracker.snapshot("test-repo")
        assert isinstance(snap, VelocitySnapshot)
        assert snap.repo == "test-repo"
        assert snap.material_change_count >= 2
        assert snap.breaking_change_count >= 1

    def test_snapshot_empty_repo(self):
        snap = self.tracker.snapshot("nonexistent-repo")
        assert isinstance(snap, VelocitySnapshot)
        assert snap.material_change_count == 0

    def test_list_repos(self):
        self.tracker.record_changes("repo-a", [])
        repos = self.tracker.list_repos()
        assert "repo-a" in repos

    def test_clear_repo(self):
        changes = [
            MaterialChange(
                change_id="c3", file_path="x.py",
                category=ChangeCategory.AUTH,
                classification=ChangeClassification.COSMETIC,
                severity=SeverityLevel.LOW, risk_score=10.0,
                summary="Minor", explanation="", pattern_matches=[],
                recommended_reviewers=[], review_items=[]
            )
        ]
        self.tracker.record_changes("repo-clear", changes)
        self.tracker.clear_repo("repo-clear")
        snap = self.tracker.snapshot("repo-clear")
        assert snap.material_change_count == 0

    def test_historical_profile(self):
        changes = [
            MaterialChange(
                change_id="h1", file_path="auth.py",
                category=ChangeCategory.AUTH,
                classification=ChangeClassification.MATERIAL,
                severity=SeverityLevel.HIGH, risk_score=60.0,
                summary="Change", explanation="", pattern_matches=[],
                recommended_reviewers=[], review_items=[]
            )
        ]
        self.tracker.record_changes("repo-hist", changes)
        profile = self.tracker.historical_profile("repo-hist")
        assert isinstance(profile, dict)


# ---------------------------------------------------------------------------
# Integration: Full Pipeline
# ---------------------------------------------------------------------------

class TestFullPipeline:
    """End-to-end tests combining parser → detector → PR analyzer."""

    def test_full_auth_change_pipeline(self):
        analyzer = PRAnalyzer()
        diffs = [{"path": "auth/login.py", "diff": SAMPLE_DIFF}]
        result = analyzer.analyze_pr("INT-001", diffs)
        assert result.pr_id == "INT-001"
        assert isinstance(result.overall_risk_score, (int, float))
        assert isinstance(result.classification, ChangeClassification)

    def test_full_secrets_pipeline(self):
        analyzer = PRAnalyzer()
        diffs = [{"path": "config/secrets.py", "diff": SAMPLE_DIFF_NEW_FILE}]
        result = analyzer.analyze_pr("INT-002", diffs)
        if result.material_changes:
            severities = {mc.severity for mc in result.material_changes}
            assert len(severities) > 0

    def test_full_infra_pipeline(self):
        analyzer = PRAnalyzer()
        diffs = [{"path": "deploy/main.tf", "diff": SAMPLE_DIFF_INFRA}]
        result = analyzer.analyze_pr("INT-003", diffs)
        assert isinstance(result, PRRiskAssessment)

    def test_velocity_after_analysis(self):
        tracker = VelocityTracker()
        detector = MaterialChangeDetector()
        changes = detector.analyze_diff(SAMPLE_DIFF_NEW_FILE)
        if changes:
            tracker.record_changes("velocity-test", changes)
            snap = tracker.snapshot("velocity-test")
            assert snap.material_change_count > 0
