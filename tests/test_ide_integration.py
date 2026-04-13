"""Tests for IDE integration module — IDEIntegration, SAST patterns, scan_file, scan_diff.

Run with: python -m pytest tests/test_ide_integration.py -x --tb=short --timeout=10 -q
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.ide_integration import (
    IDEFinding,
    IDEIntegration,
    IDESession,
    SAST_PATTERNS,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def ide():
    """Fresh in-memory IDEIntegration instance."""
    return IDEIntegration(db_path=":memory:")


@pytest.fixture
def session(ide):
    """A registered session."""
    return ide.register_session(
        user_email="alice@example.com",
        ide_type="vscode",
        project_path="/home/alice/myproject",
        org_id="org-1",
    )


# ============================================================================
# Pattern coverage — all 12 SAST_PATTERNS must be present
# ============================================================================


class TestSASTPatterns:
    def test_exactly_12_patterns(self):
        assert len(SAST_PATTERNS) == 12

    def test_all_pattern_rule_ids_unique(self):
        rule_ids = [p[0] for p in SAST_PATTERNS]
        assert len(rule_ids) == len(set(rule_ids))

    def test_pattern_tuple_has_seven_fields(self):
        for pattern in SAST_PATTERNS:
            assert len(pattern) == 7, f"Pattern {pattern[0]} should have 7 fields"

    def test_severity_values_are_valid(self):
        valid = {"HIGH", "MEDIUM", "LOW"}
        for p in SAST_PATTERNS:
            assert p[2] in valid, f"Pattern {p[0]} has invalid severity {p[2]}"

    def test_all_patterns_have_cwe(self):
        for p in SAST_PATTERNS:
            assert p[5].startswith("CWE-"), f"Pattern {p[0]} missing CWE"


# ============================================================================
# scan_file — detects each of the 12 SAST patterns
# ============================================================================


class TestScanFile:
    def test_sql_injection_detected(self, ide):
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)'
        findings = ide.scan_file(code, "db.py", "python")
        rule_ids = [f.rule_id for f in findings]
        assert "sql_injection" in rule_ids

    def test_eval_exec_detected(self, ide):
        code = "eval(user_input)"
        findings = ide.scan_file(code, "app.py", "python")
        rule_ids = [f.rule_id for f in findings]
        assert "eval_exec" in rule_ids

    def test_hardcoded_password_detected(self, ide):
        code = 'password = "supersecret123"'
        findings = ide.scan_file(code, "config.py", "python")
        rule_ids = [f.rule_id for f in findings]
        assert "hardcoded_password" in rule_ids

    def test_insecure_random_detected(self, ide):
        code = "token = random.random()"
        findings = ide.scan_file(code, "auth.py", "python")
        rule_ids = [f.rule_id for f in findings]
        assert "insecure_random" in rule_ids

    def test_path_traversal_detected(self, ide):
        code = 'f = open("/base/" + user_path)'
        findings = ide.scan_file(code, "files.py", "python")
        rule_ids = [f.rule_id for f in findings]
        assert "path_traversal" in rule_ids

    def test_xss_innerhtml_detected(self, ide):
        code = "element.innerHTML = userInput;"
        findings = ide.scan_file(code, "app.js", "javascript")
        rule_ids = [f.rule_id for f in findings]
        assert "xss_innerhtml" in rule_ids

    def test_command_injection_detected(self, ide):
        code = "os.system(cmd)"
        findings = ide.scan_file(code, "runner.py", "python")
        rule_ids = [f.rule_id for f in findings]
        assert "command_injection" in rule_ids

    def test_weak_crypto_md5_detected(self, ide):
        code = "digest = md5(data)"
        findings = ide.scan_file(code, "crypto.py", "python")
        rule_ids = [f.rule_id for f in findings]
        assert "weak_crypto" in rule_ids

    def test_weak_crypto_sha1_detected(self, ide):
        code = "digest = sha1(data)"
        findings = ide.scan_file(code, "crypto.py", "python")
        rule_ids = [f.rule_id for f in findings]
        assert "weak_crypto" in rule_ids

    def test_debug_logging_detected(self, ide):
        code = 'print("password:", user_password)'
        findings = ide.scan_file(code, "login.py", "python")
        rule_ids = [f.rule_id for f in findings]
        assert "debug_logging" in rule_ids

    def test_no_verify_ssl_detected(self, ide):
        code = "requests.get(url, verify=False)"
        findings = ide.scan_file(code, "client.py", "python")
        rule_ids = [f.rule_id for f in findings]
        assert "no_verify_ssl" in rule_ids

    def test_js_eval_detected(self, ide):
        code = "var result = eval(expr);"
        findings = ide.scan_file(code, "app.js", "javascript")
        rule_ids = [f.rule_id for f in findings]
        assert "js_eval" in rule_ids

    def test_document_write_detected(self, ide):
        code = "document.write(userContent);"
        findings = ide.scan_file(code, "page.js", "javascript")
        rule_ids = [f.rule_id for f in findings]
        assert "document_write" in rule_ids

    def test_clean_code_returns_no_findings(self, ide):
        code = "def add(a, b):\n    return a + b\n"
        findings = ide.scan_file(code, "math.py", "python")
        assert findings == []

    def test_finding_has_correct_file_path(self, ide):
        code = "eval(x)"
        findings = ide.scan_file(code, "src/app.py", "python")
        assert all(f.file_path == "src/app.py" for f in findings)

    def test_finding_line_numbers_are_correct(self, ide):
        code = "x = 1\neval(bad)\ny = 2"
        findings = ide.scan_file(code, "f.py", "python")
        eval_findings = [f for f in findings if f.rule_id == "eval_exec"]
        assert eval_findings[0].line_start == 2

    def test_multiple_findings_on_same_file(self, ide):
        code = 'password = "abc123"\neval(x)'
        findings = ide.scan_file(code, "f.py", "python")
        rule_ids = {f.rule_id for f in findings}
        assert "hardcoded_password" in rule_ids
        assert "eval_exec" in rule_ids

    def test_finding_fields_populated(self, ide):
        code = "eval(x)"
        findings = ide.scan_file(code, "f.py", "python")
        f = findings[0]
        assert f.severity in {"HIGH", "MEDIUM", "LOW"}
        assert f.title
        assert f.description
        assert f.cwe_id
        assert f.fix_suggestion
        assert f.rule_id

    def test_returns_list_of_ide_finding(self, ide):
        code = "eval(x)"
        findings = ide.scan_file(code, "f.py", "python")
        assert isinstance(findings, list)
        assert all(isinstance(f, IDEFinding) for f in findings)


# ============================================================================
# scan_diff — only catches added lines
# ============================================================================


class TestScanDiff:
    def _make_diff(self, added_line: str, file: str = "src/app.py") -> str:
        return (
            f"diff --git a/{file} b/{file}\n"
            f"--- a/{file}\n"
            f"+++ b/{file}\n"
            f"@@ -1,1 +1,2 @@\n"
            f" existing line\n"
            f"+{added_line}\n"
        )

    def test_added_eval_caught(self, ide):
        diff = self._make_diff("eval(user_input)")
        findings = ide.scan_diff(diff)
        rule_ids = [f.rule_id for f in findings]
        assert "eval_exec" in rule_ids

    def test_removed_line_not_caught(self, ide):
        diff = (
            "diff --git a/f.py b/f.py\n"
            "--- a/f.py\n"
            "+++ b/f.py\n"
            "@@ -1,2 +1,1 @@\n"
            "-eval(user_input)\n"
            " safe_line\n"
        )
        findings = ide.scan_diff(diff)
        assert findings == []

    def test_context_line_not_caught(self, ide):
        diff = (
            "diff --git a/f.py b/f.py\n"
            "--- a/f.py\n"
            "+++ b/f.py\n"
            "@@ -1,2 +1,2 @@\n"
            " eval(user_input)\n"
            "+safe_new_line\n"
        )
        findings = ide.scan_diff(diff)
        assert findings == []

    def test_file_path_extracted_from_diff(self, ide):
        diff = self._make_diff("eval(x)", file="core/auth.py")
        findings = ide.scan_diff(diff)
        assert any(f.file_path == "core/auth.py" for f in findings)

    def test_clean_diff_returns_empty(self, ide):
        diff = self._make_diff("x = 1 + 2")
        findings = ide.scan_diff(diff)
        assert findings == []

    def test_multiple_patterns_in_diff(self, ide):
        diff = (
            "diff --git a/f.py b/f.py\n"
            "--- a/f.py\n"
            "+++ b/f.py\n"
            "@@ -1 +1,3 @@\n"
            '+password = "hunter2"\n'
            "+eval(cmd)\n"
        )
        findings = ide.scan_diff(diff)
        rule_ids = {f.rule_id for f in findings}
        assert "hardcoded_password" in rule_ids
        assert "eval_exec" in rule_ids


# ============================================================================
# register_session / heartbeat / get_active_sessions
# ============================================================================


class TestSessionManagement:
    def test_register_session_returns_ide_session(self, ide):
        s = ide.register_session("bob@x.com", "jetbrains", "/proj", "org-2")
        assert isinstance(s, IDESession)

    def test_register_session_fields(self, ide):
        s = ide.register_session("bob@x.com", "jetbrains", "/proj", "org-2")
        assert s.user_email == "bob@x.com"
        assert s.ide_type == "jetbrains"
        assert s.project_path == "/proj"
        assert s.org_id == "org-2"
        assert s.findings_shown == 0
        assert s.fixes_applied == 0

    def test_register_session_generates_unique_ids(self, ide):
        s1 = ide.register_session("a@x.com", "vscode", "/p1", "org-1")
        s2 = ide.register_session("b@x.com", "vscode", "/p2", "org-1")
        assert s1.id != s2.id

    def test_heartbeat_updates_last_active(self, ide, session):
        before = session.last_active
        import time; time.sleep(0.01)
        ide.heartbeat(session.id)
        sessions = ide.get_active_sessions("org-1")
        updated = next(s for s in sessions if s["id"] == session.id)
        assert updated["last_active"] >= before

    def test_get_active_sessions_returns_list(self, ide, session):
        sessions = ide.get_active_sessions("org-1")
        assert isinstance(sessions, list)
        assert len(sessions) >= 1

    def test_get_active_sessions_filters_by_org(self, ide):
        ide.register_session("a@x.com", "vscode", "/p", "org-A")
        ide.register_session("b@x.com", "vscode", "/p", "org-B")
        sessions_a = ide.get_active_sessions("org-A")
        assert all(s["org_id"] == "org-A" for s in sessions_a)

    def test_get_active_sessions_empty_for_unknown_org(self, ide):
        assert ide.get_active_sessions("no-such-org") == []


# ============================================================================
# get_ide_stats
# ============================================================================


class TestIDEStats:
    def test_stats_returns_dict_with_expected_keys(self, ide, session):
        stats = ide.get_ide_stats("org-1")
        assert "sessions" in stats
        assert "findings_shown" in stats
        assert "fixes_applied" in stats

    def test_stats_counts_sessions(self, ide):
        ide.register_session("a@x.com", "vscode", "/p1", "org-stats")
        ide.register_session("b@x.com", "vscode", "/p2", "org-stats")
        stats = ide.get_ide_stats("org-stats")
        assert stats["sessions"] == 2

    def test_stats_zero_for_unknown_org(self, ide):
        stats = ide.get_ide_stats("org-does-not-exist")
        assert stats["sessions"] == 0
        assert stats["findings_shown"] == 0
        assert stats["fixes_applied"] == 0

    def test_stats_reflects_fixes_applied(self, ide, session):
        ide.record_fix_applied(session.id, "eval_exec")
        ide.record_fix_applied(session.id, "hardcoded_password")
        stats = ide.get_ide_stats("org-1")
        assert stats["fixes_applied"] == 2


# ============================================================================
# get_fix_for_finding
# ============================================================================


class TestGetFixForFinding:
    def test_returns_dict_with_expected_keys(self, ide):
        finding = IDEFinding(
            file_path="f.py", line_start=1, line_end=1,
            severity="HIGH", title="Eval", description="dangerous",
            fix_suggestion="Use ast.literal_eval", cwe_id="CWE-95",
            rule_id="eval_exec",
        )
        result = ide.get_fix_for_finding(finding)
        assert "finding_id" in result
        assert "suggestion" in result
        assert "cwe" in result
        assert "severity" in result

    def test_fix_propagates_suggestion(self, ide):
        finding = IDEFinding(
            file_path="f.py", line_start=1, line_end=1,
            severity="HIGH", title="Eval", description="dangerous",
            fix_suggestion="Use ast.literal_eval", cwe_id="CWE-95",
            rule_id="eval_exec",
        )
        result = ide.get_fix_for_finding(finding)
        assert result["suggestion"] == "Use ast.literal_eval"

    def test_fix_fallback_when_no_suggestion(self, ide):
        finding = IDEFinding(
            file_path="f.py", line_start=1, line_end=1,
            severity="HIGH", title="X", description="Y",
            rule_id="custom_rule",
        )
        result = ide.get_fix_for_finding(finding)
        assert result["suggestion"] == "No automated fix"


# ============================================================================
# get_patterns
# ============================================================================


class TestGetPatterns:
    def test_returns_list(self, ide):
        patterns = ide.get_patterns()
        assert isinstance(patterns, list)

    def test_returns_12_patterns(self, ide):
        patterns = ide.get_patterns()
        assert len(patterns) == 12

    def test_pattern_dict_has_expected_keys(self, ide):
        patterns = ide.get_patterns()
        for p in patterns:
            assert "rule_id" in p
            assert "severity" in p
            assert "title" in p
            assert "cwe" in p

    def test_all_severities_present(self, ide):
        patterns = ide.get_patterns()
        severities = {p["severity"] for p in patterns}
        assert "HIGH" in severities
        assert "MEDIUM" in severities
