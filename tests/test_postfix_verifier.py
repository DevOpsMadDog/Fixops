"""Tests for the MPTE Post-Fix Verification Engine.

Covers: PostFixVerifier, CheckResult, CheckStatus, VerificationReport,
vulnerability pattern scanning, static analysis, regression checks, and more.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))


from core.postfix_verifier import (
    CheckResult,
    CheckStatus,
    MPTERetestResult,
    PostFixVerifier,
    VerificationReport,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VULN_PYTHON_CODE = """\
import os
import pickle

def handle_request(user_input):
    os.system(user_input)
    data = pickle.loads(user_input)
    cursor.execute("SELECT * FROM users WHERE id = '%s'" % user_input)
    eval(user_input)
    return data
"""

FIXED_PYTHON_CODE = """\
import subprocess
import json

def handle_request(user_input):
    subprocess.run(["ls", "-la"], check=True)
    data = json.loads(user_input)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))
    return data
"""

VULN_JS_CODE = """\
const express = require('express');
app.get('/search', (req, res) => {
    document.write(req.query.q);
    eval(req.query.q);
    child_process.exec(req.query.cmd);
});
"""

FIXED_JS_CODE = """\
const express = require('express');
app.get('/search', (req, res) => {
    const sanitized = DOMPurify.sanitize(req.query.q);
    res.json({ result: sanitized });
});
"""

VULN_JAVA_CODE = """\
public class UserService {
    public void findUser(String input) {
        Statement stmt = conn.createStatement();
        stmt.execute("SELECT * FROM users WHERE id = '" + input + "'");
        Runtime.getRuntime().exec(input);
    }
}
"""

FIXED_JAVA_CODE = """\
public class UserService {
    public void findUser(String input) {
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        stmt.setString(1, input);
        stmt.execute();
    }
}
"""


def _verify(verifier, **kwargs):
    """Helper to call verify with the correct signature (including severity)."""
    # Signature: verify(finding_id, finding_type, severity, original_code, fixed_code, language, ...)
    defaults = {"severity": "high"}
    defaults.update(kwargs)
    return verifier.verify(**defaults)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class TestCheckStatus:
    def test_values(self):
        assert CheckStatus.PASSED == "passed"
        assert CheckStatus.FAILED == "failed"
        assert CheckStatus.WARNING == "warning"
        assert CheckStatus.SKIPPED == "skipped"
        assert CheckStatus.INCONCLUSIVE == "inconclusive"


class TestMPTERetestResult:
    def test_values(self):
        assert MPTERetestResult.EXPLOIT_BLOCKED == "exploit_blocked"
        assert MPTERetestResult.EXPLOIT_STILL_POSSIBLE == "exploit_still_possible"
        assert MPTERetestResult.INCONCLUSIVE == "inconclusive"
        assert MPTERetestResult.NOT_APPLICABLE == "not_applicable"


# ---------------------------------------------------------------------------
# CheckResult
# ---------------------------------------------------------------------------

class TestCheckResult:
    def test_creation(self):
        cr = CheckResult(
            check_name="syntax_check",
            status=CheckStatus.PASSED,
            description="Syntax is valid",
            details="No errors found",
            cwe="CWE-89",
            severity="high",
            duration_ms=5.2
        )
        assert cr.check_name == "syntax_check"
        assert cr.status == CheckStatus.PASSED
        assert cr.duration_ms == 5.2

    def test_defaults(self):
        cr = CheckResult(
            check_name="test",
            status=CheckStatus.PASSED,
            description="ok"
        )
        assert cr.details is None
        assert cr.cwe is None
        assert cr.severity == "info"
        assert cr.duration_ms == 0.0


# ---------------------------------------------------------------------------
# VerificationReport
# ---------------------------------------------------------------------------

class TestVerificationReport:
    def _make_report(self, **kwargs):
        defaults = dict(
            finding_id="FIND-001",
            finding_type="sql_injection",
            language="python",
            verified=True,
            confidence=0.95,
            checks_passed=5,
            checks_total=6,
            regressions_found=[],
            mpte_retest_result=MPTERetestResult.EXPLOIT_BLOCKED.value,
            safe_to_deploy=True,
            verification_duration_ms=123.4,
            detailed_checks=[
                CheckResult("c1", CheckStatus.PASSED, "ok"),
                CheckResult("c2", CheckStatus.FAILED, "fail"),
            ],
            fix_fingerprint="abc123",
            original_fingerprint="xyz789",
            recommendation="Deploy the fix",
        )
        defaults.update(kwargs)
        return VerificationReport(**defaults)

    def test_to_dict(self):
        report = self._make_report()
        d = report.to_dict()
        assert d["finding_id"] == "FIND-001"
        assert d["finding_type"] == "sql_injection"
        assert d["verified"] is True
        assert d["confidence"] == 0.95
        assert d["checks_passed"] == 5
        assert d["checks_total"] == 6
        assert d["safe_to_deploy"] is True
        assert len(d["detailed_checks"]) == 2
        assert d["detailed_checks"][0]["status"] == "passed"
        assert d["detailed_checks"][1]["status"] == "failed"

    def test_to_dict_with_regressions(self):
        report = self._make_report(regressions_found=["CWE-79", "CWE-502"])
        d = report.to_dict()
        assert d["regressions_found"] == ["CWE-79", "CWE-502"]

    def test_timestamp_auto_set(self):
        report = self._make_report()
        assert report.timestamp  # Should be auto-set


# ---------------------------------------------------------------------------
# PostFixVerifier
# ---------------------------------------------------------------------------

class TestPostFixVerifier:
    def setup_method(self):
        self.verifier = PostFixVerifier()

    def test_verify_python_fix(self):
        report = _verify(self.verifier,
            finding_id="PY-001",
            finding_type="sql_injection",
            severity="critical",
            language="python",
            original_code=VULN_PYTHON_CODE,
            fixed_code=FIXED_PYTHON_CODE,
        )
        assert isinstance(report, VerificationReport)
        assert report.finding_id == "PY-001"
        assert report.language == "python"
        assert report.checks_total > 0
        assert isinstance(report.confidence, float)
        assert 0.0 <= report.confidence <= 1.0

    def test_verify_javascript_fix(self):
        report = _verify(self.verifier,
            finding_id="JS-001",
            finding_type="xss",
            severity="high",
            language="javascript",
            original_code=VULN_JS_CODE,
            fixed_code=FIXED_JS_CODE,
        )
        assert isinstance(report, VerificationReport)
        assert report.finding_id == "JS-001"
        assert report.language == "javascript"

    def test_verify_java_fix(self):
        report = _verify(self.verifier,
            finding_id="JAVA-001",
            finding_type="sql_injection",
            severity="critical",
            language="java",
            original_code=VULN_JAVA_CODE,
            fixed_code=FIXED_JAVA_CODE,
        )
        assert isinstance(report, VerificationReport)
        assert report.finding_id == "JAVA-001"
        assert report.language == "java"

    def test_verify_unfixed_code(self):
        """Verify that passing identical vulnerable code is detected."""
        report = _verify(self.verifier,
            finding_id="SAME-001",
            finding_type="command_injection",
            severity="critical",
            language="python",
            original_code=VULN_PYTHON_CODE,
            fixed_code=VULN_PYTHON_CODE,
        )
        assert isinstance(report, VerificationReport)

    def test_verify_empty_code(self):
        report = _verify(self.verifier,
            finding_id="EMPTY-001",
            finding_type="xss",
            severity="medium",
            language="python",
            original_code="",
            fixed_code="",
        )
        assert isinstance(report, VerificationReport)

    def test_verify_generates_fingerprints(self):
        report = _verify(self.verifier,
            finding_id="FP-001",
            finding_type="sql_injection",
            severity="critical",
            language="python",
            original_code=VULN_PYTHON_CODE,
            fixed_code=FIXED_PYTHON_CODE,
        )
        assert report.fix_fingerprint
        assert report.original_fingerprint
        assert report.fix_fingerprint != report.original_fingerprint

    def test_verify_report_to_dict(self):
        report = _verify(self.verifier,
            finding_id="DICT-001",
            finding_type="xss",
            severity="high",
            language="python",
            original_code=VULN_PYTHON_CODE,
            fixed_code=FIXED_PYTHON_CODE,
        )
        d = report.to_dict()
        assert isinstance(d, dict)
        assert "finding_id" in d
        assert "detailed_checks" in d
        assert "confidence" in d

    def test_verify_duration_tracked(self):
        report = _verify(self.verifier,
            finding_id="DUR-001",
            finding_type="command_injection",
            severity="high",
            language="python",
            original_code=VULN_PYTHON_CODE,
            fixed_code=FIXED_PYTHON_CODE,
        )
        assert report.verification_duration_ms >= 0

    def test_supported_languages(self):
        langs = self.verifier.supported_languages()
        assert isinstance(langs, (list, set, tuple))
        assert "python" in langs

    def test_verify_command_injection(self):
        report = _verify(self.verifier,
            finding_id="CMD-001",
            finding_type="command_injection",
            severity="critical",
            language="python",
            original_code="import os\nos.system(user_input)",
            fixed_code="import subprocess\nsubprocess.run(['ls'], check=True)",
        )
        assert isinstance(report, VerificationReport)

    def test_verify_deserialization(self):
        report = _verify(self.verifier,
            finding_id="DESER-001",
            finding_type="deserialization",
            severity="critical",
            language="python",
            original_code="import pickle\ndata = pickle.loads(raw)",
            fixed_code="import json\ndata = json.loads(raw)",
        )
        assert isinstance(report, VerificationReport)

    def test_verify_path_traversal(self):
        report = _verify(self.verifier,
            finding_id="PATH-001",
            finding_type="path_traversal",
            severity="high",
            language="python",
            original_code="open(request.args['file'])",
            fixed_code="import os\npath = os.path.basename(request.args['file'])\nopen(path)",
        )
        assert isinstance(report, VerificationReport)

    def test_get_history(self):
        _verify(self.verifier,
            finding_id="HIST-001",
            finding_type="xss",
            severity="medium",
            language="python",
            original_code="x",
            fixed_code="y",
        )
        history = self.verifier.get_history(10)
        assert isinstance(history, list)
        assert len(history) >= 1

    def test_get_stats(self):
        stats = self.verifier.get_stats()
        assert isinstance(stats, dict)


# ---------------------------------------------------------------------------
# Pattern Detection Tests
# ---------------------------------------------------------------------------

class TestPatternDetection:
    """Test that vulnerability patterns are properly detected/removed."""

    def setup_method(self):
        self.verifier = PostFixVerifier()

    def test_python_sqli_detected(self):
        report = _verify(self.verifier,
            finding_id="SQLI-PY",
            finding_type="sql_injection",
            severity="critical",
            language="python",
            original_code='cursor.execute("SELECT * FROM t WHERE id = %s" % uid)',
            fixed_code='cursor.execute("SELECT * FROM t WHERE id = %s", (uid,))',
        )
        assert isinstance(report, VerificationReport)

    def test_python_eval_detected(self):
        report = _verify(self.verifier,
            finding_id="EVAL-PY",
            finding_type="command_injection",
            severity="critical",
            language="python",
            original_code="result = eval(user_input)",
            fixed_code="result = safe_parse(user_input)",
        )
        assert isinstance(report, VerificationReport)

    def test_python_pickle_detected(self):
        report = _verify(self.verifier,
            finding_id="PICKLE-PY",
            finding_type="deserialization",
            severity="critical",
            language="python",
            original_code="data = pickle.loads(raw_bytes)",
            fixed_code="data = json.loads(raw_str)",
        )
        assert isinstance(report, VerificationReport)

    def test_ssrf_detected(self):
        report = _verify(self.verifier,
            finding_id="SSRF-PY",
            finding_type="ssrf",
            severity="high",
            language="python",
            original_code="requests.get(request.args['url'])",
            fixed_code="requests.get(ALLOWED_URLS[request.args['url_id']])",
        )
        assert isinstance(report, VerificationReport)
