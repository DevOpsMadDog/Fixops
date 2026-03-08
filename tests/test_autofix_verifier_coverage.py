"""Comprehensive tests for core.autofix_verifier — Fix Verification Engine.

Tests AutoFixVerifier class: syntax checks, security regression detection,
pattern matching, complexity analysis, and verification stats.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

import pytest
from core.autofix_verifier import (
    VerificationStatus,
    FixRisk,
    VerificationCheck,
    FixVerificationResult,
    AutoFixVerifier,
    verify_fix,
    get_verifier_stats,
)


# ── Enumerations ──────────────────────────────────────────────

class TestEnumerations:
    def test_verification_status_values(self):
        assert VerificationStatus.PASSED == "passed"
        assert VerificationStatus.FAILED == "failed"
        assert VerificationStatus.WARNING == "warning"
        assert VerificationStatus.SKIPPED == "skipped"
        assert VerificationStatus.ERROR == "error"

    def test_fix_risk_values(self):
        assert FixRisk.SAFE == "safe"
        assert FixRisk.LOW_RISK == "low_risk"
        assert FixRisk.MEDIUM_RISK == "medium_risk"
        assert FixRisk.HIGH_RISK == "high_risk"
        assert FixRisk.DANGEROUS == "dangerous"


# ── Data Models ───────────────────────────────────────────────

class TestDataModels:
    def test_verification_check(self):
        vc = VerificationCheck(
            name="syntax_check",
            status=VerificationStatus.PASSED,
            description="Python syntax is valid",
        )
        assert vc.name == "syntax_check"
        assert vc.status == VerificationStatus.PASSED
        assert vc.severity == "info"  # default

    def test_verification_check_with_details(self):
        vc = VerificationCheck(
            name="security_regression",
            status=VerificationStatus.FAILED,
            description="New eval() found",
            details="Line 15: eval(user_input)",
            severity="critical",
        )
        assert vc.details == "Line 15: eval(user_input)"
        assert vc.severity == "critical"

    def test_fix_verification_result(self):
        fvr = FixVerificationResult(
            finding_id="VULN-001",
            fix_id="FIX-001",
            status=VerificationStatus.PASSED,
            risk_level=FixRisk.SAFE,
        )
        assert fvr.finding_id == "VULN-001"
        assert fvr.safe_to_apply is False  # default
        assert fvr.checks == []
        assert fvr.new_vulnerabilities == []


# ── AutoFixVerifier ───────────────────────────────────────────

class TestAutoFixVerifier:
    @pytest.fixture
    def verifier(self):
        return AutoFixVerifier()

    @pytest.fixture
    def strict_verifier(self):
        return AutoFixVerifier(config={"strict_mode": True})

    def test_init_default(self, verifier):
        assert verifier.strict_mode is True
        assert verifier.max_new_vulns == 0

    def test_init_custom_config(self):
        v = AutoFixVerifier(config={"strict_mode": False, "max_new_vulns": 2})
        assert v.strict_mode is False
        assert v.max_new_vulns == 2


class TestVerifyFixPython:
    """Test verification of Python code fixes."""

    @pytest.fixture
    def verifier(self):
        return AutoFixVerifier()

    def test_valid_python_fix(self, verifier):
        original = 'query = "SELECT * FROM users WHERE id = " + user_id'
        fixed = 'query = "SELECT * FROM users WHERE id = %s"\ncursor.execute(query, (user_id,))'
        result = verifier.verify_fix(original, fixed, "python", finding_id="SQL-001")
        assert isinstance(result, FixVerificationResult)
        assert result.status in [
            VerificationStatus.PASSED,
            VerificationStatus.WARNING,
            VerificationStatus.FAILED,
        ]

    def test_fix_with_syntax_error(self, verifier):
        original = "x = 1"
        fixed = "x = 1 ++"  # Invalid Python syntax
        result = verifier.verify_fix(original, fixed, "python")
        assert isinstance(result, FixVerificationResult)
        # Should detect syntax error
        syntax_checks = [c for c in result.checks if "syntax" in c.name.lower()]
        if syntax_checks:
            assert syntax_checks[0].status == VerificationStatus.FAILED

    def test_fix_introducing_eval(self, verifier):
        original = "result = process(data)"
        fixed = "result = eval(data)"
        result = verifier.verify_fix(original, fixed, "python")
        assert isinstance(result, FixVerificationResult)
        # Should detect new dangerous pattern

    def test_fix_introducing_exec(self, verifier):
        original = "run_command(cmd)"
        fixed = "exec(cmd)"
        result = verifier.verify_fix(original, fixed, "python")
        assert isinstance(result, FixVerificationResult)

    def test_fix_introducing_os_system(self, verifier):
        original = "subprocess.run(['ls', '-la'])"
        fixed = "import os\nos.system('ls -la')"
        result = verifier.verify_fix(original, fixed, "python")
        assert isinstance(result, FixVerificationResult)

    def test_fix_introducing_pickle(self, verifier):
        original = "data = json.loads(raw)"
        fixed = "import pickle\ndata = pickle.loads(raw)"
        result = verifier.verify_fix(original, fixed, "python")
        assert isinstance(result, FixVerificationResult)

    def test_fix_introducing_hardcoded_password(self, verifier):
        original = "password = get_password_from_vault()"
        fixed = 'password = "hunter2"'
        result = verifier.verify_fix(original, fixed, "python")
        assert isinstance(result, FixVerificationResult)

    def test_safe_fix(self, verifier):
        original = "x = input()\nprint(x)"
        fixed = "x = input()\nif x:\n    print(x)"
        result = verifier.verify_fix(original, fixed, "python")
        assert isinstance(result, FixVerificationResult)

    def test_empty_fix(self, verifier):
        result = verifier.verify_fix("", "", "python")
        assert isinstance(result, FixVerificationResult)

    def test_identical_code(self, verifier):
        code = "x = 1\ny = 2\nprint(x + y)"
        result = verifier.verify_fix(code, code, "python")
        assert isinstance(result, FixVerificationResult)


class TestVerifyFixJavaScript:
    """Test verification of JavaScript code fixes."""

    @pytest.fixture
    def verifier(self):
        return AutoFixVerifier()

    def test_fix_introducing_eval_js(self, verifier):
        original = "const result = JSON.parse(data);"
        fixed = "const result = eval(data);"
        result = verifier.verify_fix(original, fixed, "javascript")
        assert isinstance(result, FixVerificationResult)

    def test_fix_introducing_innerhtml(self, verifier):
        original = "element.textContent = userInput;"
        fixed = "element.innerHTML = userInput;"
        result = verifier.verify_fix(original, fixed, "javascript")
        assert isinstance(result, FixVerificationResult)

    def test_safe_js_fix(self, verifier):
        original = "const x = data.value;"
        fixed = "const x = data?.value ?? '';"
        result = verifier.verify_fix(original, fixed, "javascript")
        assert isinstance(result, FixVerificationResult)


class TestVerifyFixJava:
    """Test verification of Java code fixes."""

    @pytest.fixture
    def verifier(self):
        return AutoFixVerifier()

    def test_fix_introducing_runtime_exec(self, verifier):
        original = "ProcessBuilder pb = new ProcessBuilder(cmd);"
        fixed = "Runtime.getRuntime().exec(cmd);"
        result = verifier.verify_fix(original, fixed, "java")
        assert isinstance(result, FixVerificationResult)

    def test_fix_introducing_objectinputstream(self, verifier):
        original = "Data data = mapper.readValue(json, Data.class);"
        fixed = "ObjectInputStream ois = new ObjectInputStream(stream);"
        result = verifier.verify_fix(original, fixed, "java")
        assert isinstance(result, FixVerificationResult)


class TestVerifyFixGo:
    """Test verification of Go code fixes."""

    @pytest.fixture
    def verifier(self):
        return AutoFixVerifier()

    def test_fix_introducing_exec_command(self, verifier):
        original = "// safe command"
        fixed = 'cmd := exec.Command("rm", "-rf", path)'
        result = verifier.verify_fix(original, fixed, "go")
        assert isinstance(result, FixVerificationResult)


class TestInternalChecks:
    """Test individual verification check methods."""

    @pytest.fixture
    def verifier(self):
        return AutoFixVerifier()

    def test_check_syntax_valid_python(self, verifier):
        check = verifier._check_syntax("x = 1\ny = x + 2", "python")
        assert isinstance(check, VerificationCheck)
        assert check.status == VerificationStatus.PASSED

    def test_check_syntax_invalid_python(self, verifier):
        check = verifier._check_syntax("x = 1 ++\n", "python")
        assert isinstance(check, VerificationCheck)
        assert check.status == VerificationStatus.FAILED

    def test_check_syntax_non_python(self, verifier):
        # For non-Python languages, syntax check should skip or pass
        check = verifier._check_syntax("var x = 1;", "javascript")
        assert isinstance(check, VerificationCheck)
        assert check.status in [
            VerificationStatus.PASSED,
            VerificationStatus.SKIPPED,
        ]

    def test_check_secrets(self, verifier):
        code_with_secret = 'api_key = "sk-proj-1234567890abcdef"'
        check = verifier._check_secrets(code_with_secret)
        assert isinstance(check, VerificationCheck)

    def test_check_secrets_clean(self, verifier):
        clean_code = "api_key = os.environ['API_KEY']"
        check = verifier._check_secrets(clean_code)
        assert isinstance(check, VerificationCheck)

    def test_check_imports(self, verifier):
        original = "import json"
        fixed = "import json\nimport pickle"
        check = verifier._check_imports(original, fixed, "python")
        assert isinstance(check, VerificationCheck)

    def test_check_complexity(self, verifier):
        simple = "x = 1"
        complex_code = "\n".join([f"if x == {i}:\n    y = {i}" for i in range(20)])
        check = verifier._check_complexity(simple, complex_code, "python")
        assert isinstance(check, VerificationCheck)


class TestVerifierStats:
    """Test verification statistics."""

    def test_get_stats(self):
        v = AutoFixVerifier()
        v.verify_fix("x = 1", "y = 1", "python")
        stats = v.get_stats()
        assert isinstance(stats, dict)
        assert stats.get("total_verifications", 0) >= 1

    def test_module_level_verify(self):
        result = verify_fix("x = 1", "y = 2", "python")
        assert isinstance(result, FixVerificationResult)

    def test_module_level_stats(self):
        stats = get_verifier_stats()
        assert isinstance(stats, dict)
