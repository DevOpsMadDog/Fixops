"""Rigorous tests for secrets detection functionality.

These tests verify secret pattern detection, file scanning, and result
building with realistic scenarios and proper assertions.
"""

from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from risk.secrets_detection import (
    SecretFinding,
    SecretsDetectionResult,
    SecretsDetector,
    SecretType,
)


class TestSecretType:
    """Tests for SecretType enum."""

    def test_secret_type_values(self):
        """Verify SecretType enum has expected values."""
        assert SecretType.API_KEY.value == "api_key"
        assert SecretType.PASSWORD.value == "password"
        assert SecretType.ACCESS_TOKEN.value == "access_token"
        assert SecretType.PRIVATE_KEY.value == "private_key"
        assert SecretType.DATABASE_CREDENTIAL.value == "database_credential"
        assert SecretType.AWS_CREDENTIAL.value == "aws_credential"
        assert SecretType.GCP_CREDENTIAL.value == "gcp_credential"
        assert SecretType.AZURE_CREDENTIAL.value == "azure_credential"
        assert SecretType.GITHUB_TOKEN.value == "github_token"
        assert SecretType.SLACK_TOKEN.value == "slack_token"

    def test_secret_type_count(self):
        """Verify all expected secret types exist."""
        assert len(SecretType) == 10


class TestSecretFinding:
    """Tests for SecretFinding dataclass."""

    def test_finding_defaults(self):
        """Verify SecretFinding has correct default values."""
        finding = SecretFinding(
            secret_type=SecretType.API_KEY,
            severity="high",
            file_path="/path/to/file.py",
            line_number=42,
            matched_pattern="api_key=abc123",
        )
        assert finding.secret_type == SecretType.API_KEY
        assert finding.severity == "high"
        assert finding.file_path == "/path/to/file.py"
        assert finding.line_number == 42
        assert finding.matched_pattern == "api_key=abc123"
        assert finding.context == ""
        assert finding.recommendation == ""
        assert isinstance(finding.timestamp, datetime)

    def test_finding_with_all_fields(self):
        """Verify SecretFinding stores all fields correctly."""
        finding = SecretFinding(
            secret_type=SecretType.PASSWORD,
            severity="critical",
            file_path="/app/config.py",
            line_number=15,
            matched_pattern="password='secret123'",
            context="# Config file\npassword='secret123'\n# End",
            recommendation="Use environment variables",
        )
        assert finding.context == "# Config file\npassword='secret123'\n# End"
        assert finding.recommendation == "Use environment variables"


class TestSecretsDetectionResult:
    """Tests for SecretsDetectionResult dataclass."""

    def test_result_structure(self):
        """Verify SecretsDetectionResult has correct structure."""
        finding = SecretFinding(
            secret_type=SecretType.API_KEY,
            severity="high",
            file_path="/test.py",
            line_number=1,
            matched_pattern="api_key=test",
        )
        result = SecretsDetectionResult(
            findings=[finding],
            total_findings=1,
            findings_by_type={"api_key": 1},
            files_scanned=5,
        )
        assert len(result.findings) == 1
        assert result.total_findings == 1
        assert result.findings_by_type["api_key"] == 1
        assert result.files_scanned == 5
        assert isinstance(result.timestamp, datetime)


class TestSecretsDetectorInit:
    """Tests for SecretsDetector initialization."""

    def test_default_initialization(self):
        """Verify default initialization."""
        detector = SecretsDetector()
        assert detector.config == {}
        assert len(detector.patterns) > 0
        assert ".git" in detector.exclude_paths
        assert "node_modules" in detector.exclude_paths

    def test_custom_config(self):
        """Verify custom config is applied."""
        config = {"exclude_paths": [".git", "vendor"]}
        detector = SecretsDetector(config=config)
        assert detector.exclude_paths == [".git", "vendor"]


class TestBuildSecretPatterns:
    """Tests for _build_secret_patterns method."""

    def test_patterns_include_api_key(self):
        """Verify API key patterns are included."""
        detector = SecretsDetector()
        assert SecretType.API_KEY in detector.patterns
        assert len(detector.patterns[SecretType.API_KEY]) >= 1

    def test_patterns_include_password(self):
        """Verify password patterns are included."""
        detector = SecretsDetector()
        assert SecretType.PASSWORD in detector.patterns

    def test_patterns_include_aws_credential(self):
        """Verify AWS credential patterns are included."""
        detector = SecretsDetector()
        assert SecretType.AWS_CREDENTIAL in detector.patterns
        assert len(detector.patterns[SecretType.AWS_CREDENTIAL]) >= 2

    def test_patterns_include_private_key(self):
        """Verify private key patterns are included."""
        detector = SecretsDetector()
        assert SecretType.PRIVATE_KEY in detector.patterns

    def test_patterns_include_github_token(self):
        """Verify GitHub token patterns are included."""
        detector = SecretsDetector()
        assert SecretType.GITHUB_TOKEN in detector.patterns


class TestScanFile:
    """Tests for _scan_file method."""

    def test_scan_file_with_api_key(self):
        """Verify API key is detected in file."""
        detector = SecretsDetector()

        with TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "config.py"
            file_path.write_text('api_key = "abcdefghijklmnopqrstuvwxyz123456"')

            findings = detector._scan_file(file_path)

            assert len(findings) >= 1
            assert any(f.secret_type == SecretType.API_KEY for f in findings)

    def test_scan_file_with_password(self):
        """Verify password is detected in file."""
        detector = SecretsDetector()

        with TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "config.py"
            file_path.write_text('password = "supersecretpassword123"')

            findings = detector._scan_file(file_path)

            assert len(findings) >= 1
            assert any(f.secret_type == SecretType.PASSWORD for f in findings)

    def test_scan_file_with_private_key(self):
        """Verify private key is detected in file."""
        detector = SecretsDetector()

        with TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "key.pem"
            file_path.write_text(
                "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
            )

            # Note: .pem is not in default extensions, use .py
            file_path = Path(tmpdir) / "config.py"
            file_path.write_text(
                "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"
            )

            findings = detector._scan_file(file_path)

            assert len(findings) >= 1
            assert any(f.secret_type == SecretType.PRIVATE_KEY for f in findings)

    def test_scan_file_with_aws_credentials(self):
        """Verify AWS credentials are detected in file."""
        detector = SecretsDetector()

        with TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "config.py"
            content = """
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
"""
            file_path.write_text(content)

            findings = detector._scan_file(file_path)

            assert len(findings) >= 1
            assert any(f.secret_type == SecretType.AWS_CREDENTIAL for f in findings)

    def test_scan_file_with_github_token(self):
        """Verify GitHub token is detected in file."""
        detector = SecretsDetector()

        with TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "config.py"
            file_path.write_text(
                'github_token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"'
            )

            findings = detector._scan_file(file_path)

            assert len(findings) >= 1
            assert any(f.secret_type == SecretType.GITHUB_TOKEN for f in findings)

    def test_scan_file_no_secrets(self):
        """Verify clean file returns no findings."""
        detector = SecretsDetector()

        with TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "clean.py"
            file_path.write_text('print("Hello, World!")\nx = 42')

            findings = detector._scan_file(file_path)

            assert len(findings) == 0

    def test_scan_file_context_extraction(self):
        """Verify context is extracted around finding."""
        detector = SecretsDetector()

        with TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "config.py"
            content = """# Line 1
# Line 2
# Line 3
api_key = "abcdefghijklmnopqrstuvwxyz123456"
# Line 5
# Line 6
"""
            file_path.write_text(content)

            findings = detector._scan_file(file_path)

            assert len(findings) >= 1
            # Context should include surrounding lines
            assert findings[0].context != ""


class TestScan:
    """Tests for scan method."""

    def test_scan_directory(self):
        """Verify directory scanning works."""
        detector = SecretsDetector()

        with TemporaryDirectory() as tmpdir:
            # Create files with secrets
            config_file = Path(tmpdir) / "config.py"
            config_file.write_text('api_key = "abcdefghijklmnopqrstuvwxyz123456"')

            clean_file = Path(tmpdir) / "clean.py"
            clean_file.write_text('print("Hello")')

            result = detector.scan(Path(tmpdir))

            assert result.files_scanned == 2
            assert result.total_findings >= 1

    def test_scan_excludes_paths(self):
        """Verify excluded paths are skipped."""
        detector = SecretsDetector()

        with TemporaryDirectory() as tmpdir:
            # Create file in excluded directory
            node_modules = Path(tmpdir) / "node_modules"
            node_modules.mkdir()
            excluded_file = node_modules / "config.py"
            excluded_file.write_text('api_key = "abcdefghijklmnopqrstuvwxyz123456"')

            # Create file in included directory
            src = Path(tmpdir) / "src"
            src.mkdir()
            included_file = src / "config.py"
            included_file.write_text('print("clean")')

            result = detector.scan(Path(tmpdir))

            # node_modules should be excluded
            assert result.files_scanned == 1

    def test_scan_multiple_file_types(self):
        """Verify multiple file types are scanned."""
        detector = SecretsDetector()

        with TemporaryDirectory() as tmpdir:
            # Create different file types
            py_file = Path(tmpdir) / "config.py"
            py_file.write_text('api_key = "abcdefghijklmnopqrstuvwxyz123456"')

            js_file = Path(tmpdir) / "config.js"
            js_file.write_text('const api_key = "abcdefghijklmnopqrstuvwxyz123456"')

            yaml_file = Path(tmpdir) / "config.yaml"
            yaml_file.write_text('api_key: "abcdefghijklmnopqrstuvwxyz123456"')

            result = detector.scan(Path(tmpdir))

            assert result.files_scanned == 3

    def test_scan_empty_directory(self):
        """Verify empty directory returns empty result."""
        detector = SecretsDetector()

        with TemporaryDirectory() as tmpdir:
            result = detector.scan(Path(tmpdir))

            assert result.files_scanned == 0
            assert result.total_findings == 0


class TestGetRecommendation:
    """Tests for _get_recommendation method."""

    def test_recommendation_api_key(self):
        """Verify API key recommendation."""
        detector = SecretsDetector()
        rec = detector._get_recommendation(SecretType.API_KEY)
        assert (
            "environment variables" in rec.lower()
            or "secrets management" in rec.lower()
        )

    def test_recommendation_password(self):
        """Verify password recommendation."""
        detector = SecretsDetector()
        rec = detector._get_recommendation(SecretType.PASSWORD)
        assert "secrets management" in rec.lower()

    def test_recommendation_aws_credential(self):
        """Verify AWS credential recommendation."""
        detector = SecretsDetector()
        rec = detector._get_recommendation(SecretType.AWS_CREDENTIAL)
        assert "iam" in rec.lower() or "secrets manager" in rec.lower()

    def test_recommendation_private_key(self):
        """Verify private key recommendation."""
        detector = SecretsDetector()
        rec = detector._get_recommendation(SecretType.PRIVATE_KEY)
        assert "key management" in rec.lower()

    def test_recommendation_unknown_type(self):
        """Verify unknown type returns default recommendation."""
        detector = SecretsDetector()
        rec = detector._get_recommendation(SecretType.DATABASE_CREDENTIAL)
        assert "secure storage" in rec.lower() or "remove" in rec.lower()


class TestBuildResult:
    """Tests for _build_result method."""

    def test_build_result_empty(self):
        """Verify empty result is built correctly."""
        detector = SecretsDetector()
        result = detector._build_result([], 0)

        assert result.findings == []
        assert result.total_findings == 0
        assert result.findings_by_type == {}
        assert result.files_scanned == 0

    def test_build_result_with_findings(self):
        """Verify result with findings is built correctly."""
        detector = SecretsDetector()

        findings = [
            SecretFinding(
                secret_type=SecretType.API_KEY,
                severity="high",
                file_path="/test1.py",
                line_number=1,
                matched_pattern="api_key=test",
            ),
            SecretFinding(
                secret_type=SecretType.API_KEY,
                severity="high",
                file_path="/test2.py",
                line_number=5,
                matched_pattern="api_key=test2",
            ),
            SecretFinding(
                secret_type=SecretType.PASSWORD,
                severity="critical",
                file_path="/test3.py",
                line_number=10,
                matched_pattern="password=secret",
            ),
        ]

        result = detector._build_result(findings, 10)

        assert result.total_findings == 3
        assert result.findings_by_type["api_key"] == 2
        assert result.findings_by_type["password"] == 1
        assert result.files_scanned == 10
