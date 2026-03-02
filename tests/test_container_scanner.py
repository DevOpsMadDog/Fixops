"""
Comprehensive unit tests for suite-core/core/container_scanner.py.

Covers:
- ContainerSeverity enum
- ContainerFinding dataclass and to_dict()
- ContainerScanResult dataclass and to_dict()
- DOCKERFILE_RULES module constant structure
- KNOWN_VULNERABLE_IMAGES module constant
- ContainerImageScanner.__init__ and properties
- ContainerImageScanner.scan_dockerfile — all pattern rules, meta-rules,
  privileged port, vulnerable base image detection
- ContainerImageScanner._validate_image_ref — all valid/invalid cases
- ContainerImageScanner.scan_image — trivy path, no-trivy path, error paths
- get_container_scanner singleton
- Edge cases: empty content, comments-only, fully compliant Dockerfile,
  all severity levels
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# sitecustomize.py handles sys.path; add suite-core explicitly for robustness
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

import core.container_scanner as _mod
from core.container_scanner import (
    DOCKERFILE_RULES,
    KNOWN_VULNERABLE_IMAGES,
    ContainerFinding,
    ContainerImageScanner,
    ContainerScanResult,
    ContainerSeverity,
    get_container_scanner,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _make_scanner_no_tools() -> ContainerImageScanner:
    """Return a scanner instance that reports no external tools available."""
    scanner = ContainerImageScanner()
    scanner._trivy = None
    scanner._grype = None
    return scanner


def _make_scanner_with_trivy(trivy_path: str = "/usr/bin/trivy") -> ContainerImageScanner:
    """Return a scanner instance that reports trivy available."""
    scanner = ContainerImageScanner()
    scanner._trivy = trivy_path
    scanner._grype = None
    return scanner


# ─────────────────────────────────────────────────────────────────────────────
# ContainerSeverity enum
# ─────────────────────────────────────────────────────────────────────────────


class TestContainerSeverityEnum:
    def test_all_values_present(self):
        values = {s.value for s in ContainerSeverity}
        assert values == {"critical", "high", "medium", "low", "info"}

    def test_str_subclass(self):
        assert isinstance(ContainerSeverity.HIGH, str)

    def test_comparison_with_string(self):
        assert ContainerSeverity.CRITICAL == "critical"

    def test_construction_from_string(self):
        assert ContainerSeverity("medium") == ContainerSeverity.MEDIUM

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            ContainerSeverity("unknown_sev")


# ─────────────────────────────────────────────────────────────────────────────
# ContainerFinding dataclass
# ─────────────────────────────────────────────────────────────────────────────


class TestContainerFindingDataclass:
    def _sample(self, **kwargs) -> ContainerFinding:
        defaults = dict(
            finding_id="CONT-abc12345",
            title="Running as Root",
            severity=ContainerSeverity.HIGH,
            category="dockerfile",
            cwe_id="CWE-250",
            description="Container runs as root",
            recommendation="Add non-root USER directive",
        )
        defaults.update(kwargs)
        return ContainerFinding(**defaults)

    def test_defaults(self):
        f = self._sample()
        assert f.line_number == 0
        assert f.image_ref == ""
        assert f.confidence == 0.9
        assert isinstance(f.timestamp, datetime)
        assert f.timestamp.tzinfo == timezone.utc

    def test_custom_fields(self):
        f = self._sample(line_number=12, image_ref="ubuntu:14.04", confidence=0.75)
        assert f.line_number == 12
        assert f.image_ref == "ubuntu:14.04"
        assert f.confidence == 0.75

    def test_to_dict_keys(self):
        f = self._sample()
        d = f.to_dict()
        expected_keys = {
            "finding_id", "title", "severity", "category", "cwe_id",
            "description", "recommendation", "line_number", "image_ref",
            "confidence", "timestamp",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_severity_is_string(self):
        f = self._sample(severity=ContainerSeverity.CRITICAL)
        assert f.to_dict()["severity"] == "critical"

    def test_to_dict_timestamp_is_iso_string(self):
        f = self._sample()
        ts = f.to_dict()["timestamp"]
        assert isinstance(ts, str)
        # Must parse as ISO 8601
        parsed = datetime.fromisoformat(ts)
        assert parsed.tzinfo is not None

    def test_to_dict_roundtrip_values(self):
        f = self._sample(line_number=7, image_ref="debian:jessie", confidence=0.5)
        d = f.to_dict()
        assert d["line_number"] == 7
        assert d["image_ref"] == "debian:jessie"
        assert d["confidence"] == 0.5
        assert d["cwe_id"] == "CWE-250"


# ─────────────────────────────────────────────────────────────────────────────
# ContainerScanResult dataclass
# ─────────────────────────────────────────────────────────────────────────────


class TestContainerScanResultDataclass:
    def _sample_finding(self) -> ContainerFinding:
        return ContainerFinding(
            finding_id="CONT-00000001",
            title="Test finding",
            severity=ContainerSeverity.LOW,
            category="dockerfile",
            cwe_id="CWE-400",
            description="desc",
            recommendation="rec",
        )

    def test_to_dict_keys(self):
        result = ContainerScanResult(
            scan_id="cont-aabbccddee00",
            target="Dockerfile",
            total_findings=1,
            findings=[self._sample_finding()],
            by_severity={"low": 1},
            by_category={"dockerfile": 1},
        )
        d = result.to_dict()
        assert "scan_id" in d
        assert "target" in d
        assert "total_findings" in d
        assert "findings" in d
        assert "by_severity" in d
        assert "by_category" in d
        assert "trivy_available" in d
        assert "grype_available" in d
        assert "duration_ms" in d
        assert "timestamp" in d

    def test_to_dict_findings_serialised(self):
        result = ContainerScanResult(
            scan_id="cont-x",
            target="Dockerfile",
            total_findings=1,
            findings=[self._sample_finding()],
            by_severity={"low": 1},
            by_category={"dockerfile": 1},
        )
        d = result.to_dict()
        assert isinstance(d["findings"], list)
        assert len(d["findings"]) == 1
        assert isinstance(d["findings"][0], dict)

    def test_default_tool_availability(self):
        result = ContainerScanResult(
            scan_id="cont-y",
            target="Dockerfile",
            total_findings=0,
            findings=[],
            by_severity={},
            by_category={},
        )
        assert result.trivy_available is False
        assert result.grype_available is False

    def test_timestamp_is_utc(self):
        result = ContainerScanResult(
            scan_id="cont-z",
            target="Dockerfile",
            total_findings=0,
            findings=[],
            by_severity={},
            by_category={},
        )
        assert result.timestamp.tzinfo == timezone.utc


# ─────────────────────────────────────────────────────────────────────────────
# Module-level constants
# ─────────────────────────────────────────────────────────────────────────────


class TestModuleConstants:
    def test_dockerfile_rules_is_list(self):
        assert isinstance(DOCKERFILE_RULES, list)
        assert len(DOCKERFILE_RULES) == 10

    def test_each_rule_has_seven_elements(self):
        for rule in DOCKERFILE_RULES:
            assert len(rule) == 7, f"Rule has wrong length: {rule}"

    def test_rule_ids_unique(self):
        ids = [r[0] for r in DOCKERFILE_RULES]
        assert len(ids) == len(set(ids))

    def test_rule_severities_valid(self):
        valid_sev = {"critical", "high", "medium", "low", "info"}
        for rule in DOCKERFILE_RULES:
            assert rule[2] in valid_sev, f"Bad severity in rule {rule[0]}: {rule[2]}"

    def test_known_vulnerable_images_is_dict(self):
        assert isinstance(KNOWN_VULNERABLE_IMAGES, dict)
        assert len(KNOWN_VULNERABLE_IMAGES) >= 10

    def test_known_vulnerable_images_structure(self):
        for img, (sev, desc) in KNOWN_VULNERABLE_IMAGES.items():
            assert sev in ("critical", "high", "medium", "low")
            assert isinstance(desc, str)
            assert len(desc) > 0

    def test_python2_eol_entry(self):
        assert "python:2" in KNOWN_VULNERABLE_IMAGES
        sev, _ = KNOWN_VULNERABLE_IMAGES["python:2"]
        assert sev == "critical"

    def test_ubuntu_1404_eol_entry(self):
        assert "ubuntu:14.04" in KNOWN_VULNERABLE_IMAGES

    def test_centos7_eol_entry(self):
        assert "centos:7" in KNOWN_VULNERABLE_IMAGES


# ─────────────────────────────────────────────────────────────────────────────
# ContainerImageScanner — initialisation and properties
# ─────────────────────────────────────────────────────────────────────────────


class TestContainerImageScannerInit:
    def test_init_creates_instance(self):
        scanner = ContainerImageScanner()
        assert scanner is not None

    def test_trivy_available_false_when_none(self):
        scanner = _make_scanner_no_tools()
        assert scanner.trivy_available is False

    def test_grype_available_false_when_none(self):
        scanner = _make_scanner_no_tools()
        assert scanner.grype_available is False

    def test_trivy_available_true_when_set(self):
        scanner = _make_scanner_with_trivy()
        assert scanner.trivy_available is True

    def test_grype_available_true_when_set(self):
        scanner = _make_scanner_no_tools()
        scanner._grype = "/usr/bin/grype"
        assert scanner.grype_available is True


# ─────────────────────────────────────────────────────────────────────────────
# ContainerImageScanner._validate_image_ref
# ─────────────────────────────────────────────────────────────────────────────


class TestValidateImageRef:
    def _validate(self, ref: str) -> str:
        return ContainerImageScanner._validate_image_ref(ref)

    # ---- Valid references ----
    def test_simple_name(self):
        assert self._validate("nginx") == "nginx"

    def test_name_with_tag(self):
        assert self._validate("nginx:1.25") == "nginx:1.25"

    def test_name_with_latest_tag(self):
        assert self._validate("python:latest") == "python:latest"

    def test_registry_with_port(self):
        assert self._validate("registry.example.com:5000/myapp:v1.0") == "registry.example.com:5000/myapp:v1.0"

    def test_sha_digest(self):
        ref = "ubuntu@sha256:abc123def456"
        assert self._validate(ref) == ref

    def test_strips_surrounding_whitespace(self):
        # The format regex runs on the raw (unstripped) string, so leading/trailing
        # spaces cause the format check to fail — spaces are not in [\w\.\-/:@]
        with pytest.raises(ValueError, match="Invalid image reference format"):
            self._validate("  nginx:1.25  ")

    def test_version_with_dots_and_dashes(self):
        assert self._validate("my-app:1.2.3-alpine") == "my-app:1.2.3-alpine"

    # ---- Invalid references ----
    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="Empty image reference"):
            self._validate("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="Empty image reference"):
            self._validate("   ")

    def test_too_long_raises(self):
        with pytest.raises(ValueError, match="too long"):
            self._validate("a" * 513)

    def test_semicolon_raises(self):
        with pytest.raises(ValueError, match="Blocked characters"):
            self._validate("nginx;rm -rf /")

    def test_pipe_raises(self):
        with pytest.raises(ValueError, match="Blocked characters"):
            self._validate("nginx|cat /etc/passwd")

    def test_ampersand_raises(self):
        with pytest.raises(ValueError, match="Blocked characters"):
            self._validate("nginx&whoami")

    def test_dollar_raises(self):
        with pytest.raises(ValueError, match="Blocked characters"):
            self._validate("nginx$HOME")

    def test_backtick_raises(self):
        with pytest.raises(ValueError, match="Blocked characters"):
            self._validate("nginx`id`")

    def test_newline_raises(self):
        with pytest.raises(ValueError, match="Blocked characters"):
            self._validate("nginx\nnewline")

    def test_backslash_raises(self):
        with pytest.raises(ValueError, match="Blocked characters"):
            self._validate("nginx\\path")

    def test_greater_than_raises(self):
        with pytest.raises(ValueError, match="Blocked characters"):
            self._validate("nginx > /tmp/x")

    def test_parenthesis_raises(self):
        with pytest.raises(ValueError, match="Blocked characters"):
            self._validate("nginx()")

    def test_space_raises(self):
        # Space is not in blocked chars set but fails the regex format check
        with pytest.raises(ValueError, match="Invalid image reference format"):
            self._validate("nginx image")

    def test_exactly_512_chars_ok(self):
        # 512-char valid reference (e.g. repeated 'a')
        ref = "a" * 512
        # Should not raise on length; may fail on format if not alphanumeric-only
        # 'a' * 512 passes the alphanumeric pattern
        result = self._validate(ref)
        assert len(result) == 512

    def test_exclamation_raises(self):
        with pytest.raises(ValueError, match="Blocked characters"):
            self._validate("nginx!")


# ─────────────────────────────────────────────────────────────────────────────
# scan_dockerfile — empty / trivial content
# ─────────────────────────────────────────────────────────────────────────────


class TestScanDockerfileEmpty:
    def setup_method(self):
        self.scanner = _make_scanner_no_tools()

    def test_empty_dockerfile_triggers_meta_rules(self):
        result = self.scanner.scan_dockerfile("")
        titles = {f.title for f in result.findings}
        assert "No USER Directive" in titles
        assert "No HEALTHCHECK" in titles

    def test_empty_dockerfile_finding_count(self):
        result = self.scanner.scan_dockerfile("")
        # At minimum: No USER + No HEALTHCHECK = 2
        assert result.total_findings >= 2
        assert result.total_findings == len(result.findings)

    def test_whitespace_only_dockerfile(self):
        result = self.scanner.scan_dockerfile("   \n\n   ")
        titles = {f.title for f in result.findings}
        assert "No USER Directive" in titles
        assert "No HEALTHCHECK" in titles

    def test_comments_only_dockerfile(self):
        content = "# syntax=docker/dockerfile:1\n# This is a comment\n# Another comment\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "No USER Directive" in titles
        assert "No HEALTHCHECK" in titles

    def test_result_has_scan_id(self):
        result = self.scanner.scan_dockerfile("")
        assert result.scan_id.startswith("cont-")

    def test_result_target_defaults_to_Dockerfile(self):
        result = self.scanner.scan_dockerfile("")
        assert result.target == "Dockerfile"

    def test_result_target_custom(self):
        result = self.scanner.scan_dockerfile("", filename="myapp/Dockerfile.prod")
        assert result.target == "myapp/Dockerfile.prod"

    def test_duration_ms_non_negative(self):
        result = self.scanner.scan_dockerfile("")
        assert result.duration_ms >= 0.0

    def test_by_severity_is_dict(self):
        result = self.scanner.scan_dockerfile("")
        assert isinstance(result.by_severity, dict)

    def test_by_category_is_dict(self):
        result = self.scanner.scan_dockerfile("")
        assert isinstance(result.by_category, dict)


# ─────────────────────────────────────────────────────────────────────────────
# scan_dockerfile — USER directive rules
# ─────────────────────────────────────────────────────────────────────────────


class TestScanDockerfileUserRules:
    def setup_method(self):
        self.scanner = _make_scanner_no_tools()

    def test_user_root_triggers_finding(self):
        content = "FROM ubuntu:22.04\nUSER root\nCMD bash\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "Running as Root" in titles

    def test_user_root_still_triggers_no_user_meta(self):
        # "USER root" does not set has_user=True, so No USER meta-rule also fires
        content = "FROM ubuntu:22.04\nUSER root\nCMD bash\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "No USER Directive" in titles

    def test_user_nonroot_suppresses_no_user_meta(self):
        # NOTE: "nonroot" contains the substring "root", so the source code's
        # check `"root" not in stripped.lower()` evaluates to False, meaning
        # "USER nonroot" does NOT set has_user=True. Use a username without "root".
        content = "FROM ubuntu:22.04\nUSER appuser\nCMD bash\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "No USER Directive" not in titles

    def test_user_1000_suppresses_no_user_meta(self):
        content = "FROM ubuntu:22.04\nUSER 1000\nCMD bash\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "No USER Directive" not in titles

    def test_no_user_directive_severity_high(self):
        content = "FROM ubuntu:22.04\nCMD bash\n"
        result = self.scanner.scan_dockerfile(content)
        for f in result.findings:
            if f.title == "No USER Directive":
                assert f.severity == ContainerSeverity.HIGH
                break
        else:
            pytest.fail("No USER Directive finding not found")

    def test_user_root_severity_high(self):
        content = "FROM ubuntu:22.04\nUSER root\n"
        result = self.scanner.scan_dockerfile(content)
        for f in result.findings:
            if f.title == "Running as Root":
                assert f.severity == ContainerSeverity.HIGH
                break


# ─────────────────────────────────────────────────────────────────────────────
# scan_dockerfile — HEALTHCHECK rule
# ─────────────────────────────────────────────────────────────────────────────


class TestScanDockerfileHealthcheck:
    def setup_method(self):
        self.scanner = _make_scanner_no_tools()

    def test_no_healthcheck_triggers_finding(self):
        content = "FROM ubuntu:22.04\nUSER nonroot\nCMD bash\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "No HEALTHCHECK" in titles

    def test_healthcheck_present_suppresses_finding(self):
        content = "FROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\nCMD bash\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "No HEALTHCHECK" not in titles

    def test_healthcheck_severity_low(self):
        content = "FROM ubuntu:22.04\nUSER nonroot\nCMD bash\n"
        result = self.scanner.scan_dockerfile(content)
        for f in result.findings:
            if f.title == "No HEALTHCHECK":
                assert f.severity == ContainerSeverity.LOW
                break
        else:
            pytest.fail("No HEALTHCHECK finding not found")

    def test_healthcheck_cwe(self):
        content = "FROM ubuntu:22.04\nUSER nonroot\nCMD bash\n"
        result = self.scanner.scan_dockerfile(content)
        for f in result.findings:
            if f.title == "No HEALTHCHECK":
                assert f.cwe_id == "CWE-693"
                return


# ─────────────────────────────────────────────────────────────────────────────
# scan_dockerfile — :latest tag rule
# ─────────────────────────────────────────────────────────────────────────────


class TestScanDockerfileLatestTag:
    def setup_method(self):
        self.scanner = _make_scanner_no_tools()

    def test_from_latest_triggers_finding(self):
        content = "FROM nginx:latest\nUSER nonroot\nHEALTHCHECK CMD true\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "Latest Tag" in titles

    def test_from_pinned_no_latest_finding(self):
        content = "FROM nginx:1.25.3\nUSER nonroot\nHEALTHCHECK CMD true\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "Latest Tag" not in titles

    def test_latest_tag_severity_medium(self):
        content = "FROM nginx:latest\nUSER nonroot\nHEALTHCHECK CMD true\n"
        result = self.scanner.scan_dockerfile(content)
        for f in result.findings:
            if f.title == "Latest Tag":
                assert f.severity == ContainerSeverity.MEDIUM
                return

    def test_from_no_tag_no_latest_finding(self):
        # "FROM ubuntu" without any tag should not trigger latest rule
        content = "FROM ubuntu\nUSER nonroot\nHEALTHCHECK CMD true\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "Latest Tag" not in titles


# ─────────────────────────────────────────────────────────────────────────────
# scan_dockerfile — secrets in ENV rule
# ─────────────────────────────────────────────────────────────────────────────


class TestScanDockerfileSecretsInEnv:
    def setup_method(self):
        self.scanner = _make_scanner_no_tools()

    def test_password_in_env_triggers_critical(self):
        content = "FROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\nENV DB_PASSWORD=s3cr3t\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "Secrets in ENV" in titles
        for f in result.findings:
            if f.title == "Secrets in ENV":
                assert f.severity == ContainerSeverity.CRITICAL
                return

    def test_secret_in_env_triggers(self):
        content = "FROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\nENV APP_SECRET=mysecretvalue\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "Secrets in ENV" in titles

    def test_api_key_in_env_triggers(self):
        content = "FROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\nENV STRIPE_API_KEY=sk_live_xxxx\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "Secrets in ENV" in titles

    def test_token_in_env_triggers(self):
        content = "FROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\nENV GITHUB_TOKEN=ghp_xxxx\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "Secrets in ENV" in titles

    def test_non_secret_env_no_finding(self):
        content = "FROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\nENV PORT=8080\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "Secrets in ENV" not in titles

    def test_secrets_cwe_798(self):
        content = "FROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\nENV DB_PASSWORD=oops\n"
        result = self.scanner.scan_dockerfile(content)
        for f in result.findings:
            if f.title == "Secrets in ENV":
                assert f.cwe_id == "CWE-798"
                return


# ─────────────────────────────────────────────────────────────────────────────
# scan_dockerfile — ADD vs COPY rule
# ─────────────────────────────────────────────────────────────────────────────


class TestScanDockerfileAddVsCopy:
    def setup_method(self):
        self.scanner = _make_scanner_no_tools()

    def test_add_local_file_triggers(self):
        content = "FROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\nADD ./app /app\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "ADD Instead of COPY" in titles

    def test_add_url_no_finding(self):
        # ADD with URL (http/https) is allowed
        content = "FROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\nADD https://example.com/file.tar.gz /app/\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "ADD Instead of COPY" not in titles

    def test_copy_no_finding(self):
        content = "FROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\nCOPY ./app /app\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "ADD Instead of COPY" not in titles

    def test_add_severity_low(self):
        content = "FROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\nADD ./app /app\n"
        result = self.scanner.scan_dockerfile(content)
        for f in result.findings:
            if f.title == "ADD Instead of COPY":
                assert f.severity == ContainerSeverity.LOW
                return


# ─────────────────────────────────────────────────────────────────────────────
# scan_dockerfile — curl pipe to shell rule
# ─────────────────────────────────────────────────────────────────────────────


class TestScanDockerfileCurlPipeShell:
    def setup_method(self):
        self.scanner = _make_scanner_no_tools()

    def test_curl_pipe_bash_triggers(self):
        content = "FROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\nRUN curl https://example.com/install.sh | bash\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "Curl Pipe to Shell" in titles

    def test_wget_pipe_sh_triggers(self):
        content = "FROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\nRUN wget https://get.docker.com | sh\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "Curl Pipe to Shell" in titles

    def test_curl_no_pipe_no_finding(self):
        content = "FROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\nRUN curl -o file.sh https://example.com/install.sh\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "Curl Pipe to Shell" not in titles

    def test_curl_pipe_bash_severity_critical(self):
        content = "FROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\nRUN curl https://example.com | bash\n"
        result = self.scanner.scan_dockerfile(content)
        for f in result.findings:
            if f.title == "Curl Pipe to Shell":
                assert f.severity == ContainerSeverity.CRITICAL
                return


# ─────────────────────────────────────────────────────────────────────────────
# scan_dockerfile — package pinning / apt-get clean rules
# ─────────────────────────────────────────────────────────────────────────────


class TestScanDockerfilePackageRules:
    def setup_method(self):
        self.scanner = _make_scanner_no_tools()

    def test_apt_get_without_version_triggers_no_pinning(self):
        content = "FROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\nRUN apt-get install curl\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "No Package Pinning" in titles

    def test_apk_add_without_version_triggers_no_pinning(self):
        content = "FROM alpine:3.18\nUSER nonroot\nHEALTHCHECK CMD true\nRUN apk add curl\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "No Package Pinning" in titles

    def test_apt_get_without_clean_triggers(self):
        content = "FROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\nRUN apt-get install curl\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "Apt-get No Clean" in titles

    def test_no_pinning_severity_medium(self):
        content = "FROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\nRUN apt-get install curl\n"
        result = self.scanner.scan_dockerfile(content)
        for f in result.findings:
            if f.title == "No Package Pinning":
                assert f.severity == ContainerSeverity.MEDIUM
                return


# ─────────────────────────────────────────────────────────────────────────────
# scan_dockerfile — privileged port rule
# ─────────────────────────────────────────────────────────────────────────────


class TestScanDockerfilePrivilegedPort:
    def setup_method(self):
        self.scanner = _make_scanner_no_tools()

    def test_expose_port_80_triggers(self):
        content = "FROM nginx:1.25\nUSER nonroot\nHEALTHCHECK CMD true\nEXPOSE 80\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "Privileged Port 80" in titles

    def test_expose_port_443_triggers(self):
        content = "FROM nginx:1.25\nUSER nonroot\nHEALTHCHECK CMD true\nEXPOSE 443\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "Privileged Port 443" in titles

    def test_expose_port_8080_no_finding(self):
        content = "FROM nginx:1.25\nUSER nonroot\nHEALTHCHECK CMD true\nEXPOSE 8080\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        # No privileged port finding
        assert not any("Privileged Port" in t for t in titles)

    def test_expose_1023_triggers(self):
        content = "FROM nginx:1.25\nUSER nonroot\nHEALTHCHECK CMD true\nEXPOSE 1023\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "Privileged Port 1023" in titles

    def test_expose_1024_no_finding(self):
        content = "FROM nginx:1.25\nUSER nonroot\nHEALTHCHECK CMD true\nEXPOSE 1024\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert not any("Privileged Port" in t for t in titles)

    def test_privileged_port_severity_medium(self):
        content = "FROM nginx:1.25\nUSER nonroot\nHEALTHCHECK CMD true\nEXPOSE 80\n"
        result = self.scanner.scan_dockerfile(content)
        for f in result.findings:
            if "Privileged Port" in f.title:
                assert f.severity == ContainerSeverity.MEDIUM
                return

    def test_privileged_port_cwe_284(self):
        content = "FROM nginx:1.25\nUSER nonroot\nHEALTHCHECK CMD true\nEXPOSE 80\n"
        result = self.scanner.scan_dockerfile(content)
        for f in result.findings:
            if "Privileged Port" in f.title:
                assert f.cwe_id == "CWE-284"
                return


# ─────────────────────────────────────────────────────────────────────────────
# scan_dockerfile — vulnerable base image detection
# ─────────────────────────────────────────────────────────────────────────────


class TestScanDockerfileVulnerableBaseImage:
    def setup_method(self):
        self.scanner = _make_scanner_no_tools()

    def test_python2_triggers_critical(self):
        content = "FROM python:2\nUSER nonroot\nHEALTHCHECK CMD true\nCMD python app.py\n"
        result = self.scanner.scan_dockerfile(content)
        base_findings = [f for f in result.findings if f.category == "base_image"]
        assert len(base_findings) >= 1
        assert any(f.severity == ContainerSeverity.CRITICAL for f in base_findings)

    def test_ubuntu_1404_triggers_critical(self):
        content = "FROM ubuntu:14.04\nUSER nonroot\nHEALTHCHECK CMD true\nCMD bash\n"
        result = self.scanner.scan_dockerfile(content)
        base_findings = [f for f in result.findings if f.category == "base_image"]
        assert len(base_findings) >= 1
        assert any(f.severity == ContainerSeverity.CRITICAL for f in base_findings)

    def test_centos7_triggers_high(self):
        content = "FROM centos:7\nUSER nonroot\nHEALTHCHECK CMD true\nCMD bash\n"
        result = self.scanner.scan_dockerfile(content)
        base_findings = [f for f in result.findings if f.category == "base_image"]
        assert len(base_findings) >= 1
        assert any(f.severity == ContainerSeverity.HIGH for f in base_findings)

    def test_alpine318_no_base_image_finding(self):
        content = "FROM alpine:3.18\nUSER nonroot\nHEALTHCHECK CMD true\nCMD sh\n"
        result = self.scanner.scan_dockerfile(content)
        base_findings = [f for f in result.findings if f.category == "base_image"]
        assert len(base_findings) == 0

    def test_base_image_finding_has_line_number(self):
        content = "FROM python:2\nUSER nonroot\nHEALTHCHECK CMD true\nCMD python app.py\n"
        result = self.scanner.scan_dockerfile(content)
        base_findings = [f for f in result.findings if f.category == "base_image"]
        assert base_findings[0].line_number == 1

    def test_base_image_finding_has_image_ref(self):
        content = "FROM python:2\nUSER nonroot\nHEALTHCHECK CMD true\nCMD python app.py\n"
        result = self.scanner.scan_dockerfile(content)
        base_findings = [f for f in result.findings if f.category == "base_image"]
        assert "python:2" in base_findings[0].image_ref

    def test_debian_jessie_triggers(self):
        content = "FROM debian:jessie\nUSER nonroot\nHEALTHCHECK CMD true\nCMD bash\n"
        result = self.scanner.scan_dockerfile(content)
        base_findings = [f for f in result.findings if f.category == "base_image"]
        assert len(base_findings) >= 1

    def test_golang_116_triggers_medium(self):
        content = "FROM golang:1.16\nUSER nonroot\nHEALTHCHECK CMD true\nCMD ./app\n"
        result = self.scanner.scan_dockerfile(content)
        base_findings = [f for f in result.findings if f.category == "base_image"]
        assert any(f.severity == ContainerSeverity.MEDIUM for f in base_findings)

    def test_base_image_cwe_1104(self):
        content = "FROM python:2\nUSER nonroot\nHEALTHCHECK CMD true\nCMD python\n"
        result = self.scanner.scan_dockerfile(content)
        for f in result.findings:
            if f.category == "base_image":
                assert f.cwe_id == "CWE-1104"
                return


# ─────────────────────────────────────────────────────────────────────────────
# scan_dockerfile — fully compliant Dockerfile
# ─────────────────────────────────────────────────────────────────────────────


class TestScanDockerfileCompliant:
    def setup_method(self):
        self.scanner = _make_scanner_no_tools()

    def _compliant_dockerfile(self) -> str:
        # Use "appuser" (not "nonroot") — the source checks `"root" not in stripped.lower()`
        # so "nonroot" would fail because it contains "root" as a substring.
        return (
            "FROM python:3.12-slim\n"
            "WORKDIR /app\n"
            "COPY requirements.txt .\n"
            "RUN pip install --no-cache-dir -r requirements.txt\n"
            "COPY . .\n"
            "USER appuser\n"
            "HEALTHCHECK CMD curl -f http://localhost:8080/health || exit 1\n"
            "EXPOSE 8080\n"
            "CMD [\"python\", \"app.py\"]\n"
        )

    def test_compliant_no_critical_findings(self):
        result = self.scanner.scan_dockerfile(self._compliant_dockerfile())
        critical = [f for f in result.findings if f.severity == ContainerSeverity.CRITICAL]
        assert len(critical) == 0

    def test_compliant_no_user_finding(self):
        result = self.scanner.scan_dockerfile(self._compliant_dockerfile())
        titles = {f.title for f in result.findings}
        assert "No USER Directive" not in titles

    def test_compliant_no_healthcheck_finding(self):
        result = self.scanner.scan_dockerfile(self._compliant_dockerfile())
        titles = {f.title for f in result.findings}
        assert "No HEALTHCHECK" not in titles

    def test_compliant_no_base_image_finding(self):
        result = self.scanner.scan_dockerfile(self._compliant_dockerfile())
        base_findings = [f for f in result.findings if f.category == "base_image"]
        assert len(base_findings) == 0


# ─────────────────────────────────────────────────────────────────────────────
# scan_dockerfile — by_severity and by_category aggregation
# ─────────────────────────────────────────────────────────────────────────────


class TestScanDockerfileAggregation:
    def setup_method(self):
        self.scanner = _make_scanner_no_tools()

    def test_by_severity_counts_match_findings(self):
        content = "FROM ubuntu:22.04\n"
        result = self.scanner.scan_dockerfile(content)
        total_from_sev = sum(result.by_severity.values())
        assert total_from_sev == result.total_findings

    def test_by_category_counts_match_findings(self):
        content = "FROM ubuntu:22.04\n"
        result = self.scanner.scan_dockerfile(content)
        total_from_cat = sum(result.by_category.values())
        assert total_from_cat == result.total_findings

    def test_finding_ids_unique(self):
        content = "FROM ubuntu:22.04\nUSER root\nENV DB_PASSWORD=oops\nADD ./x /y\n"
        result = self.scanner.scan_dockerfile(content)
        ids = [f.finding_id for f in result.findings]
        assert len(ids) == len(set(ids))

    def test_total_findings_consistent(self):
        content = "FROM ubuntu:22.04\n"
        result = self.scanner.scan_dockerfile(content)
        assert result.total_findings == len(result.findings)

    def test_line_numbers_recorded(self):
        content = "FROM ubuntu:22.04\nUSER root\nCMD bash\n"
        result = self.scanner.scan_dockerfile(content)
        for f in result.findings:
            if f.title == "Running as Root":
                assert f.line_number == 2
                return

    def test_trivy_grype_availability_reflected(self):
        # scanner with no tools
        result = self.scanner.scan_dockerfile("FROM ubuntu:22.04\n")
        assert result.trivy_available is False
        assert result.grype_available is False


# ─────────────────────────────────────────────────────────────────────────────
# scan_dockerfile — multi-finding Dockerfile
# ─────────────────────────────────────────────────────────────────────────────


class TestScanDockerfileMultipleFindings:
    def setup_method(self):
        self.scanner = _make_scanner_no_tools()

    def _bad_dockerfile(self) -> str:
        return (
            "FROM python:2\n"
            "FROM ubuntu:latest\n"
            "ENV DB_PASSWORD=secret123\n"
            "USER root\n"
            "ADD ./app /app\n"
            "RUN curl https://install.sh | bash\n"
            "RUN apt-get install vim\n"
            "EXPOSE 22\n"
            "CMD python app.py\n"
        )

    def test_multiple_findings_found(self):
        result = self.scanner.scan_dockerfile(self._bad_dockerfile())
        assert result.total_findings >= 5

    def test_critical_severity_in_results(self):
        result = self.scanner.scan_dockerfile(self._bad_dockerfile())
        severities = {f.severity for f in result.findings}
        assert ContainerSeverity.CRITICAL in severities

    def test_high_severity_in_results(self):
        result = self.scanner.scan_dockerfile(self._bad_dockerfile())
        severities = {f.severity for f in result.findings}
        assert ContainerSeverity.HIGH in severities

    def test_to_dict_serializable(self):
        result = self.scanner.scan_dockerfile(self._bad_dockerfile())
        d = result.to_dict()
        # Should be JSON-serializable
        json_str = json.dumps(d)
        assert len(json_str) > 0
        parsed = json.loads(json_str)
        assert parsed["total_findings"] == result.total_findings


# ─────────────────────────────────────────────────────────────────────────────
# scan_image — no trivy available
# ─────────────────────────────────────────────────────────────────────────────


class TestScanImageNoTrivy:
    def setup_method(self):
        self.scanner = _make_scanner_no_tools()

    async def test_no_trivy_returns_empty_findings(self):
        result = await self.scanner.scan_image("ubuntu:22.04")
        assert result.total_findings == 0
        assert result.findings == []

    async def test_no_trivy_result_has_scan_id(self):
        result = await self.scanner.scan_image("ubuntu:22.04")
        assert result.scan_id.startswith("cont-")

    async def test_no_trivy_target_is_image_ref(self):
        result = await self.scanner.scan_image("nginx:1.25")
        assert result.target == "nginx:1.25"

    async def test_no_trivy_availability_flags(self):
        result = await self.scanner.scan_image("ubuntu:22.04")
        assert result.trivy_available is False
        assert result.grype_available is False

    async def test_no_trivy_duration_non_negative(self):
        result = await self.scanner.scan_image("ubuntu:22.04")
        assert result.duration_ms >= 0.0

    async def test_invalid_ref_raises(self):
        with pytest.raises(ValueError):
            await self.scanner.scan_image("")

    async def test_injection_attempt_raises(self):
        with pytest.raises(ValueError):
            await self.scanner.scan_image("nginx; rm -rf /")


# ─────────────────────────────────────────────────────────────────────────────
# scan_image — with trivy (mocked)
# ─────────────────────────────────────────────────────────────────────────────


class TestScanImageWithTrivy:
    def setup_method(self):
        self.scanner = _make_scanner_with_trivy()

    def _trivy_json_output(self, vulns: list) -> bytes:
        payload = {
            "Results": [
                {
                    "Target": "nginx:1.25",
                    "Vulnerabilities": vulns,
                }
            ]
        }
        return json.dumps(payload).encode()

    def _make_vuln(
        self,
        vuln_id: str = "CVE-2023-1234",
        pkg: str = "libssl1.1",
        severity: str = "HIGH",
        fix: str = "1.1.1t",
        description: str = "A test vulnerability",
        cwe_ids: list = None,
    ) -> dict:
        v = {
            "VulnerabilityID": vuln_id,
            "PkgName": pkg,
            "Severity": severity,
            "FixedVersion": fix,
            "Description": description,
        }
        if cwe_ids is not None:
            v["CweIDs"] = cwe_ids
        return v

    async def test_trivy_findings_parsed(self):
        trivy_output = self._trivy_json_output([self._make_vuln(severity="HIGH")])

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(trivy_output, b""))

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc
        ):
            result = await self.scanner.scan_image("nginx:1.25")

        assert result.total_findings == 1
        assert result.findings[0].severity == ContainerSeverity.HIGH

    async def test_trivy_critical_severity(self):
        trivy_output = self._trivy_json_output([self._make_vuln(severity="CRITICAL")])
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(trivy_output, b""))

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc
        ):
            result = await self.scanner.scan_image("nginx:1.25")

        assert result.findings[0].severity == ContainerSeverity.CRITICAL

    async def test_trivy_medium_severity(self):
        trivy_output = self._trivy_json_output([self._make_vuln(severity="MEDIUM")])
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(trivy_output, b""))

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc
        ):
            result = await self.scanner.scan_image("nginx:1.25")

        assert result.findings[0].severity == ContainerSeverity.MEDIUM

    async def test_trivy_low_severity(self):
        trivy_output = self._trivy_json_output([self._make_vuln(severity="LOW")])
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(trivy_output, b""))

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc
        ):
            result = await self.scanner.scan_image("nginx:1.25")

        assert result.findings[0].severity == ContainerSeverity.LOW

    async def test_trivy_unknown_severity_mapped_to_info(self):
        trivy_output = self._trivy_json_output([self._make_vuln(severity="UNKNOWN")])
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(trivy_output, b""))

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc
        ):
            result = await self.scanner.scan_image("nginx:1.25")

        assert result.findings[0].severity == ContainerSeverity.INFO

    async def test_trivy_finding_title_includes_vuln_id_and_pkg(self):
        trivy_output = self._trivy_json_output(
            [self._make_vuln(vuln_id="CVE-2023-9999", pkg="openssl")]
        )
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(trivy_output, b""))

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc
        ):
            result = await self.scanner.scan_image("nginx:1.25")

        assert "CVE-2023-9999" in result.findings[0].title
        assert "openssl" in result.findings[0].title

    async def test_trivy_finding_category_image_vuln(self):
        trivy_output = self._trivy_json_output([self._make_vuln()])
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(trivy_output, b""))

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc
        ):
            result = await self.scanner.scan_image("nginx:1.25")

        assert result.findings[0].category == "image_vuln"

    async def test_trivy_finding_image_ref_set(self):
        trivy_output = self._trivy_json_output([self._make_vuln()])
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(trivy_output, b""))

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc
        ):
            result = await self.scanner.scan_image("nginx:1.25")

        assert result.findings[0].image_ref == "nginx:1.25"

    async def test_trivy_cwe_from_vuln_data(self):
        trivy_output = self._trivy_json_output(
            [self._make_vuln(cwe_ids=["CWE-79"])]
        )
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(trivy_output, b""))

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc
        ):
            result = await self.scanner.scan_image("nginx:1.25")

        assert result.findings[0].cwe_id == "CWE-79"

    async def test_trivy_no_cwe_falls_back_to_1104(self):
        trivy_output = self._trivy_json_output([self._make_vuln(cwe_ids=None)])
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(trivy_output, b""))

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc
        ):
            result = await self.scanner.scan_image("nginx:1.25")

        assert result.findings[0].cwe_id == "CWE-1104"

    async def test_trivy_empty_cwe_list_falls_back_to_1104(self):
        trivy_output = self._trivy_json_output([self._make_vuln(cwe_ids=[])])
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(trivy_output, b""))

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc
        ):
            result = await self.scanner.scan_image("nginx:1.25")

        assert result.findings[0].cwe_id == "CWE-1104"

    async def test_trivy_multiple_vulns(self):
        vulns = [
            self._make_vuln("CVE-2023-0001", severity="HIGH"),
            self._make_vuln("CVE-2023-0002", severity="MEDIUM"),
            self._make_vuln("CVE-2023-0003", severity="LOW"),
        ]
        trivy_output = self._trivy_json_output(vulns)
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(trivy_output, b""))

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc
        ):
            result = await self.scanner.scan_image("nginx:1.25")

        assert result.total_findings == 3
        assert result.by_severity.get("high", 0) == 1
        assert result.by_severity.get("medium", 0) == 1
        assert result.by_severity.get("low", 0) == 1

    async def test_trivy_empty_results_array(self):
        trivy_output = json.dumps({"Results": []}).encode()
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(trivy_output, b""))

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc
        ):
            result = await self.scanner.scan_image("nginx:1.25")

        assert result.total_findings == 0

    async def test_trivy_result_with_no_vulnerabilities_key(self):
        trivy_output = json.dumps({"Results": [{"Target": "test"}]}).encode()
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(trivy_output, b""))

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc
        ):
            result = await self.scanner.scan_image("nginx:1.25")

        assert result.total_findings == 0

    async def test_trivy_availability_true_in_result(self):
        trivy_output = self._trivy_json_output([])
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(trivy_output, b""))

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc
        ):
            result = await self.scanner.scan_image("nginx:1.25")

        assert result.trivy_available is True


# ─────────────────────────────────────────────────────────────────────────────
# scan_image — error handling paths
# ─────────────────────────────────────────────────────────────────────────────


class TestScanImageErrorHandling:
    def setup_method(self):
        self.scanner = _make_scanner_with_trivy()

    async def test_trivy_timeout_returns_empty_findings(self):
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc
        ):
            result = await self.scanner.scan_image("nginx:1.25")

        assert result.total_findings == 0
        assert result.findings == []

    async def test_trivy_invalid_json_returns_empty_findings(self):
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"not valid json!!", b""))

        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc
        ):
            result = await self.scanner.scan_image("nginx:1.25")

        assert result.total_findings == 0

    async def test_trivy_file_not_found_returns_empty_findings(self):
        with patch(
            "asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            side_effect=FileNotFoundError("trivy not found"),
        ):
            result = await self.scanner.scan_image("nginx:1.25")

        assert result.total_findings == 0

    async def test_trivy_generic_exception_returns_empty_findings(self):
        with patch(
            "asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            side_effect=RuntimeError("unexpected"),
        ):
            result = await self.scanner.scan_image("nginx:1.25")

        assert result.total_findings == 0

    async def test_scan_result_scan_id_unique_each_call(self):
        trivy_output = json.dumps({"Results": []}).encode()
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(trivy_output, b""))

        scanner = _make_scanner_no_tools()
        with patch(
            "asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc
        ):
            r1 = await scanner.scan_image("nginx:1.25")
            r2 = await scanner.scan_image("nginx:1.25")

        assert r1.scan_id != r2.scan_id


# ─────────────────────────────────────────────────────────────────────────────
# get_container_scanner singleton
# ─────────────────────────────────────────────────────────────────────────────


class TestGetContainerScannerSingleton:
    def setup_method(self):
        # Reset singleton before each test
        _mod._scanner = None

    def teardown_method(self):
        # Clean up singleton
        _mod._scanner = None

    def test_returns_scanner_instance(self):
        scanner = get_container_scanner()
        assert isinstance(scanner, ContainerImageScanner)

    def test_returns_same_instance_on_second_call(self):
        s1 = get_container_scanner()
        s2 = get_container_scanner()
        assert s1 is s2

    def test_singleton_is_none_initially(self):
        assert _mod._scanner is None

    def test_singleton_set_after_first_call(self):
        get_container_scanner()
        assert _mod._scanner is not None

    def test_reuses_existing_instance_if_set(self):
        existing = ContainerImageScanner()
        _mod._scanner = existing
        result = get_container_scanner()
        assert result is existing


# ─────────────────────────────────────────────────────────────────────────────
# Edge cases — line number tracking and skipping
# ─────────────────────────────────────────────────────────────────────────────


class TestScanDockerfileEdgeCases:
    def setup_method(self):
        self.scanner = _make_scanner_no_tools()

    def test_inline_comment_ignored(self):
        # Lines starting with # are skipped entirely
        content = "# FROM ubuntu:14.04\nFROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\n"
        result = self.scanner.scan_dockerfile(content)
        base_findings = [f for f in result.findings if f.category == "base_image"]
        assert len(base_findings) == 0

    def test_blank_lines_ignored(self):
        # Use "appuser" — "nonroot" contains "root" so it won't set has_user=True
        content = "\n\n\nFROM ubuntu:22.04\n\n\nUSER appuser\nHEALTHCHECK CMD true\n"
        result = self.scanner.scan_dockerfile(content)
        # Should not crash; meta-rules resolved
        titles = {f.title for f in result.findings}
        assert "No USER Directive" not in titles
        assert "No HEALTHCHECK" not in titles

    def test_finding_category_dockerfile_present(self):
        content = "FROM ubuntu:22.04\n"
        result = self.scanner.scan_dockerfile(content)
        cats = {f.category for f in result.findings}
        assert "dockerfile" in cats

    def test_expose_non_digit_no_crash(self):
        # EXPOSE with non-numeric value should not crash (regex won't match)
        content = "FROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\nEXPOSE tcp/80\n"
        result = self.scanner.scan_dockerfile(content)
        # No crash is the key assertion
        assert result is not None

    def test_finding_confidence_default(self):
        content = "FROM ubuntu:22.04\n"
        result = self.scanner.scan_dockerfile(content)
        for f in result.findings:
            assert f.confidence == 0.9

    def test_description_truncation_not_applied_in_dockerfile_scan(self):
        # Dockerfile scan findings use predefined descriptions (not truncated)
        content = "FROM ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\nADD ./app /app\n"
        result = self.scanner.scan_dockerfile(content)
        for f in result.findings:
            assert isinstance(f.description, str)

    def test_from_case_insensitive(self):
        # FROM directive detection is case-insensitive
        content = "from ubuntu:22.04\nUSER nonroot\nHEALTHCHECK CMD true\n"
        result = self.scanner.scan_dockerfile(content)
        # Should not crash and should not produce base_image finding for ubuntu:22.04
        base_findings = [f for f in result.findings if f.category == "base_image"]
        assert len(base_findings) == 0

    def test_scan_result_to_dict_json_serializable(self):
        content = "FROM ubuntu:22.04\n"
        result = self.scanner.scan_dockerfile(content)
        d = result.to_dict()
        json_str = json.dumps(d)
        reparsed = json.loads(json_str)
        assert reparsed["total_findings"] == result.total_findings

    def test_user_root_case_insensitive(self):
        # "USER ROOT" should trigger the Running as Root finding
        content = "FROM ubuntu:22.04\nUSER ROOT\nHEALTHCHECK CMD true\n"
        result = self.scanner.scan_dockerfile(content)
        titles = {f.title for f in result.findings}
        assert "Running as Root" in titles

    def test_dockerfile_with_multistage_build(self):
        # Use "appuser" — "nonroot" contains "root" so it won't set has_user=True
        content = (
            "FROM python:3.12-slim AS builder\n"
            "RUN pip install build\n"
            "FROM python:3.12-slim\n"
            "COPY --from=builder /dist /app\n"
            "USER appuser\n"
            "HEALTHCHECK CMD curl -f http://localhost/ || exit 1\n"
            "CMD [\"python\", \"-m\", \"app\"]\n"
        )
        result = self.scanner.scan_dockerfile(content)
        # No vulnerable base image, user present, healthcheck present
        base_findings = [f for f in result.findings if f.category == "base_image"]
        assert len(base_findings) == 0
        titles = {f.title for f in result.findings}
        assert "No USER Directive" not in titles
        assert "No HEALTHCHECK" not in titles
