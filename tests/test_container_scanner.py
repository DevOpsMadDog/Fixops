"""Tests for ContainerSecurityScanner (suite-core/core/container_scanner.py).

30+ tests covering all 7 check categories, scoring, parsing, persistence,
and the Pydantic models.

Usage:
    pytest tests/test_container_scanner.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure suite-core is importable
suite_core_path = str(Path(__file__).parent.parent / "suite-core")
if suite_core_path not in sys.path:
    sys.path.insert(0, suite_core_path)

from core.container_scanner import (
    CheckCategory,
    ContainerFinding,
    ContainerSecurityScanner,
    DockerfileAnalysis,
    Severity,
)

# ---------------------------------------------------------------------------
# Sample Dockerfiles
# ---------------------------------------------------------------------------

GOOD_DOCKERFILE = """
FROM python:3.12-slim@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ /app/src/
RUN addgroup -S app && adduser -S app -G app
USER app
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8080/health || exit 1
CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8080"]
"""

BAD_DOCKERFILE = """
FROM ubuntu:latest
RUN apt-get install -y curl wget netcat python3-dev
ENV DB_PASSWORD=supersecret
ENV API_KEY=myapikey123
ARG PRIVATE_KEY=defaultkey
COPY .env /app/.env
COPY id_rsa /root/.ssh/id_rsa
EXPOSE 22
EXPOSE 3306
EXPOSE 80
CMD ["/bin/bash"]
"""

MINIMAL_DOCKERFILE = """
FROM python:3.11
CMD ["python", "app.py"]
"""

ALPINE_DOCKERFILE = """
FROM alpine:3.19
RUN apk add curl nmap
EXPOSE 8443
USER appuser
HEALTHCHECK CMD wget -O- http://localhost/ || exit 1
CMD ["./app"]
"""

MULTISTAGE_DOCKERFILE = """
FROM node:20-slim AS builder
WORKDIR /build
COPY package.json .
RUN npm ci
COPY src/ src/
RUN npm run build

FROM node:20-slim
WORKDIR /app
COPY --from=builder /build/dist /app/dist
RUN adduser --disabled-password --gecos '' appuser
USER appuser
EXPOSE 3000
HEALTHCHECK --interval=30s CMD curl -f http://localhost:3000/ || exit 1
CMD ["node", "dist/index.js"]
"""

PRIVILEGED_DOCKERFILE = """
FROM debian:bookworm-slim
# Run with --privileged for full access
# cap_sys_admin required
RUN apt-get update && apt-get install -y openssh-server && rm -rf /var/lib/apt/lists/*
EXPOSE 2375
CMD ["/usr/sbin/sshd", "-D"]
"""

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def scanner(tmp_path):
    """Provide a ContainerSecurityScanner with an isolated temp DB."""
    return ContainerSecurityScanner(db_path=str(tmp_path / "test_scanner.db"))


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestModels:
    def test_severity_enum_values(self):
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"
        assert Severity.INFO == "info"

    def test_check_category_enum_values(self):
        assert CheckCategory.USER_PRIVILEGE == "user_privilege"
        assert CheckCategory.SECRETS == "secrets"
        assert CheckCategory.PACKAGES == "packages"
        assert CheckCategory.BASE_IMAGE == "base_image"
        assert CheckCategory.NETWORK == "network"
        assert CheckCategory.FILESYSTEM == "filesystem"
        assert CheckCategory.RUNTIME == "runtime"

    def test_container_finding_defaults(self):
        f = ContainerFinding(
            check_id="DKR-001",
            title="Test",
            description="desc",
            severity=Severity.HIGH,
            category=CheckCategory.USER_PRIVILEGE,
            remediation="fix it",
        )
        assert f.id  # auto-generated uuid
        assert f.line_number is None
        assert f.file_path == "Dockerfile"

    def test_dockerfile_analysis_defaults(self):
        a = DockerfileAnalysis()
        assert a.id
        assert a.score == 100.0
        assert a.user == "root"
        assert a.exposed_ports == []
        assert a.findings == []


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------


class TestParser:
    def test_parse_basic_instructions(self, scanner):
        content = "FROM python:3.12\nRUN pip install flask\nCMD [\"python\", \"app.py\"]"
        instructions = scanner._parse_dockerfile(content)
        cmds = [i["cmd"] for i in instructions]
        assert "FROM" in cmds
        assert "RUN" in cmds
        assert "CMD" in cmds

    def test_parse_skips_comments(self, scanner):
        content = "# This is a comment\nFROM python:3.12\n# Another comment"
        instructions = scanner._parse_dockerfile(content)
        assert all(i["cmd"] != "#" for i in instructions)
        assert len(instructions) == 1

    def test_parse_skips_blank_lines(self, scanner):
        content = "\n\nFROM python:3.12\n\n\nRUN echo hi\n"
        instructions = scanner._parse_dockerfile(content)
        assert len(instructions) == 2

    def test_parse_continuation_lines(self, scanner):
        content = "RUN apt-get install -y \\\n    curl \\\n    wget"
        instructions = scanner._parse_dockerfile(content)
        assert len(instructions) == 1
        assert "curl" in instructions[0]["value"]
        assert "wget" in instructions[0]["value"]

    def test_parse_line_numbers(self, scanner):
        content = "FROM python:3.12\n\nRUN echo hi"
        instructions = scanner._parse_dockerfile(content)
        assert instructions[0]["line"] == 1
        assert instructions[1]["line"] == 3

    def test_extract_base_image(self, scanner):
        instructions = scanner._parse_dockerfile("FROM python:3.12-slim\nCMD [\"python\"]")
        assert scanner._extract_base_image(instructions) == "python:3.12-slim"

    def test_extract_user_defaults_root(self, scanner):
        instructions = scanner._parse_dockerfile("FROM python:3.12\nCMD [\"python\"]")
        assert scanner._extract_user(instructions) == "root"

    def test_extract_user_last_wins(self, scanner):
        instructions = scanner._parse_dockerfile("FROM python:3.12\nUSER root\nUSER appuser")
        assert scanner._extract_user(instructions) == "appuser"

    def test_extract_ports(self, scanner):
        instructions = scanner._parse_dockerfile("FROM python:3.12\nEXPOSE 8080 443\nEXPOSE 22")
        ports = scanner._extract_ports(instructions)
        assert 8080 in ports
        assert 443 in ports
        assert 22 in ports


# ---------------------------------------------------------------------------
# USER_PRIVILEGE checks
# ---------------------------------------------------------------------------


class TestUserPrivilegeChecks:
    def test_no_user_directive_raises_finding(self, scanner):
        analysis = scanner.scan_dockerfile(MINIMAL_DOCKERFILE)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-001" in check_ids

    def test_root_user_explicit_raises_finding(self, scanner):
        content = "FROM python:3.12\nUSER root\nCMD [\"python\"]"
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-002" in check_ids

    def test_nonroot_user_no_privilege_finding(self, scanner):
        content = "FROM python:3.12\nUSER appuser\nCMD [\"python\"]"
        analysis = scanner.scan_dockerfile(content)
        privilege_findings = [f for f in analysis.findings if f.category == CheckCategory.USER_PRIVILEGE]
        assert not privilege_findings

    def test_user_zero_triggers_finding(self, scanner):
        content = "FROM python:3.12\nUSER 0\nCMD [\"python\"]"
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-002" in check_ids


# ---------------------------------------------------------------------------
# SECRETS checks
# ---------------------------------------------------------------------------


class TestSecretsChecks:
    def test_env_password_detected(self, scanner):
        content = "FROM python:3.12\nENV DB_PASSWORD=secret123\nCMD [\"python\"]"
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-010" in check_ids

    def test_env_api_key_detected(self, scanner):
        content = "FROM python:3.12\nENV API_KEY=abc123\nCMD [\"python\"]"
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-010" in check_ids

    def test_arg_private_key_detected(self, scanner):
        content = "FROM python:3.12\nARG PRIVATE_KEY\nCMD [\"python\"]"
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-011" in check_ids

    def test_copy_pem_file_detected(self, scanner):
        content = "FROM python:3.12\nCOPY server.pem /app/\nCMD [\"python\"]"
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-012" in check_ids

    def test_copy_env_file_detected(self, scanner):
        content = "FROM python:3.12\nCOPY .env /app/.env\nCMD [\"python\"]"
        analysis = scanner.scan_dockerfile(content)
        # .env file should trigger DKR-051 (filesystem) or DKR-012 (secrets)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-012" in check_ids or "DKR-051" in check_ids

    def test_bad_dockerfile_secrets(self, scanner):
        analysis = scanner.scan_dockerfile(BAD_DOCKERFILE)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-010" in check_ids  # ENV secret


# ---------------------------------------------------------------------------
# PACKAGES checks
# ---------------------------------------------------------------------------


class TestPackagesChecks:
    def test_risky_package_wget(self, scanner):
        content = "FROM python:3.12\nRUN apt-get install -y wget\nCMD [\"python\"]"
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-020" in check_ids

    def test_risky_package_curl(self, scanner):
        content = "FROM python:3.12\nRUN apt-get install -y curl\nCMD [\"python\"]"
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-020" in check_ids

    def test_apt_cache_not_cleaned(self, scanner):
        content = "FROM debian:bookworm-slim\nRUN apt-get install -y vim\nCMD [\"bash\"]"
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-022" in check_ids

    def test_apk_without_no_cache(self, scanner):
        content = "FROM alpine:3.19\nRUN apk add bash\nCMD [\"bash\"]"
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-023" in check_ids

    def test_apk_with_no_cache_ok(self, scanner):
        content = "FROM alpine:3.19\nRUN apk add --no-cache bash\nUSER appuser\nCMD [\"bash\"]"
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-023" not in check_ids


# ---------------------------------------------------------------------------
# BASE_IMAGE checks
# ---------------------------------------------------------------------------


class TestBaseImageChecks:
    def test_latest_tag_detected(self, scanner):
        content = "FROM ubuntu:latest\nCMD [\"bash\"]"
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-030" in check_ids

    def test_pinned_digest_no_finding(self, scanner):
        content = ("FROM python:3.12-slim@sha256:abcdef1234567890abcdef1234567890"
                   "abcdef1234567890abcdef1234567890\nUSER appuser\nCMD [\"python\"]")
        analysis = scanner.scan_dockerfile(content)
        base_findings = [f for f in analysis.findings if f.check_id in {"DKR-030", "DKR-031"}]
        assert not base_findings

    def test_version_tag_without_digest(self, scanner):
        content = "FROM python:3.12\nCMD [\"python\"]"
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-031" in check_ids

    def test_full_os_base_detected(self, scanner):
        content = "FROM ubuntu:22.04\nCMD [\"bash\"]"
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-033" in check_ids

    def test_slim_base_no_full_os_finding(self, scanner):
        content = "FROM debian:bookworm-slim\nCMD [\"bash\"]"
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-033" not in check_ids


# ---------------------------------------------------------------------------
# NETWORK checks
# ---------------------------------------------------------------------------


class TestNetworkChecks:
    def test_ssh_port_detected(self, scanner):
        content = "FROM python:3.12\nEXPOSE 22\nCMD [\"python\"]"
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-040" in check_ids

    def test_mysql_port_detected(self, scanner):
        content = "FROM python:3.12\nEXPOSE 3306\nCMD [\"python\"]"
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-040" in check_ids

    def test_privileged_port_80(self, scanner):
        content = "FROM python:3.12\nEXPOSE 80\nCMD [\"python\"]"
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-041" in check_ids

    def test_safe_port_no_finding(self, scanner):
        content = "FROM python:3.12\nEXPOSE 8080\nUSER appuser\nCMD [\"python\"]"
        analysis = scanner.scan_dockerfile(content)
        network_findings = [f for f in analysis.findings if f.category == CheckCategory.NETWORK]
        assert not network_findings


# ---------------------------------------------------------------------------
# FILESYSTEM checks
# ---------------------------------------------------------------------------


class TestFilesystemChecks:
    def test_copy_whole_context(self, scanner):
        content = "FROM python:3.12\nCOPY . .\nCMD [\"python\"]"
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-050" in check_ids

    def test_copy_key_file(self, scanner):
        content = "FROM python:3.12\nCOPY private.key /app/\nCMD [\"python\"]"
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-051" in check_ids

    def test_readonly_filesystem_finding_always_present(self, scanner):
        # DKR-052 is always added as an informational nudge
        analysis = scanner.scan_dockerfile(MINIMAL_DOCKERFILE)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-052" in check_ids


# ---------------------------------------------------------------------------
# RUNTIME checks
# ---------------------------------------------------------------------------


class TestRuntimeChecks:
    def test_no_healthcheck_finding(self, scanner):
        analysis = scanner.scan_dockerfile(MINIMAL_DOCKERFILE)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-062" in check_ids

    def test_healthcheck_present_no_finding(self, scanner):
        content = (
            "FROM python:3.12-slim\nUSER appuser\n"
            "HEALTHCHECK CMD curl -f http://localhost/ || exit 1\nCMD [\"python\"]"
        )
        analysis = scanner.scan_dockerfile(content)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-062" not in check_ids

    def test_no_shell_info_finding(self, scanner):
        analysis = scanner.scan_dockerfile(MINIMAL_DOCKERFILE)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-063" in check_ids

    def test_privileged_hint_detected(self, scanner):
        analysis = scanner.scan_dockerfile(PRIVILEGED_DOCKERFILE)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-060" in check_ids

    def test_dangerous_cap_detected(self, scanner):
        analysis = scanner.scan_dockerfile(PRIVILEGED_DOCKERFILE)
        check_ids = [f.check_id for f in analysis.findings]
        assert "DKR-061" in check_ids


# ---------------------------------------------------------------------------
# Scoring tests
# ---------------------------------------------------------------------------


class TestScoring:
    def test_no_findings_score_100(self, scanner):
        score = scanner.score_analysis([])
        assert score == 100.0

    def test_critical_finding_deducts_25(self, scanner):
        f = ContainerFinding(
            check_id="DKR-010",
            title="t",
            description="d",
            severity=Severity.CRITICAL,
            category=CheckCategory.SECRETS,
            remediation="r",
        )
        assert scanner.score_analysis([f]) == 75.0

    def test_score_floored_at_zero(self, scanner):
        findings = [
            ContainerFinding(
                check_id=f"DKR-{i:03d}",
                title="t",
                description="d",
                severity=Severity.CRITICAL,
                category=CheckCategory.SECRETS,
                remediation="r",
            )
            for i in range(10)
        ]
        assert scanner.score_analysis(findings) == 0.0

    def test_good_dockerfile_score_higher_than_bad(self, scanner):
        good = scanner.scan_dockerfile(GOOD_DOCKERFILE, org_id="score_test")
        bad = scanner.scan_dockerfile(BAD_DOCKERFILE, org_id="score_test")
        assert good.score > bad.score

    def test_bad_dockerfile_score_below_50(self, scanner):
        analysis = scanner.scan_dockerfile(BAD_DOCKERFILE)
        assert analysis.score < 50


# ---------------------------------------------------------------------------
# get_checks catalogue
# ---------------------------------------------------------------------------


class TestGetChecks:
    def test_returns_at_least_20_checks(self, scanner):
        checks = scanner.get_checks()
        assert len(checks) >= 20

    def test_all_checks_have_required_fields(self, scanner):
        for check in scanner.get_checks():
            assert "id" in check
            assert "category" in check
            assert "severity" in check
            assert "title" in check

    def test_check_ids_are_unique(self, scanner):
        checks = scanner.get_checks()
        ids = [c["id"] for c in checks]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# History and stats persistence
# ---------------------------------------------------------------------------


class TestPersistence:
    def test_scan_stored_in_history(self, scanner):
        scanner.scan_dockerfile(MINIMAL_DOCKERFILE, org_id="test_org")
        history = scanner.get_scan_history("test_org")
        assert len(history) >= 1

    def test_history_scoped_by_org(self, scanner):
        scanner.scan_dockerfile(MINIMAL_DOCKERFILE, org_id="org_a")
        scanner.scan_dockerfile(MINIMAL_DOCKERFILE, org_id="org_b")
        history_a = scanner.get_scan_history("org_a")
        history_b = scanner.get_scan_history("org_b")
        assert all(a.org_id == "org_a" for a in history_a)
        assert all(b.org_id == "org_b" for b in history_b)

    def test_stats_total_scans(self, scanner):
        scanner.scan_dockerfile(MINIMAL_DOCKERFILE, org_id="stats_org")
        scanner.scan_dockerfile(MINIMAL_DOCKERFILE, org_id="stats_org")
        stats = scanner.get_scanner_stats("stats_org")
        assert stats["total_scans"] == 2

    def test_stats_empty_org(self, scanner):
        stats = scanner.get_scanner_stats("nonexistent_org")
        assert stats["total_scans"] == 0
        assert stats["avg_score"] == 0.0

    def test_stats_has_expected_keys(self, scanner):
        scanner.scan_dockerfile(MINIMAL_DOCKERFILE, org_id="keys_org")
        stats = scanner.get_scanner_stats("keys_org")
        for key in ("total_scans", "avg_score", "total_findings", "by_severity", "by_category"):
            assert key in stats

    def test_history_deserialization(self, scanner):
        scanner.scan_dockerfile(MINIMAL_DOCKERFILE, org_id="deser_org")
        history = scanner.get_scan_history("deser_org")
        assert isinstance(history[0], DockerfileAnalysis)
        assert isinstance(history[0].findings[0], ContainerFinding)


# ---------------------------------------------------------------------------
# Integration: multistage and alpine
# ---------------------------------------------------------------------------


class TestIntegration:
    def test_multistage_dockerfile_parsed(self, scanner):
        analysis = scanner.scan_dockerfile(MULTISTAGE_DOCKERFILE)
        assert analysis.base_image  # detected FROM
        assert analysis.total_layers > 0

    def test_alpine_dockerfile_apk_check(self, scanner):
        analysis = scanner.scan_dockerfile(ALPINE_DOCKERFILE)
        check_ids = [f.check_id for f in analysis.findings]
        # curl installed — risky package
        assert "DKR-020" in check_ids

    def test_analysis_exposed_ports_populated(self, scanner):
        analysis = scanner.scan_dockerfile(BAD_DOCKERFILE)
        assert 22 in analysis.exposed_ports
        assert 3306 in analysis.exposed_ports

    def test_analysis_findings_are_pydantic(self, scanner):
        analysis = scanner.scan_dockerfile(MINIMAL_DOCKERFILE)
        for f in analysis.findings:
            assert isinstance(f, ContainerFinding)

    def test_scan_returns_dockerfile_analysis(self, scanner):
        result = scanner.scan_dockerfile(GOOD_DOCKERFILE)
        assert isinstance(result, DockerfileAnalysis)
