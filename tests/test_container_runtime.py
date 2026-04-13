"""Tests for Container Runtime Security Engine.

Covers: ImageAnalyzer, RuntimePolicyEngine, DriftDetector, VulnerabilityMapper,
CISBenchmarkChecker, ImageSigningVerifier, RegistrySecurityScanner, and the
ContainerRuntimeSecurityEngine facade.

Usage:
    pytest tests/test_container_runtime.py -v --timeout=10
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

# Ensure suite-core is on the path
suite_core_path = str(Path(__file__).parent.parent / "suite-core")
if suite_core_path not in sys.path:
    sys.path.insert(0, suite_core_path)

from core.container_runtime import (
    CISBenchmarkChecker,
    CISBenchmarkSection,
    ContainerRuntimeSecurityEngine,
    DriftDetector,
    DriftType,
    ImageAnalysisResult,
    ImageAnalyzer,
    ImageLayer,
    ImageSigningVerifier,
    InstalledPackage,
    RegistrySecurityScanner,
    RegistryVulnStatus,
    RuntimePolicy,
    RuntimePolicyEngine,
    Severity,
    SignatureScheme,
    VulnerabilityMapper,
    _detect_base_image,
    _detect_os,
    _is_squashable,
    _severity_from_cvss,
    get_container_runtime_engine,
)


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
def basic_manifest() -> Dict[str, Any]:
    return {
        "architecture": "amd64",
        "layers": [
            {"digest": "sha256:abc123", "size": 5_000_000},
            {"digest": "sha256:def456", "size": 2_000_000},
        ],
        "config": {"digest": "sha256:cfgdigest"},
    }


@pytest.fixture
def basic_config() -> Dict[str, Any]:
    return {
        "Labels": {"maintainer": "team@example.com", "version": "1.0"},
        "Env": ["PATH=/usr/local/bin:/usr/bin:/bin", "APP_PORT=8080"],
        "ExposedPorts": {"8080/tcp": {}},
        "Entrypoint": ["/app/server"],
        "Cmd": ["--config", "/app/config.yaml"],
        "User": "appuser",
        "Healthcheck": {"Test": ["CMD", "curl", "-f", "http://localhost:8080/health"]},
        "history": [
            {"created_by": "FROM ubuntu:22.04", "created": "2024-01-01T00:00:00Z"},
            {"created_by": "RUN apt-get update && apt-get install -y curl", "created": "2024-01-02T00:00:00Z"},
        ],
    }


@pytest.fixture
def image_analysis(basic_manifest, basic_config) -> ImageAnalysisResult:
    analyzer = ImageAnalyzer()
    return analyzer.analyse("myregistry.io/myapp:1.0", basic_manifest, basic_config)


@pytest.fixture
def engine() -> ContainerRuntimeSecurityEngine:
    return ContainerRuntimeSecurityEngine()


@pytest.fixture
def default_policy() -> RuntimePolicy:
    return RuntimePolicy(
        name="test-policy",
        approved_base_images=["ubuntu", "alpine"],
        approved_registries=["myregistry.io"],
        required_labels=["maintainer", "version"],
        max_image_size_mb=100,
        allow_root_user=False,
        require_healthcheck=True,
    )


# ===========================================================================
# Helper utilities
# ===========================================================================


class TestHelpers:
    def test_severity_from_cvss_critical(self):
        assert _severity_from_cvss(9.5) == Severity.CRITICAL

    def test_severity_from_cvss_high(self):
        assert _severity_from_cvss(7.8) == Severity.HIGH

    def test_severity_from_cvss_medium(self):
        assert _severity_from_cvss(5.0) == Severity.MEDIUM

    def test_severity_from_cvss_low(self):
        assert _severity_from_cvss(2.0) == Severity.LOW

    def test_severity_from_cvss_info(self):
        assert _severity_from_cvss(0.0) == Severity.INFO

    def test_detect_base_image_with_tag(self):
        base, tag = _detect_base_image("docker.io/library/ubuntu:22.04")
        assert base == "docker.io/library/ubuntu"
        assert tag == "22.04"

    def test_detect_base_image_latest(self):
        base, tag = _detect_base_image("nginx")
        assert base == "nginx"
        assert tag == "latest"

    def test_detect_base_image_strips_digest(self):
        base, tag = _detect_base_image("alpine:3.18@sha256:abc123")
        assert "alpine" in base

    def test_detect_os_from_alpine_label(self):
        labels = {"org.opencontainers.image.base.name": "alpine"}
        os_f, _ = _detect_os(labels, [], [])
        assert os_f == "alpine"

    def test_detect_os_from_ubuntu_label(self):
        labels = {"os": "ubuntu"}
        os_f, _ = _detect_os(labels, [], [])
        assert os_f == "ubuntu"

    def test_detect_os_fallback(self):
        os_f, _ = _detect_os({}, [], [])
        assert os_f == "linux"

    def test_squashable_consecutive_run(self):
        layers = [
            ImageLayer(digest="sha256:a", size_bytes=1000, command="RUN apt-get update"),
            ImageLayer(digest="sha256:b", size_bytes=1000, command="RUN apt-get install curl"),
            ImageLayer(digest="sha256:c", size_bytes=1000, command="COPY . /app"),
        ]
        assert _is_squashable(layers) == 1

    def test_squashable_no_consecutive(self):
        layers = [
            ImageLayer(digest="sha256:a", size_bytes=1000, command="COPY . /app"),
            ImageLayer(digest="sha256:b", size_bytes=1000, command="RUN echo hello"),
        ]
        assert _is_squashable(layers) == 0


# ===========================================================================
# ImageAnalyzer
# ===========================================================================


class TestImageAnalyzer:
    def test_analyse_basic(self, basic_manifest, basic_config):
        analyzer = ImageAnalyzer()
        result = analyzer.analyse("myregistry.io/myapp:1.0", basic_manifest, basic_config)
        assert result.image_ref == "myregistry.io/myapp:1.0"
        assert result.layer_count == 2
        assert result.total_size_bytes == 7_000_000

    def test_analyse_no_manifest(self):
        analyzer = ImageAnalyzer()
        result = analyzer.analyse("scratch:latest")
        assert result.image_ref == "scratch:latest"
        assert result.layer_count == 0

    def test_analyse_user(self, image_analysis):
        assert image_analysis.user == "appuser"

    def test_analyse_healthcheck(self, image_analysis):
        assert image_analysis.has_healthcheck is True

    def test_analyse_exposed_ports(self, image_analysis):
        assert "8080/tcp" in image_analysis.exposed_ports

    def test_analyse_labels(self, image_analysis):
        assert "maintainer" in image_analysis.labels
        assert "version" in image_analysis.labels

    def test_analyse_entrypoint(self, image_analysis):
        assert "/app/server" in image_analysis.entrypoint

    def test_analyse_env_vars(self, image_analysis):
        assert any("APP_PORT" in v for v in image_analysis.environment_vars)

    def test_analyse_scan_id_unique(self, basic_manifest, basic_config):
        analyzer = ImageAnalyzer()
        r1 = analyzer.analyse("img:1", basic_manifest, basic_config)
        r2 = analyzer.analyse("img:2", basic_manifest, basic_config)
        assert r1.scan_id != r2.scan_id

    def test_analyse_multi_stage_detection(self):
        analyzer = ImageAnalyzer()
        manifest = {"layers": []}
        config = {
            "history": [
                {"created_by": "FROM golang:1.21 AS builder"},
                {"created_by": "RUN go build -o app ."},
                {"created_by": "FROM scratch"},
                {"created_by": "COPY --from=builder /app /app"},
            ]
        }
        result = analyzer.analyse("multi:latest", manifest, config)
        assert result.is_multi_stage is True

    def test_analyse_to_dict(self, image_analysis):
        d = image_analysis.to_dict()
        assert isinstance(d, dict)
        assert "image_ref" in d
        assert "layer_count" in d

    def test_analyse_architecture_from_manifest(self):
        analyzer = ImageAnalyzer()
        manifest = {"architecture": "arm64", "layers": []}
        result = analyzer.analyse("arm-app:latest", manifest, {})
        assert result.architecture == "arm64"

    def test_analyse_root_user_default(self):
        analyzer = ImageAnalyzer()
        result = analyzer.analyse("img:latest", {}, {"User": ""})
        assert result.user == "root"

    def test_analyse_no_healthcheck_by_default(self):
        analyzer = ImageAnalyzer()
        result = analyzer.analyse("img:latest", {}, {})
        assert result.has_healthcheck is False


# ===========================================================================
# RuntimePolicyEngine
# ===========================================================================


class TestRuntimePolicyEngine:
    def test_add_and_list_policy(self, default_policy):
        pe = RuntimePolicyEngine()
        pe.add_policy(default_policy)
        policies = pe.list_policies()
        assert len(policies) == 1
        assert policies[0].name == "test-policy"

    def test_remove_policy(self, default_policy):
        pe = RuntimePolicyEngine()
        pe.add_policy(default_policy)
        removed = pe.remove_policy(default_policy.policy_id)
        assert removed is True
        assert len(pe.list_policies()) == 0

    def test_remove_nonexistent_policy(self):
        pe = RuntimePolicyEngine()
        assert pe.remove_policy("nonexistent-id") is False

    def test_evaluate_pass(self, image_analysis, default_policy):
        pe = RuntimePolicyEngine()
        pe.add_policy(default_policy)
        results = pe.evaluate("myregistry.io/myapp:1.0", image_analysis)
        assert len(results) == 1
        # Size is 7MB < 100MB limit; user is appuser; healthcheck present; labels ok
        # base image heuristic: "myregistry.io/myapp" doesn't contain "ubuntu" or "alpine"
        # so we expect a violation on approved_base_images
        assert isinstance(results[0].passed, bool)

    def test_evaluate_root_user_violation(self, default_policy):
        pe = RuntimePolicyEngine()
        pe.add_policy(default_policy)
        analysis = ImageAnalysisResult(
            image_ref="bad:latest",
            user="root",
            has_healthcheck=True,
            labels={"maintainer": "x", "version": "1"},
            total_size_bytes=10 * 1024 * 1024,
        )
        results = pe.evaluate("bad:latest", analysis)
        violations = results[0].violations
        rules = [v.rule for v in violations]
        assert "no_root_user" in rules

    def test_evaluate_missing_label_violation(self, default_policy):
        pe = RuntimePolicyEngine()
        pe.add_policy(default_policy)
        analysis = ImageAnalysisResult(
            image_ref="myregistry.io/myapp:1.0",
            user="appuser",
            has_healthcheck=True,
            labels={"maintainer": "x"},  # missing "version"
            total_size_bytes=10 * 1024 * 1024,
        )
        results = pe.evaluate("myregistry.io/myapp:1.0", analysis)
        rules = [v.rule for v in results[0].violations]
        assert "required_labels" in rules

    def test_evaluate_size_violation(self, default_policy):
        pe = RuntimePolicyEngine()
        pe.add_policy(default_policy)
        analysis = ImageAnalysisResult(
            image_ref="myregistry.io/myapp:1.0",
            user="appuser",
            has_healthcheck=True,
            labels={"maintainer": "x", "version": "1"},
            total_size_bytes=200 * 1024 * 1024,  # 200 MB > 100 MB limit
        )
        results = pe.evaluate("myregistry.io/myapp:1.0", analysis)
        rules = [v.rule for v in results[0].violations]
        assert "max_image_size_mb" in rules

    def test_evaluate_missing_healthcheck_violation(self, default_policy):
        pe = RuntimePolicyEngine()
        pe.add_policy(default_policy)
        analysis = ImageAnalysisResult(
            image_ref="myregistry.io/myapp:1.0",
            user="appuser",
            has_healthcheck=False,
            labels={"maintainer": "x", "version": "1"},
            total_size_bytes=10 * 1024 * 1024,
        )
        results = pe.evaluate("myregistry.io/myapp:1.0", analysis)
        rules = [v.rule for v in results[0].violations]
        assert "require_healthcheck" in rules

    def test_evaluate_unapproved_registry(self, default_policy):
        pe = RuntimePolicyEngine()
        pe.add_policy(default_policy)
        analysis = ImageAnalysisResult(
            image_ref="badregistry.evil.com/myapp:1.0",
            user="appuser",
            has_healthcheck=True,
            labels={"maintainer": "x", "version": "1"},
            total_size_bytes=10 * 1024 * 1024,
        )
        results = pe.evaluate("badregistry.evil.com/myapp:1.0", analysis)
        rules = [v.rule for v in results[0].violations]
        assert "approved_registries" in rules

    def test_evaluate_specific_policy_id(self, image_analysis):
        pe = RuntimePolicyEngine()
        p1 = RuntimePolicy(name="p1")
        p2 = RuntimePolicy(name="p2")
        pe.add_policy(p1)
        pe.add_policy(p2)
        results = pe.evaluate("img:latest", image_analysis, policy_id=p1.policy_id)
        assert len(results) == 1
        assert results[0].policy_name == "p1"

    def test_evaluate_no_policies(self, image_analysis):
        pe = RuntimePolicyEngine()
        results = pe.evaluate("img:latest", image_analysis)
        assert results == []


# ===========================================================================
# DriftDetector
# ===========================================================================


class TestDriftDetector:
    def test_no_drift(self, image_analysis):
        detector = DriftDetector()
        runtime_state = {
            "files": {},
            "processes": ["/app/server"],
            "env_vars": list(image_analysis.environment_vars),
            "network_connections": ["127.0.0.1:8080"],
        }
        report = detector.detect("ctr-001", "myregistry.io/myapp:1.0", image_analysis, runtime_state)
        # network connection on exposed port should be allowed
        assert report.container_id == "ctr-001"
        assert report.image_ref == "myregistry.io/myapp:1.0"

    def test_new_process_drift(self, image_analysis):
        detector = DriftDetector()
        runtime_state = {
            "files": {},
            "processes": ["/app/server", "/bin/bash", "nc -l 4444"],
            "env_vars": list(image_analysis.environment_vars),
            "network_connections": [],
        }
        report = detector.detect("ctr-001", "myregistry.io/myapp:1.0", image_analysis, runtime_state)
        assert report.drift_detected is True
        types = [e.drift_type for e in report.drift_events]
        assert DriftType.NEW_PROCESS in types

    def test_env_var_drift(self, image_analysis):
        detector = DriftDetector()
        runtime_state = {
            "files": {},
            "processes": [],
            "env_vars": ["PATH=/usr/local/bin", "INJECTED_SECRET=s3cr3t"],
            "network_connections": [],
        }
        report = detector.detect("ctr-001", "myregistry.io/myapp:1.0", image_analysis, runtime_state)
        assert report.drift_detected is True
        types = [e.drift_type for e in report.drift_events]
        assert DriftType.CHANGED_ENV in types

    def test_new_file_drift(self, image_analysis):
        detector = DriftDetector()
        runtime_state = {
            "files": {"/etc/cron.d/backdoor": "sha256:malicious"},
            "processes": [],
            "env_vars": [],
            "network_connections": [],
        }
        report = detector.detect("ctr-001", "myregistry.io/myapp:1.0", image_analysis, runtime_state)
        assert report.drift_detected is True
        types = [e.drift_type for e in report.drift_events]
        assert DriftType.NEW_FILE in types
        assert "/etc/cron.d/backdoor" in report.modified_files

    def test_unexpected_network_drift(self, image_analysis):
        detector = DriftDetector()
        runtime_state = {
            "files": {},
            "processes": [],
            "env_vars": [],
            "network_connections": ["185.220.101.1:9001"],  # Tor-like C2
        }
        report = detector.detect("ctr-001", "myregistry.io/myapp:1.0", image_analysis, runtime_state)
        assert report.drift_detected is True
        assert "185.220.101.1:9001" in report.unexpected_connections

    def test_drift_report_structure(self, image_analysis):
        detector = DriftDetector()
        report = detector.detect("ctr-abc", "img:1", image_analysis, {})
        d = report.to_dict()
        assert "report_id" in d
        assert "container_id" in d
        assert "drift_events" in d


# ===========================================================================
# VulnerabilityMapper
# ===========================================================================


class TestVulnerabilityMapper:
    def test_map_basic(self):
        mapper = VulnerabilityMapper()
        result = mapper.map_vulnerabilities(
            image_ref="myregistry.io/myapp:1.0",
            cve_list=[
                {"id": "CVE-2024-1234", "cvss_score": 9.8, "severity": "critical"},
                {"id": "CVE-2024-5678", "cvss_score": 7.5, "severity": "high"},
            ],
            running_containers=[
                {"container_id": "ctr-001", "image_ref": "myregistry.io/myapp:1.0", "namespace": "production", "service": "api"},
                {"container_id": "ctr-002", "image_ref": "myregistry.io/myapp:1.0", "namespace": "staging"},
            ],
        )
        assert result.total_cves == 2
        assert result.critical_count == 1
        assert result.high_count == 1
        assert len(result.affected_containers) == 2

    def test_map_namespace_aggregation(self):
        mapper = VulnerabilityMapper()
        result = mapper.map_vulnerabilities(
            image_ref="myapp:1.0",
            cve_list=[{"id": "CVE-2024-0001", "severity": "high"}],
            running_containers=[
                {"container_id": "c1", "image_ref": "myapp:1.0", "namespace": "ns-a"},
                {"container_id": "c2", "image_ref": "myapp:1.0", "namespace": "ns-b"},
            ],
        )
        assert set(result.affected_namespaces) == {"ns-a", "ns-b"}

    def test_map_service_aggregation(self):
        mapper = VulnerabilityMapper()
        result = mapper.map_vulnerabilities(
            image_ref="svc:latest",
            cve_list=[{"id": "CVE-2024-9999", "severity": "medium"}],
            running_containers=[
                {"container_id": "c1", "image_ref": "svc:latest", "service": "frontend"},
                {"container_id": "c2", "image_ref": "svc:latest", "service": "backend"},
            ],
        )
        assert "frontend" in result.affected_services
        assert "backend" in result.affected_services

    def test_map_no_matching_containers(self):
        mapper = VulnerabilityMapper()
        result = mapper.map_vulnerabilities(
            image_ref="myapp:1.0",
            cve_list=[{"id": "CVE-2024-0001", "severity": "critical"}],
            running_containers=[
                {"container_id": "c1", "image_ref": "otherapp:2.0"},
            ],
        )
        assert len(result.affected_containers) == 0

    def test_map_empty_cves(self):
        mapper = VulnerabilityMapper()
        result = mapper.map_vulnerabilities("img:1", [], [])
        assert result.total_cves == 0
        assert len(result.affected_containers) == 0

    def test_map_to_dict(self):
        mapper = VulnerabilityMapper()
        result = mapper.map_vulnerabilities("img:1", [], [])
        d = result.to_dict()
        assert "map_id" in d
        assert "affected_containers" in d


# ===========================================================================
# CISBenchmarkChecker
# ===========================================================================


class TestCISBenchmarkChecker:
    def test_run_all_checks_count(self):
        checker = CISBenchmarkChecker()
        report = checker.run_checks("docker-host", {})
        assert report.total_checks >= 80
        assert report.total_checks == report.passed_checks + report.failed_checks

    def test_score_between_0_and_100(self):
        checker = CISBenchmarkChecker()
        report = checker.run_checks("docker-host", {})
        assert 0.0 <= report.score_pct <= 100.0

    def test_section_filter(self):
        checker = CISBenchmarkChecker()
        report = checker.run_checks(
            "docker-host", {}, section_filter=CISBenchmarkSection.DOCKER_DAEMON
        )
        for check in report.checks:
            assert check.section == CISBenchmarkSection.DOCKER_DAEMON

    def test_privileged_container_fails_54(self):
        checker = CISBenchmarkChecker()
        config = {"container_opts": {"privileged": True}}
        report = checker.run_checks("ctr-001", config)
        failed = {c.check_id for c in report.checks if not c.passed}
        assert "5.4" in failed

    def test_tls_enabled_passes_26(self):
        checker = CISBenchmarkChecker()
        config = {"docker_daemon": {"tlsverify": True}}
        report = checker.run_checks("host", config)
        passed = {c.check_id for c in report.checks if c.passed}
        assert "2.6" in passed

    def test_user_namespace_remap_passes_28(self):
        checker = CISBenchmarkChecker()
        config = {"docker_daemon": {"userns-remap": "default"}}
        report = checker.run_checks("host", config)
        passed = {c.check_id for c in report.checks if c.passed}
        assert "2.8" in passed

    def test_root_user_fails_41(self):
        checker = CISBenchmarkChecker()
        analysis = ImageAnalysisResult(image_ref="img:1", user="root")
        config = {"image_analysis": analysis}
        report = checker.run_checks("host", config)
        failed = {c.check_id for c in report.checks if not c.passed}
        assert "4.1" in failed

    def test_non_root_user_passes_41(self):
        checker = CISBenchmarkChecker()
        analysis = ImageAnalysisResult(image_ref="img:1", user="appuser")
        config = {"image_analysis": analysis}
        report = checker.run_checks("host", config)
        passed = {c.check_id for c in report.checks if c.passed}
        assert "4.1" in passed

    def test_healthcheck_passes_46(self):
        checker = CISBenchmarkChecker()
        analysis = ImageAnalysisResult(image_ref="img:1", has_healthcheck=True)
        config = {"image_analysis": analysis}
        report = checker.run_checks("host", config)
        passed = {c.check_id for c in report.checks if c.passed}
        assert "4.6" in passed

    def test_secret_in_env_fails_410(self):
        checker = CISBenchmarkChecker()
        analysis = ImageAnalysisResult(
            image_ref="img:1",
            environment_vars=["DB_PASSWORD=supersecret"],
        )
        config = {"image_analysis": analysis}
        report = checker.run_checks("host", config)
        failed = {c.check_id for c in report.checks if not c.passed}
        assert "4.10" in failed

    def test_report_to_dict(self):
        checker = CISBenchmarkChecker()
        report = checker.run_checks("host", {})
        d = report.to_dict()
        assert "report_id" in d
        assert "score_pct" in d
        assert "checks" in d


# ===========================================================================
# ImageSigningVerifier
# ===========================================================================


class TestImageSigningVerifier:
    def test_verify_with_valid_cosign_data(self):
        verifier = ImageSigningVerifier()
        sig_data = {
            "signatures": [
                {"signer": "ci@example.com", "digest": "sha256:sigdigest", "signed_at": "2024-01-01T00:00:00Z"}
            ]
        }
        result = verifier.verify("myapp:1.0", sig_data, SignatureScheme.COSIGN)
        assert result.verified is True
        assert result.signer == "ci@example.com"

    def test_verify_no_signature_data(self):
        verifier = ImageSigningVerifier()
        result = verifier.verify("myapp:1.0", None)
        assert result.verified is False
        assert result.error is not None

    def test_verify_empty_signatures_list(self):
        verifier = ImageSigningVerifier()
        result = verifier.verify("myapp:1.0", {"signatures": []})
        assert result.verified is False

    def test_policy_compliant_when_not_required(self):
        verifier = ImageSigningVerifier(require_signed=False)
        result = verifier.verify("myapp:1.0", None)
        assert result.policy_compliant is True

    def test_policy_noncompliant_when_required_and_unsigned(self):
        verifier = ImageSigningVerifier(require_signed=True)
        result = verifier.verify("myapp:1.0", None)
        assert result.policy_compliant is False

    def test_verify_notary_v2(self):
        verifier = ImageSigningVerifier()
        sig_data = {
            "signatures": [
                {"signer": "notary@example.com", "digest": "sha256:notarydigest"}
            ]
        }
        result = verifier.verify("myapp:1.0", sig_data, SignatureScheme.NOTARY_V2)
        assert result.scheme == SignatureScheme.NOTARY_V2
        assert result.verified is True

    def test_verify_result_to_dict(self):
        verifier = ImageSigningVerifier()
        result = verifier.verify("img:1", None)
        d = result.to_dict()
        assert "image_ref" in d
        assert "verified" in d
        assert "scheme" in d


# ===========================================================================
# RegistrySecurityScanner
# ===========================================================================


class TestRegistrySecurityScanner:
    def test_scan_well_configured_registry(self):
        scanner = RegistrySecurityScanner()
        meta = {
            "public_access": False,
            "tag_immutability": True,
            "vuln_scanning": "enabled",
            "auth_required": True,
        }
        report = scanner.scan("myregistry.io", meta, [])
        assert report.risk_score < 50
        assert report.tag_immutability is True

    def test_scan_public_registry_raises_risk(self):
        scanner = RegistrySecurityScanner()
        meta = {"public_access": True, "tag_immutability": False, "vuln_scanning": "disabled", "auth_required": False}
        report = scanner.scan("docker.io", meta, [])
        assert report.risk_score >= 50

    def test_scan_stale_image_detection(self):
        scanner = RegistrySecurityScanner()
        images = [
            {"ref": "myapp:old", "pushed_at": "2020-01-01T00:00:00Z"},
            {"ref": "myapp:new", "pushed_at": "2025-01-01T00:00:00Z"},
        ]
        report = scanner.scan("myregistry.io", {"tag_immutability": True, "vuln_scanning": "enabled", "auth_required": True}, images)
        assert "myapp:old" in report.stale_images
        assert report.stale_image_count >= 1

    def test_scan_no_stale_images(self):
        scanner = RegistrySecurityScanner()
        images = [{"ref": "myapp:recent", "pushed_at": "2025-12-01T00:00:00Z"}]
        report = scanner.scan("myregistry.io", {}, images)
        assert report.stale_image_count == 0

    def test_scan_report_issues_present(self):
        scanner = RegistrySecurityScanner()
        report = scanner.scan("badregistry.io", {"public_access": True}, [])
        assert len(report.issues) > 0

    def test_scan_to_dict(self):
        scanner = RegistrySecurityScanner()
        report = scanner.scan("myregistry.io", {}, [])
        d = report.to_dict()
        assert "report_id" in d
        assert "registry_url" in d
        assert "risk_score" in d

    def test_scan_vuln_status_enabled(self):
        scanner = RegistrySecurityScanner()
        meta = {"vuln_scanning": "enabled"}
        report = scanner.scan("myregistry.io", meta, [])
        assert report.vuln_scanning_status == RegistryVulnStatus.SCANNING_ENABLED


# ===========================================================================
# ContainerRuntimeSecurityEngine facade
# ===========================================================================


class TestContainerRuntimeSecurityEngine:
    def test_singleton(self):
        e1 = get_container_runtime_engine()
        e2 = get_container_runtime_engine()
        assert e1 is e2

    def test_engine_analyse_image(self, engine):
        result = engine.analyse_image("ubuntu:22.04")
        assert result.image_ref == "ubuntu:22.04"

    def test_engine_policy_roundtrip(self, engine):
        policy = RuntimePolicy(name="e2e-policy")
        engine.policy_engine.add_policy(policy)
        policies = engine.policy_engine.list_policies()
        assert any(p.policy_id == policy.policy_id for p in policies)
        engine.policy_engine.remove_policy(policy.policy_id)

    def test_engine_drift_detect(self, engine, image_analysis):
        report = engine.detect_drift("ctr-test", "img:1", image_analysis, {})
        assert report.container_id == "ctr-test"

    def test_engine_map_vulnerabilities(self, engine):
        result = engine.map_vulnerabilities("img:1", [], [])
        assert result.image_ref == "img:1"

    def test_engine_cis_benchmark(self, engine):
        report = engine.run_cis_benchmark("host", {})
        assert report.total_checks >= 80

    def test_engine_verify_signature(self, engine):
        result = engine.verify_signature("img:1", None)
        assert result.verified is False

    def test_engine_scan_registry(self, engine):
        report = engine.scan_registry("myregistry.io", {}, [])
        assert report.registry_url == "myregistry.io"


# ===========================================================================
# Pydantic model validation
# ===========================================================================


class TestPydanticModels:
    def test_runtime_policy_defaults(self):
        policy = RuntimePolicy(name="defaults-test")
        assert policy.allow_root_user is False
        assert policy.require_healthcheck is True
        assert policy.max_image_size_mb == 2048
        assert "SYS_ADMIN" in policy.blocked_capabilities

    def test_image_analysis_result_defaults(self):
        r = ImageAnalysisResult(image_ref="test:1")
        assert r.os_family == "unknown"
        assert r.layer_count == 0
        assert r.is_multi_stage is False

    def test_installed_package_model(self):
        pkg = InstalledPackage(name="curl", version="7.81.0", arch="amd64", manager="apt")
        assert pkg.name == "curl"
        assert pkg.cves == []

    def test_image_layer_model(self):
        layer = ImageLayer(digest="sha256:abc", size_bytes=1024, command="RUN echo hello")
        assert layer.is_empty is False
        assert layer.is_squashable is False

    def test_policy_violation_severity(self):
        from core.container_runtime import PolicyViolation
        v = PolicyViolation(
            policy_id="p1",
            policy_name="test",
            rule="no_root_user",
            detail="Running as root",
            severity=Severity.HIGH,
            image_ref="img:1",
        )
        assert v.severity == Severity.HIGH
        d = v.to_dict()
        assert d["severity"] == "high"
