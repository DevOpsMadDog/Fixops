"""Verification tests for Tier 2.4: Container Scanning enhancements."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.container_scanner import (
    ContainerImageScanner,
    HELM_CHART_RULES,
    LAYER_SECRET_PATTERNS,
)


def test_helm_chart_rules_exist():
    assert len(HELM_CHART_RULES) >= 8, f"Expected >=8 Helm rules, got {len(HELM_CHART_RULES)}"


def test_layer_secret_patterns_exist():
    assert len(LAYER_SECRET_PATTERNS) >= 15, f"Expected >=15 patterns, got {len(LAYER_SECRET_PATTERNS)}"


def test_helm_scan_privileged_container():
    scanner = ContainerImageScanner()
    helm = "\n".join([
        "apiVersion: v1",
        "name: my-app",
        "---",
        "kind: Deployment",
        "spec:",
        "  template:",
        "    spec:",
        "      containers:",
        "      - name: app",
        "        image: myapp:latest",
        "        securityContext:",
        "          privileged: true",
        "          runAsUser: 0",
    ])
    result = scanner.scan_helm_chart(helm, "deploy.yaml")
    assert result.total_findings >= 3, f"Expected >=3 findings, got {result.total_findings}"
    titles = [f.title for f in result.findings]
    assert any("Privileged" in t for t in titles), f"Missing privileged finding: {titles}"
    assert any("Root" in t or "root" in t.lower() for t in titles), f"Missing root finding: {titles}"


def test_helm_scan_deprecated_api():
    scanner = ContainerImageScanner()
    chart = "apiVersion: v1\nname: old-chart\nversion: 0.1.0\n"
    result = scanner.scan_helm_chart(chart, "Chart.yaml")
    titles = [f.title for f in result.findings]
    assert any("Deprecated" in t or "API" in t for t in titles), f"Missing deprecated API finding: {titles}"


def test_layer_secrets_aws_key():
    scanner = ContainerImageScanner()
    dockerfile = "\n".join([
        "FROM python:3.10",
        "ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "COPY .env /app/.env",
        "COPY id_rsa /root/.ssh/id_rsa",
        "ENV STRIPE_SECRET=STRIPE_SECRET_TEST_FIXTURE",
    ])
    result = scanner.scan_layer_secrets(dockerfile, "Dockerfile")
    assert result.total_findings >= 3, f"Expected >=3 findings, got {result.total_findings}"
    names = [f.title for f in result.findings]
    assert any("AWS" in n for n in names), f"Missing AWS secret finding: {names}"


def test_layer_secrets_clean_dockerfile():
    scanner = ContainerImageScanner()
    dockerfile = "\n".join([
        "FROM python:3.10-slim",
        "WORKDIR /app",
        "COPY requirements.txt .",
        "RUN pip install -r requirements.txt",
        "COPY . .",
        "CMD [\"python\", \"app.py\"]",
    ])
    result = scanner.scan_layer_secrets(dockerfile, "Dockerfile")
    assert result.total_findings == 0, f"Expected 0 findings for clean Dockerfile, got {result.total_findings}"


def test_scan_result_structure():
    scanner = ContainerImageScanner()
    result = scanner.scan_helm_chart("apiVersion: v2\nname: safe\n", "Chart.yaml")
    d = result.to_dict()
    assert "scan_id" in d
    assert "findings" in d
    assert "by_severity" in d
    assert d["target"] == "Chart.yaml"


def test_grype_available_property():
    scanner = ContainerImageScanner()
    assert hasattr(scanner, "grype_available")


if __name__ == "__main__":
    test_helm_chart_rules_exist()
    test_layer_secret_patterns_exist()
    test_helm_scan_privileged_container()
    test_helm_scan_deprecated_api()
    test_layer_secrets_aws_key()
    test_layer_secrets_clean_dockerfile()
    test_scan_result_structure()
    test_grype_available_property()
    print("ALL TESTS PASSED")

