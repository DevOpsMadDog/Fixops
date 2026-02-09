#!/usr/bin/env python3
"""Comprehensive API test covering all UI operations including POST/PUT."""
import requests
import json
import time

BASE_URL = "http://localhost:8000"
headers = {"X-API-Key": "demo-token", "Content-Type": "application/json"}
_timestamp = int(time.time() * 1000)  # Unique suffix for test data

def test_endpoint(method, url, data=None, name=""):
    # Add unique suffix to name fields if present
    if data and isinstance(data, dict) and "name" in data:
        data = {**data, "name": f"{data['name']}_{_timestamp}"}
    try:
        if method == "GET":
            resp = requests.get(f"{BASE_URL}{url}", headers=headers, timeout=10)
        elif method == "POST":
            resp = requests.post(f"{BASE_URL}{url}", headers=headers, json=data, timeout=10)
        elif method == "PUT":
            resp = requests.put(f"{BASE_URL}{url}", headers=headers, json=data, timeout=10)
        else:
            return "SKIP", 0, "Unknown method"
        
        status = resp.status_code
        if status in [200, 201]:
            return "OK", status, None
        else:
            return "ERR", status, resp.text[:100].replace("\n", " ")
    except Exception as e:
        return "EXC", 0, str(e)[:80]

tests = [
    # Dashboard
    ("GET", "/health", None, "Health"),
    ("GET", "/api/v1/analytics/dashboard/overview?org_id=default", None, "Dashboard Overview"),
    ("GET", "/api/v1/analytics/dashboard/trends?org_id=default", None, "Dashboard Trends"),
    ("GET", "/api/v1/analytics/dashboard/top-risks?org_id=default", None, "Dashboard Top Risks"),
    ("GET", "/api/v1/analytics/dashboard/compliance-status?org_id=default", None, "Dashboard Compliance"),
    
    # Copilot
    ("GET", "/api/v1/copilot/health", None, "Copilot Health"),
    ("POST", "/api/v1/copilot/sessions", {}, "Copilot Create Session"),
    
    # MPTE - Core
    ("GET", "/api/v1/mpte/requests", None, "MPTE List Requests"),
    ("POST", "/api/v1/mpte/requests", {
        "finding_id": "test-finding-123",
        "target_url": "http://test.example.com",
        "vulnerability_type": "xss",
        "test_case": "test-case-1",
        "priority": "medium"
    }, "MPTE Create Request"),
    ("GET", "/api/v1/mpte/results", None, "MPTE List Results"),
    ("GET", "/api/v1/mpte/configs", None, "MPTE List Configs"),
    ("POST", "/api/v1/mpte/verify", {
        "finding_id": "test-finding-456",
        "target_url": "http://verify.example.com",
        "vulnerability_type": "sqli",
        "evidence": "test evidence"
    }, "MPTE Verify"),
    
    # Micro Pentest
    ("POST", "/api/v1/micro-pentest/run", {
        "cve_ids": ["CVE-2021-44228"],
        "target_urls": ["http://localhost:8080"]
    }, "Micro Pentest Run"),
    
    # LLM
    ("GET", "/api/v1/llm/status", None, "LLM Status"),
    ("GET", "/api/v1/llm/providers", None, "LLM Providers"),
    
    # Enhanced
    ("POST", "/api/v1/enhanced/analysis", {
        "service_name": "security",
        "context": {"test": True}
    }, "Enhanced Analysis"),
    ("GET", "/api/v1/enhanced/capabilities", None, "Enhanced Capabilities"),
    
    # Feeds
    ("GET", "/api/v1/feeds/epss", None, "Feeds EPSS"),
    ("GET", "/api/v1/feeds/kev", None, "Feeds KEV"),
    ("GET", "/api/v1/feeds/exploits", None, "Feeds Exploits"),
    
    # Deduplication
    ("GET", "/api/v1/deduplication/clusters?org_id=default", None, "Dedup Clusters"),
    ("POST", "/api/v1/deduplication/process", {
        "run_id": "test-run-123",
        "org_id": "default",
        "source": "sarif",
        "finding": {"cve_id": "CVE-2021-44228", "severity": "critical"}
    }, "Dedup Process"),
    
    # GNN/Graph
    ("GET", "/graph/", None, "Graph"),
    ("POST", "/api/v1/algorithms/gnn/attack-surface", {
        "infrastructure": [{"id": "node1", "type": "compute", "properties": {}, "risk_score": 0.5}],
        "connections": [],
        "vulnerabilities": [],
        "max_paths": 10
    }, "GNN Attack Surface"),
    ("POST", "/api/v1/algorithms/gnn/critical-nodes", {
        "infrastructure": [{"id": "node1", "type": "compute", "properties": {}, "risk_score": 0.5}],
        "connections": [],
        "top_k": 10
    }, "GNN Critical Nodes"),
    
    # Reachability
    ("POST", "/api/v1/reachability/analyze", {
        "repository": {"url": "https://github.com/octocat/Hello-World", "branch": "master"},
        "vulnerability": {
            "cve_id": "CVE-2021-44228",
            "component_name": "log4j",
            "component_version": "2.14.0",
            "severity": "critical"
        },
        "async_analysis": True
    }, "Reachability Analyze"),
    
    # Webhooks
    ("GET", "/api/v1/webhooks/outbox", None, "Webhooks Outbox"),
    ("GET", "/api/v1/webhooks/events", None, "Webhooks Events"),
    ("GET", "/api/v1/webhooks/mappings", None, "Webhooks Mappings"),
    ("GET", "/api/v1/webhooks/drift", None, "Webhooks Drift"),
    
    # Teams
    ("GET", "/api/v1/teams", None, "Teams List"),
    ("POST", "/api/v1/teams", {"name": "Test Team", "description": "A test team"}, "Teams Create"),
    
    # Users
    ("GET", "/api/v1/users", None, "Users List"),
    
    # Policies
    ("GET", "/api/v1/policies", None, "Policies List"),
    ("POST", "/api/v1/policies", {
        "name": "Test Policy", 
        "description": "desc", 
        "policy_type": "compliance",
        "rules": {"min_severity": "high"}
    }, "Policies Create"),
    
    # Workflows
    ("GET", "/api/v1/workflows", None, "Workflows List"),
    ("POST", "/api/v1/workflows", {"name": "Test Flow", "description": "workflow"}, "Workflows Create"),
    
    # Reports
    ("GET", "/api/v1/reports", None, "Reports List"),
    ("POST", "/api/v1/reports", {
        "name": "Test Report",
        "report_type": "compliance",
        "format": "pdf",
        "parameters": {}
    }, "Reports Create"),
    
    # Audit
    ("GET", "/api/v1/audit/logs", None, "Audit Logs"),
    ("GET", "/api/v1/audit/compliance/frameworks", None, "Compliance Frameworks"),
    
    # Inventory
    ("GET", "/api/v1/inventory/applications", None, "Inventory Apps"),
    
    # Remediation
    ("GET", "/api/v1/remediation/tasks?org_id=default", None, "Remediation Tasks"),
    ("POST", "/api/v1/remediation/tasks", {
        "cluster_id": "test-cluster-123",
        "org_id": "default",
        "app_id": "test-app",
        "title": "Fix vulnerability",
        "severity": "high"
    }, "Remediation Create Task"),
    
    # Evidence
    ("GET", "/evidence/", None, "Evidence List"),
    
    # Secrets
    ("GET", "/api/v1/secrets", None, "Secrets List"),
    
    # IaC
    ("GET", "/api/v1/iac", None, "IaC List"),
    ("POST", "/api/v1/iac/scan/content", {
        "content": "resource aws_s3_bucket test {}",
        "filename": "main.tf"
    }, "IaC Scan"),
    
    # Integrations
    ("GET", "/api/v1/integrations", None, "Integrations List"),
    ("POST", "/api/v1/integrations", {
        "name": "test-integration",
        "integration_type": "github",
        "config": {"url": "https://github.com"}
    }, "Integrations Create"),
    
    # Marketplace
    ("GET", "/api/v1/marketplace/browse", None, "Marketplace Browse"),
    
    # Monte Carlo
    ("POST", "/api/v1/algorithms/monte-carlo/quantify", {
        "cve_ids": ["CVE-2021-44228"],
        "simulations": 100
    }, "Monte Carlo Quantify"),
    
    # Predictions
    ("POST", "/api/v1/predictions/risk-trajectory", {
        "cve_ids": ["CVE-2021-44228"]
    }, "Predictions Risk Trajectory"),
    
]

print("=" * 70)
print("COMPREHENSIVE UI API TEST")
print("=" * 70)

passed = 0
failed = 0
errors = []

for method, url, data, name in tests:
    result, status, error = test_endpoint(method, url, data, name)
    if result == "OK":
        print(f"✓ {name}: {status}")
        passed += 1
    else:
        print(f"✗ {name}: {status} - {error}")
        failed += 1
        errors.append((name, method, url, status, error))

print("=" * 70)
print(f"TOTAL: {passed}/{passed+failed} passed ({100*passed/(passed+failed):.1f}%)")
print("=" * 70)

if errors:
    print("\nFAILED ENDPOINTS:")
    for name, method, url, status, error in errors:
        print(f"  {method} {url}")
        print(f"    -> {status}: {error}")
