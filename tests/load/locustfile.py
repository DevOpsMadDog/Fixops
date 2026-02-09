"""
ALdeci / FixOps — Locust Load Test Suite.

Scenarios:
  1. SBOM upload (POST /api/v1/upload/sbom)
  2. Graph queries (GET /api/v1/graph/stats, /api/v1/graph/nodes)
  3. CVE / feed search (GET /api/v1/feeds/cve/search)
  4. Multi-LLM copilot (POST /api/v1/copilot/ask)
  5. Brain pipeline trigger (POST /api/v1/brain/pipeline/run)

Run:
  locust -f tests/load/locustfile.py --host http://localhost:8000
"""
from __future__ import annotations

import json
import os
import random
import uuid

from locust import HttpUser, between, tag, task

API_KEY = os.getenv("FIXOPS_LOAD_TEST_KEY", "fixops_test.loadtestkey123")

# ---------------------------------------------------------------------------
# Sample payloads
# ---------------------------------------------------------------------------

_SBOM_SMALL = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": f"urn:uuid:{uuid.uuid4()}",
    "version": 1,
    "metadata": {"component": {"name": "load-test-app", "version": "1.0.0", "type": "application"}},
    "components": [
        {"type": "library", "name": f"lib-{i}", "version": f"0.{i}.0",
         "purl": f"pkg:npm/lib-{i}@0.{i}.0"}
        for i in range(20)
    ],
}

_CVE_IDS = [f"CVE-2024-{n}" for n in range(1000, 1050)]

_COPILOT_QUESTIONS = [
    "What are the critical vulnerabilities in my SBOM?",
    "Explain CVE-2024-1234 and its impact on my infrastructure",
    "What is the EPSS score trend for log4j?",
    "Recommend remediation priority for my top 5 CVEs",
    "Summarize my SOC2 compliance posture",
]


# ---------------------------------------------------------------------------
# Load test user
# ---------------------------------------------------------------------------

class ALdeciUser(HttpUser):
    """Simulates a typical ALdeci platform user."""

    wait_time = between(0.5, 2.0)

    def on_start(self):
        self.headers = {
            "X-API-Key": API_KEY,
            "Content-Type": "application/json",
            "X-Org-ID": "load-test-org",
        }

    # --- Health & warm-up ---------------------------------------------------

    @tag("health")
    @task(5)
    def health_check(self):
        self.client.get("/health", headers=self.headers, name="/health")

    # --- SBOM ingestion -----------------------------------------------------

    @tag("sbom", "write")
    @task(3)
    def upload_sbom(self):
        payload = dict(_SBOM_SMALL)
        payload["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
        self.client.post(
            "/api/v1/upload/sbom",
            json=payload,
            headers=self.headers,
            name="/api/v1/upload/sbom",
        )

    # --- Graph queries ------------------------------------------------------

    @tag("graph", "read")
    @task(4)
    def graph_stats(self):
        self.client.get(
            "/api/v1/graph/stats",
            headers=self.headers,
            name="/api/v1/graph/stats",
        )

    @tag("graph", "read")
    @task(3)
    def graph_nodes(self):
        self.client.get(
            "/api/v1/graph/nodes",
            params={"type": random.choice(["package", "vulnerability", "asset"]), "limit": 50},
            headers=self.headers,
            name="/api/v1/graph/nodes",
        )

    # --- CVE / feed search --------------------------------------------------

    @tag("feeds", "read")
    @task(4)
    def cve_search(self):
        cve_id = random.choice(_CVE_IDS)
        self.client.get(
            "/api/v1/feeds/cve/search",
            params={"q": cve_id},
            headers=self.headers,
            name="/api/v1/feeds/cve/search",
        )

    @tag("feeds", "read")
    @task(2)
    def epss_scores(self):
        self.client.get(
            "/api/v1/feeds/epss/scores",
            params={"limit": 25},
            headers=self.headers,
            name="/api/v1/feeds/epss/scores",
        )

    # --- Multi-LLM copilot -------------------------------------------------

    @tag("copilot", "write")
    @task(2)
    def copilot_ask(self):
        question = random.choice(_COPILOT_QUESTIONS)
        self.client.post(
            "/api/v1/copilot/ask",
            json={"question": question, "context": "load-test"},
            headers=self.headers,
            name="/api/v1/copilot/ask",
        )

    # --- Brain pipeline -----------------------------------------------------

    @tag("brain", "write")
    @task(1)
    def brain_pipeline_run(self):
        self.client.post(
            "/api/v1/brain/pipeline/run",
            json={"org_id": "load-test-org", "mode": "quick"},
            headers=self.headers,
            name="/api/v1/brain/pipeline/run",
        )

    # --- Findings & dashboard -----------------------------------------------

    @tag("findings", "read")
    @task(3)
    def list_findings(self):
        self.client.get(
            "/api/v1/findings",
            params={"limit": 25, "severity": random.choice(["critical", "high", "medium"])},
            headers=self.headers,
            name="/api/v1/findings",
        )

    @tag("dashboard", "read")
    @task(2)
    def nerve_center(self):
        self.client.get(
            "/api/v1/nerve-center/overview",
            headers=self.headers,
            name="/api/v1/nerve-center/overview",
        )

