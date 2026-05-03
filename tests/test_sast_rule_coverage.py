"""Tests for GET /api/v1/sast/rules/coverage endpoint."""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.sast_router import router


def _make_client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ---------------------------------------------------------------------------
# 1. Endpoint responds 200 with correct top-level keys
# ---------------------------------------------------------------------------
def test_rule_coverage_200_and_shape():
    client = _make_client()
    resp = client.get("/api/v1/sast/rules/coverage")
    assert resp.status_code == 200
    data = resp.json()
    for key in ("total_rules", "by_severity", "by_cwe", "by_language", "owasp_coverage", "cwe_list"):
        assert key in data, f"Missing key: {key}"


# ---------------------------------------------------------------------------
# 2. total_rules is positive and severity buckets are non-negative
# ---------------------------------------------------------------------------
def test_rule_coverage_total_rules_positive():
    data = _make_client().get("/api/v1/sast/rules/coverage").json()
    assert data["total_rules"] > 0
    for sev, count in data["by_severity"].items():
        assert count >= 0, f"Negative count for severity {sev}"


# ---------------------------------------------------------------------------
# 3. by_cwe contains known critical CWEs (SQL injection)
# ---------------------------------------------------------------------------
def test_rule_coverage_known_cwes_present():
    data = _make_client().get("/api/v1/sast/rules/coverage").json()
    by_cwe = data["by_cwe"]
    assert "CWE-89" in by_cwe, "CWE-89 (SQL Injection) missing from coverage"
    assert by_cwe["CWE-89"] >= 1


# ---------------------------------------------------------------------------
# 4. by_language contains expected languages with positive counts
# ---------------------------------------------------------------------------
def test_rule_coverage_languages_present():
    data = _make_client().get("/api/v1/sast/rules/coverage").json()
    by_lang = data["by_language"]
    for lang in ("python", "javascript", "java"):
        assert lang in by_lang, f"Language '{lang}' missing from coverage"
        assert by_lang[lang] > 0


# ---------------------------------------------------------------------------
# 5. owasp_coverage has all 10 OWASP categories with positive counts
# ---------------------------------------------------------------------------
def test_rule_coverage_owasp_all_categories():
    data = _make_client().get("/api/v1/sast/rules/coverage").json()
    owasp = data["owasp_coverage"]
    expected_prefixes = [f"A{i:02d}:" for i in range(1, 11)]
    for prefix in expected_prefixes:
        matching = [k for k in owasp if k.startswith(prefix)]
        assert matching, f"No OWASP category starting with {prefix}"
        assert owasp[matching[0]] > 0, f"Zero rules for {matching[0]}"


# ---------------------------------------------------------------------------
# 6. cwe_list is sorted and matches by_cwe keys exactly
# ---------------------------------------------------------------------------
def test_rule_coverage_cwe_list_sorted_and_complete():
    data = _make_client().get("/api/v1/sast/rules/coverage").json()
    cwe_list = data["cwe_list"]
    by_cwe = data["by_cwe"]
    assert cwe_list == sorted(by_cwe.keys()), "cwe_list is not sorted or incomplete"
    assert len(cwe_list) == len(by_cwe)
