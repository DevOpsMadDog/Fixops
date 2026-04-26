"""Tests for GAP-019 — AI-generated code scanner.

Covers:
  - sast_engine.scan_snippet (findings, caching, language support, validation)
  - ai_security_advisor_engine.analyze_ai_generated (SAST + AI risks + combined score)
  - ai_code_scanner_router (4 endpoints via FastAPI TestClient)
  - Org-id isolation
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

# Ensure suite paths on sys.path (sitecustomize does this in normal runs)
ROOT = Path(__file__).resolve().parents[1]
for sub in ("suite-core", "suite-api"):
    p = str(ROOT / sub)
    if p not in sys.path:
        sys.path.insert(0, p)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    """Point the snippet-scan SQLite DB at a tmp path for isolation."""
    from core import sast_engine

    db = tmp_path / f"snippet_{uuid.uuid4().hex[:8]}.db"
    sast_engine._snippet_set_db_path(str(db))
    yield db
    # Reset back to default for other tests (module-level global)
    sast_engine._SNIPPET_DB_PATH = None


@pytest.fixture
def advisor(isolated_db):
    from core.ai_security_advisor_engine import AISecurityAdvisorEngine

    # Use a tmp advisor DB too so we do not pollute the default
    return AISecurityAdvisorEngine(db_path=str(isolated_db) + ".advisor.db")


@pytest.fixture
def client(isolated_db, monkeypatch):
    """TestClient for the ai_code_scanner router with auth disabled via env."""
    # Auth is enforced by api_key_auth; supply a token via env for all requests
    monkeypatch.setenv("FIXOPS_API_TOKEN", "test-token-123")

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from apps.api.ai_code_scanner_router import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


HEADERS = {"X-API-Key": "test-token-123"}


# ---------------------------------------------------------------------------
# 1. scan_snippet: basic findings
# ---------------------------------------------------------------------------


def test_scan_snippet_detects_python_hardcoded_secret(isolated_db):
    from core.sast_engine import scan_snippet

    code = 'API_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
    out = scan_snippet(org_id="org-A", code=code, language="python")

    assert out["org_id"] == "org-A"
    assert out["language"] == "python"
    assert out["source_hint"] == "ai_generated"
    assert out["cached"] is False
    assert out["findings_count"] >= 1
    # Hardcoded secret → SAST-006 / CWE-798
    assert any(
        f.get("cwe_id") == "CWE-798" or "Hardcoded" in f.get("title", "")
        for f in out["findings"]
    )


def test_scan_snippet_empty_for_clean_code(isolated_db):
    from core.sast_engine import scan_snippet

    code = "def add(a, b):\n    return a + b\n"
    out = scan_snippet(org_id="org-A", code=code, language="python")
    assert out["findings_count"] == 0
    assert out["findings"] == []


def test_scan_snippet_sha256_cache_returns_same_findings(isolated_db):
    from core.sast_engine import scan_snippet

    code = 'password = "hunter2hunter2"\n'
    first = scan_snippet(org_id="org-A", code=code, language="python")
    second = scan_snippet(org_id="org-A", code=code, language="python")

    assert first["snippet_sha256"] == second["snippet_sha256"]
    assert first["cached"] is False
    assert second["cached"] is True
    assert first["findings"] == second["findings"]


def test_scan_snippet_python_os_system(isolated_db):
    from core.sast_engine import scan_snippet

    code = 'import os\nos.system("ls " + user_input)\n'
    out = scan_snippet(org_id="org-A", code=code, language="python")
    assert out["findings_count"] >= 1
    # SAST-004 Command Injection CWE-78
    assert any(f.get("cwe_id") == "CWE-78" for f in out["findings"])


def test_scan_snippet_javascript_language(isolated_db):
    from core.sast_engine import scan_snippet

    # JS XSS via innerHTML
    code = 'document.getElementById("x").innerHTML = userInput;\n'
    out = scan_snippet(org_id="org-A", code=code, language="javascript")
    assert out["language"] == "javascript"
    # SAST-003 XSS
    assert any("CWE-79" == f.get("cwe_id") for f in out["findings"])


def test_scan_snippet_go_weak_crypto(isolated_db):
    from core.sast_engine import scan_snippet

    code = 'package main\nimport "crypto/md5"\nfunc h() { md5.New() }\n'
    out = scan_snippet(org_id="org-A", code=code, language="go")
    assert out["language"] == "go"
    # SAST-008 weak crypto
    assert any(f.get("cwe_id") == "CWE-327" for f in out["findings"])


def test_scan_snippet_invalid_org_id_raises(isolated_db):
    from core.sast_engine import scan_snippet

    with pytest.raises(ValueError):
        scan_snippet(org_id="", code="x=1", language="python")


def test_scan_snippet_invalid_language_raises(isolated_db):
    from core.sast_engine import scan_snippet

    with pytest.raises(ValueError):
        scan_snippet(org_id="org-A", code="x=1", language="")


def test_scan_snippet_source_hint_persisted(isolated_db):
    from core.sast_engine import scan_snippet, list_snippet_scans

    scan_snippet(
        org_id="org-A",
        code='api_key = "AKIATESTVALUE1234567"\n',
        language="python",
        source_hint="copilot",
    )
    history = list_snippet_scans("org-A")
    assert history
    assert history[0]["source_hint"] == "copilot"


# ---------------------------------------------------------------------------
# 2. Org-id isolation
# ---------------------------------------------------------------------------


def test_scan_snippet_org_id_isolation(isolated_db):
    from core.sast_engine import scan_snippet, list_snippet_scans

    scan_snippet(org_id="org-A", code='password="abcd1234"\n', language="python")
    scan_snippet(org_id="org-B", code='x = 1\n', language="python")

    a = list_snippet_scans("org-A")
    b = list_snippet_scans("org-B")
    assert len(a) == 1
    assert len(b) == 1
    assert a[0]["org_id"] == "org-A"
    assert b[0]["org_id"] == "org-B"


def test_scan_snippet_cache_is_per_org(isolated_db):
    from core.sast_engine import scan_snippet

    code = 'password = "abcd1234"\n'
    a = scan_snippet(org_id="org-A", code=code, language="python")
    # Same code, different org → must NOT be cached
    b = scan_snippet(org_id="org-B", code=code, language="python")
    assert a["snippet_sha256"] == b["snippet_sha256"]
    assert a["cached"] is False
    assert b["cached"] is False


# ---------------------------------------------------------------------------
# 3. analyze_ai_generated — AI-specific risks
# ---------------------------------------------------------------------------


def test_analyze_detects_eval_and_os_system(advisor):
    code = "import os\n" "os.system(cmd)\n" "eval(user_input)\n"
    result = advisor.analyze_ai_generated(org_id="org-A", code=code, language="python")

    assert result["language"] == "python"
    assert result["sast_findings_count"] >= 0
    ai_risk_ids = {r["risk_id"] for r in result["ai_risks"]}
    assert "AI-RISK-002" in ai_risk_ids  # eval
    assert "AI-RISK-003" in ai_risk_ids  # os.system
    assert result["combined_score"] > 0
    assert result["risk_level"] in {"critical", "high", "medium", "low", "minimal"}


def test_analyze_detects_subprocess_shell_true(advisor):
    code = (
        "import subprocess\n"
        "subprocess.run('ls ' + path, shell=True)\n"
    )
    result = advisor.analyze_ai_generated(org_id="org-A", code=code, language="python")
    ai_ids = {r["risk_id"] for r in result["ai_risks"]}
    assert "AI-RISK-004" in ai_ids


def test_analyze_clean_code_minimal_risk(advisor):
    code = "def square(x):\n    return x * x\n"
    result = advisor.analyze_ai_generated(org_id="org-A", code=code, language="python")
    assert result["sast_findings_count"] == 0
    assert result["ai_risks_count"] == 0
    assert result["combined_score"] == 0.0
    assert result["risk_level"] == "minimal"


def test_analyze_hardcoded_secret_triggers_ai_risk(advisor):
    code = 'api_key = "AKIAEXAMPLEKEYVALUE12"\n'
    result = advisor.analyze_ai_generated(org_id="org-A", code=code, language="python")
    ai_ids = {r["risk_id"] for r in result["ai_risks"]}
    assert "AI-RISK-001" in ai_ids


def test_analyze_js_eval_detected(advisor):
    code = "const x = eval(untrusted);\n"
    result = advisor.analyze_ai_generated(org_id="org-A", code=code, language="javascript")
    ai_ids = {r["risk_id"] for r in result["ai_risks"]}
    assert "AI-RISK-002" in ai_ids


def test_analyze_combined_score_saturates(advisor):
    # Many critical patterns → score must cap at 100
    code = "\n".join([f"eval(x{i})" for i in range(200)])
    result = advisor.analyze_ai_generated(org_id="org-A", code=code, language="python")
    assert 0 < result["combined_score"] <= 100.0


def test_analyze_returns_snippet_sha256(advisor):
    code = "print('hello')\n"
    result = advisor.analyze_ai_generated(org_id="org-A", code=code, language="python")
    assert "snippet_sha256" in result
    assert isinstance(result["snippet_sha256"], str)
    assert len(result["snippet_sha256"]) == 64


# ---------------------------------------------------------------------------
# 4. Router — 4 endpoints
# ---------------------------------------------------------------------------


def test_router_snippet_endpoint(client):
    resp = client.post(
        "/api/v1/ai-scan/snippet?org_id=org-R",
        json={
            "code": 'password = "hunter2hunter2"\n',
            "language": "python",
            "source_hint": "ai_generated",
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["org_id"] == "org-R"
    assert data["language"] == "python"
    assert data["findings_count"] >= 1


def test_router_analyze_endpoint(client):
    resp = client.post(
        "/api/v1/ai-scan/analyze?org_id=org-R",
        json={"code": "eval(userInput)\n", "language": "javascript"},
        headers=HEADERS,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "sast_findings" in data
    assert "ai_risks" in data
    assert "combined_score" in data
    assert "risk_level" in data


def test_router_history_endpoint(client):
    # First submit one scan
    client.post(
        "/api/v1/ai-scan/snippet?org_id=org-H",
        json={"code": 'token="abcd1234"\n', "language": "python"},
        headers=HEADERS,
    )
    resp = client.get("/api/v1/ai-scan/history?org_id=org-H", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["org_id"] == "org-H"
    assert data["count"] >= 1
    assert isinstance(data["items"], list)


def test_router_stats_endpoint(client):
    client.post(
        "/api/v1/ai-scan/snippet?org_id=org-S",
        json={"code": 'password="abcd1234"\n', "language": "python"},
        headers=HEADERS,
    )
    client.post(
        "/api/v1/ai-scan/snippet?org_id=org-S",
        json={"code": "print('ok')\n", "language": "python"},
        headers=HEADERS,
    )
    resp = client.get("/api/v1/ai-scan/stats?org_id=org-S", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["org_id"] == "org-S"
    assert data["total_scans"] >= 2
    assert data["scans_with_findings"] >= 1
    assert "by_language" in data
    assert "by_source_hint" in data


def test_router_requires_auth(client, monkeypatch):
    resp = client.post(
        "/api/v1/ai-scan/snippet?org_id=org-R",
        json={"code": "x=1", "language": "python"},
        # No headers
    )
    assert resp.status_code in (401, 403)


def test_router_invalid_language_rejects(client):
    resp = client.post(
        "/api/v1/ai-scan/snippet?org_id=org-R",
        json={"code": "x=1", "language": ""},
        headers=HEADERS,
    )
    # Pydantic min_length=1 → 422
    assert resp.status_code in (400, 422)
