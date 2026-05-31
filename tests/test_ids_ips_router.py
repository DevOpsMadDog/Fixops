"""Tests for ids_ips_router — Multica #3757.

Uses a temporary SQLite database per test via the IDS_IPS_DB_PATH environment
variable + module-level singleton reset between tests.

Coverage (8+ tests):
  1.  info-200
  2.  import-3-rules-from-snort-syntax (multi-line, sid + msg parsed correctly)
  3.  list-rules + filter-by-ruleset
  4.  verdict-create + list-verdicts-with-time-filter
  5.  verdict-severity-filter
  6.  delete-rule
  7.  401-on-missing-X-API-Key
  8.  bad-rule-text-doesn't-500 (0 parseable, returns 200 with imported=0)
  9.  import-invalid-ruleset-422
  10. list-verdicts-severity-filter-invalid-422
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Generator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Sample Snort/Suricata rule text used across tests
# ---------------------------------------------------------------------------

_SNORT_RULES_3 = """
# Comment line — must be skipped
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET TROJAN Possible Cobalt Strike"; sid:2019416; rev:3;)
alert udp any any -> any 53 (msg:"ET DNS Query for Known Malware Domain"; sid:2027865; rev:1;)
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"ET WEB_SERVER SQL Injection Attempt"; sid:2006445; rev:12;)
this line has no sid or msg and should be silently skipped
""".strip()

_SURICATA_RULES_1 = (
    'alert http $HOME_NET any -> $EXTERNAL_NET any '
    '(msg:"SURICATA TLS SNI mismatch"; flow:established; sid:9001; rev:1;)'
)


# ---------------------------------------------------------------------------
# Helpers to isolate the module-level DB singleton between tests
# ---------------------------------------------------------------------------


def _build_app(db_path: str) -> FastAPI:
    os.environ["IDS_IPS_DB_PATH"] = db_path

    mod_name = "apps.api.ids_ips_router"
    if mod_name in sys.modules:
        del sys.modules[mod_name]

    import apps.api.ids_ips_router as iir  # noqa: PLC0415

    iir._db = None  # type: ignore[attr-defined]

    from apps.api.auth_deps import api_key_auth  # noqa: PLC0415

    app = FastAPI()
    app.dependency_overrides[api_key_auth] = lambda: None
    app.include_router(iir.router)
    return app


@pytest.fixture()
def client(tmp_path: Path) -> Generator[TestClient, None, None]:
    db_path = str(tmp_path / "test_ids.db")
    app = _build_app(db_path)
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Test 1 — GET / returns 200 with expected structure
# ---------------------------------------------------------------------------


def test_info_200(client: TestClient) -> None:
    resp = client.get("/api/v1/ids-ips/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "IDS/IPS Rules and Verdicts"
    assert body["status"] == "empty"
    assert body["verdicts_last_24h"] == 0
    assert isinstance(body["rule_counts_by_ruleset"], dict)
    assert isinstance(body["endpoints"], list)
    assert len(body["endpoints"]) >= 5


# ---------------------------------------------------------------------------
# Test 2 — POST /rules/import parses 3 Snort rules, skips 1 bad line
# ---------------------------------------------------------------------------


def test_import_3_snort_rules(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/ids-ips/rules/import",
        json={
            "org_id": "org-a",
            "ruleset": "snort",
            "rule_text": _SNORT_RULES_3,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["imported"] == 3
    assert body["ruleset"] == "snort"
    assert body["org_id"] == "org-a"

    # Verify the rules are stored with correct sid + rule_name
    rules_resp = client.get("/api/v1/ids-ips/rules", params={"org_id": "org-a"})
    rules = rules_resp.json()["rules"]
    assert len(rules) == 3
    sids = {r["sid"] for r in rules}
    assert sids == {2019416, 2027865, 2006445}
    names = {r["rule_name"] for r in rules}
    assert "ET TROJAN Possible Cobalt Strike" in names
    assert "ET DNS Query for Known Malware Domain" in names
    assert "ET WEB_SERVER SQL Injection Attempt" in names


# ---------------------------------------------------------------------------
# Test 3 — GET /rules and filter by ruleset
# ---------------------------------------------------------------------------


def test_list_rules_and_filter_by_ruleset(client: TestClient) -> None:
    # Import snort rules
    client.post(
        "/api/v1/ids-ips/rules/import",
        json={"org_id": "org-b", "ruleset": "snort", "rule_text": _SNORT_RULES_3},
    )
    # Import 1 suricata rule
    client.post(
        "/api/v1/ids-ips/rules/import",
        json={"org_id": "org-b", "ruleset": "suricata", "rule_text": _SURICATA_RULES_1},
    )

    # All rules for org-b = 4
    all_resp = client.get("/api/v1/ids-ips/rules", params={"org_id": "org-b"})
    assert all_resp.status_code == 200
    assert all_resp.json()["count"] == 4

    # Filter to snort only = 3
    snort_resp = client.get(
        "/api/v1/ids-ips/rules", params={"org_id": "org-b", "ruleset": "snort"}
    )
    assert snort_resp.status_code == 200
    assert snort_resp.json()["count"] == 3
    assert all(r["ruleset"] == "snort" for r in snort_resp.json()["rules"])

    # Filter to suricata only = 1
    suri_resp = client.get(
        "/api/v1/ids-ips/rules", params={"org_id": "org-b", "ruleset": "suricata"}
    )
    assert suri_resp.status_code == 200
    assert suri_resp.json()["count"] == 1
    assert suri_resp.json()["rules"][0]["sid"] == 9001


# ---------------------------------------------------------------------------
# Test 4 — POST /verdicts creates verdict; GET /verdicts respects time filter
# ---------------------------------------------------------------------------


def test_verdict_create_and_list_time_filter(client: TestClient) -> None:
    verdict_payload = {
        "org_id": "org-c",
        "src_ip": "10.0.0.5",
        "dst_ip": "93.184.216.34",
        "dst_port": 443,
        "protocol": "tcp",
        "ja3": "a0e9f5d64349fb13191bc781f81f42e1",
        "sni": "example.com",
        "severity": "high",
        "message": "Suspicious TLS SNI to known C2 domain",
    }
    create_resp = client.post("/api/v1/ids-ips/verdicts", json=verdict_payload)
    assert create_resp.status_code == 201
    created = create_resp.json()
    assert created["id"] != ""
    assert created["severity"] == "high"
    assert created["src_ip"] == "10.0.0.5"
    assert created["sni"] == "example.com"
    assert "detected_at" in created

    # List with 24h window — should include the just-created verdict
    list_resp = client.get("/api/v1/ids-ips/verdicts", params={"org_id": "org-c", "hours": 24})
    assert list_resp.status_code == 200
    body = list_resp.json()
    assert body["count"] == 1
    assert body["verdicts"][0]["id"] == created["id"]

    # List with 0 hours effectively means future — but our minimum is 1h so use
    # a separate check: list with hours=8760 (1yr) should still include it
    list_resp2 = client.get("/api/v1/ids-ips/verdicts", params={"org_id": "org-c", "hours": 8760})
    assert list_resp2.json()["count"] == 1


# ---------------------------------------------------------------------------
# Test 5 — GET /verdicts filters by severity
# ---------------------------------------------------------------------------


def test_verdict_severity_filter(client: TestClient) -> None:
    org = "org-d"
    for sev in ("critical", "high", "medium", "low"):
        client.post(
            "/api/v1/ids-ips/verdicts",
            json={"org_id": org, "severity": sev, "message": f"Test {sev} event"},
        )

    # All four
    all_resp = client.get("/api/v1/ids-ips/verdicts", params={"org_id": org, "hours": 1})
    assert all_resp.json()["count"] == 4

    # Only critical
    crit_resp = client.get(
        "/api/v1/ids-ips/verdicts",
        params={"org_id": org, "hours": 1, "severity": "critical"},
    )
    assert crit_resp.status_code == 200
    assert crit_resp.json()["count"] == 1
    assert crit_resp.json()["verdicts"][0]["severity"] == "critical"

    # Only medium
    med_resp = client.get(
        "/api/v1/ids-ips/verdicts",
        params={"org_id": org, "hours": 1, "severity": "medium"},
    )
    assert med_resp.json()["count"] == 1


# ---------------------------------------------------------------------------
# Test 6 — DELETE /rules/{rule_id} removes rule; subsequent list is empty
# ---------------------------------------------------------------------------


def test_delete_rule(client: TestClient) -> None:
    # Import one rule
    client.post(
        "/api/v1/ids-ips/rules/import",
        json={"org_id": "org-e", "ruleset": "custom", "rule_text": _SURICATA_RULES_1},
    )
    rules = client.get("/api/v1/ids-ips/rules", params={"org_id": "org-e"}).json()["rules"]
    assert len(rules) == 1
    rule_id = rules[0]["id"]

    del_resp = client.delete(f"/api/v1/ids-ips/rules/{rule_id}")
    assert del_resp.status_code == 204

    # Rule no longer in list
    after = client.get("/api/v1/ids-ips/rules", params={"org_id": "org-e"}).json()
    assert after["count"] == 0

    # Second delete is 404
    del_resp2 = client.delete(f"/api/v1/ids-ips/rules/{rule_id}")
    assert del_resp2.status_code == 404
    assert del_resp2.json()["detail"]["error"] == "rule_not_found"


# ---------------------------------------------------------------------------
# Test 7 — 401 on missing X-API-Key (auth dep enforced without override)
# ---------------------------------------------------------------------------


def test_401_on_missing_api_key(tmp_path: Path) -> None:
    db_path = str(tmp_path / "test_auth.db")
    os.environ["IDS_IPS_DB_PATH"] = db_path

    mod_name = "apps.api.ids_ips_router"
    if mod_name in sys.modules:
        del sys.modules[mod_name]
    import apps.api.ids_ips_router as iir  # noqa: PLC0415

    iir._db = None  # type: ignore[attr-defined]

    # Do NOT override api_key_auth
    app = FastAPI()
    app.include_router(iir.router)

    with TestClient(app, raise_server_exceptions=False) as c:
        resp = c.get("/api/v1/ids-ips/rules")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Test 8 — bad rule text doesn't 500; returns imported=0
# ---------------------------------------------------------------------------


def test_bad_rule_text_no_500(client: TestClient) -> None:
    bad_text = "\n".join([
        "# just a comment",
        "this is not a rule at all",
        "alert without sid or msg",
        "",
    ])
    resp = client.post(
        "/api/v1/ids-ips/rules/import",
        json={"org_id": "org-f", "ruleset": "snort", "rule_text": bad_text},
    )
    assert resp.status_code == 200
    assert resp.json()["imported"] == 0


# ---------------------------------------------------------------------------
# Test 9 — import with invalid ruleset returns 422
# ---------------------------------------------------------------------------


def test_import_invalid_ruleset_422(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/ids-ips/rules/import",
        json={
            "org_id": "org-g",
            "ruleset": "zeek",  # not in allowed set
            "rule_text": _SURICATA_RULES_1,
        },
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "invalid_ruleset"


# ---------------------------------------------------------------------------
# Test 10 — GET /verdicts with invalid severity returns 422
# ---------------------------------------------------------------------------


def test_list_verdicts_invalid_severity_422(client: TestClient) -> None:
    resp = client.get(
        "/api/v1/ids-ips/verdicts",
        params={"org_id": "org-h", "severity": "unknown_level"},
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "invalid_severity"
