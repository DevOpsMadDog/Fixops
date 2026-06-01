"""SPEC-016 increment 1 — WIZ /ingest → normalize → findings + correlation brain.

Locks the debate-hardened acceptance criteria:
  AC-016-01  WIZ env unset -> honest 503 (no fake findings)
  AC-016-02  real issues+vulns -> 200, ingested>0, brain nodes grow, correlated=True
  REQ-016-07 enforced air-gap + vendor-SaaS URL -> 503 (egress guard, no silent egress)
  REQ-016-07 SSRF: cloud-metadata IP blocked; on-prem RFC-1918 allowed
  REQ-016-11 every brain node carries a classification_level marking
  REQ-016-12 ingest uses the engine's typed methods, not the raw /graphql passthrough
"""
from __future__ import annotations

import os

import pytest

# Build the app once at import time — create_app() boots in ~10s which exceeds the
# suite's per-test pytest-timeout if done inside a (timed) fixture.
os.environ.setdefault("FIXOPS_API_TOKEN", "spec016token123456")
from fastapi.testclient import TestClient  # noqa: E402
from apps.api.app import create_app  # noqa: E402

_APP = create_app()


@pytest.fixture(scope="module")
def client():
    return TestClient(_APP)


@pytest.fixture
def _H(auth_headers):
    # auth_headers (from conftest) carries the suite's valid X-API-Key.
    return {**auth_headers, "X-Org-ID": "spec016-org"}


class _FakeWiz:
    def list_issues(self, severity=None, first=50, after=None):
        if after:
            return {"issues": [], "pageInfo": {"hasNextPage": False}}
        return {"issues": [
            {"id": "I1", "severity": "CRITICAL", "type": "EXPOSURE",
             "sourceRule": {"id": "R1", "name": "Public bucket"},
             "entitySnapshot": {"id": "A1", "name": "prod-bucket", "type": "BUCKET"},
             "status": "OPEN"},
        ], "pageInfo": {"hasNextPage": False}}

    def list_vulnerabilities(self, severity=None, first=50, after=None):
        if after:
            return {"nodes": [], "pageInfo": {"hasNextPage": False}}
        return {"nodes": [
            {"id": "V1", "name": "CVE-2024-1234", "vendorSeverity": "CRITICAL",
             "cvss31": {"score": 9.1}},
        ], "pageInfo": {"hasNextPage": False}}


def test_ac_016_01_unset_returns_503(client, _H):
    os.environ.pop("WIZ_API_URL", None)
    r = client.post("/api/v1/wiz/ingest", headers=_H, json={})
    assert r.status_code == 503
    assert "unavailable" in r.json()["detail"].lower()


def test_ac_016_02_ingest_correlates(client, monkeypatch, _H):
    import core.wiz_cnapp_engine as WE
    monkeypatch.setattr(WE, "get_wiz_cnapp_engine", lambda: _FakeWiz())
    monkeypatch.setenv("WIZ_API_URL", "https://wiz.acme.local/graphql")
    r = client.post("/api/v1/wiz/ingest", headers=_H, json={})
    assert r.status_code == 200
    j = r.json()
    assert j["ingested"] == 2          # 1 issue + 1 vuln
    assert j["brain_nodes_added"] > 0
    assert j["correlated"] is True
    assert j["source"] == "wiz"


def test_req_016_07_enforced_blocks_saas(client, monkeypatch, _H):
    import core.wiz_cnapp_engine as WE
    monkeypatch.setattr(WE, "get_wiz_cnapp_engine", lambda: _FakeWiz())
    monkeypatch.setenv("FIXOPS_AIRGAP_MODE", "enforced")
    monkeypatch.setenv("WIZ_API_URL", "https://api.us17.app.wiz.io/graphql")
    r = client.post("/api/v1/wiz/ingest", headers=_H, json={})
    assert r.status_code == 503
    assert "saas" in r.json()["detail"].lower() or "blocked" in r.json()["detail"].lower()


def test_req_016_07_egress_guard_ssrf_and_onprem():
    from core.airgap_config import assert_egress_allowed, EgressBlocked
    # cloud-metadata link-local blocked (SSRF primitive)
    with pytest.raises(EgressBlocked):
        assert_egress_allowed("http://169.254.169.254/latest/meta-data/", "wiz")
    # on-prem RFC-1918 allowed (SCIF reality — tools live on 10.x)
    assert assert_egress_allowed("https://10.20.30.40/graphql", "wiz") is True
    # empty/unset -> blocked
    with pytest.raises(EgressBlocked):
        assert_egress_allowed("", "wiz")


class _Outcome:
    def __init__(self, status, details):
        self.status, self.details = status, details


class _FakePrisma:
    configured = True

    def __init__(self, settings=None, *a, **k):
        # honor the base_url the router builds from PRISMA_API_URL (egress-guard test depends on it)
        self.base_url = (settings or {}).get("base_url") or "https://prisma.acme.local"

    def get_vulnerabilities(self, limit=100):
        return _Outcome("fetched", {"vulnerabilities": [
            {"cve": "CVE-2023-9999", "severity": "critical", "packageName": "openssl",
             "image": "sha256:abc", "cvss": 9.8},
        ], "count": 1})

    def get_alerts(self, status="open", limit=100):
        return _Outcome("fetched", {"alerts": [
            {"id": "AL1", "policy": {"name": "Public S3", "severity": "high", "policyId": "P1"},
             "resource": {"id": "r1", "name": "bucket", "resourceType": "AWS_S3"}},
        ], "count": 1})


class _UnconfiguredPrisma(_FakePrisma):
    configured = False

    def get_vulnerabilities(self, limit=100):
        return _Outcome("skipped", {"reason": "prisma cloud not configured"})


def test_ac_016_02_prisma_unconfigured_503(client, monkeypatch, _H):
    import core.security_connectors as SC
    monkeypatch.setattr(SC, "PrismaCloudConnector", _UnconfiguredPrisma)
    monkeypatch.delenv("PRISMA_ACCESS_KEY", raising=False)
    monkeypatch.setenv("PRISMA_API_URL", "https://prisma.acme.local")
    r = client.post("/api/v1/prisma/ingest", headers=_H, json={})
    assert r.status_code == 503
    assert "not_configured" in r.json()["detail"].lower() or "unavailable" in r.json()["detail"].lower()


def test_ac_016_02_prisma_ingest_correlates(client, monkeypatch, _H):
    import core.security_connectors as SC
    monkeypatch.setattr(SC, "PrismaCloudConnector", _FakePrisma)
    monkeypatch.setenv("PRISMA_API_URL", "https://prisma.acme.local")
    r = client.post("/api/v1/prisma/ingest", headers=_H, json={})
    assert r.status_code == 200
    j = r.json()
    assert j["ingested"] == 2          # 1 vuln + 1 alert
    assert j["brain_nodes_added"] > 0
    assert j["correlated"] is True
    assert j["source"] == "prisma"


def test_req_016_07_prisma_enforced_blocks_saas(client, monkeypatch, _H):
    import core.security_connectors as SC
    monkeypatch.setattr(SC, "PrismaCloudConnector", _FakePrisma)
    monkeypatch.setenv("FIXOPS_AIRGAP_MODE", "enforced")
    monkeypatch.setenv("PRISMA_API_URL", "https://api.prismacloud.io")  # SaaS default
    r = client.post("/api/v1/prisma/ingest", headers=_H, json={})
    assert r.status_code == 503
    assert "blocked" in r.json()["detail"].lower() or "saas" in r.json()["detail"].lower()


class _FakeVerdict:
    action = "remediate_critical"
    confidence = 0.92
    reasoning = "deterministic test verdict"


class _FakeCouncil:
    def convene(self, finding, context, org_id="default"):
        return _FakeVerdict()


@pytest.fixture
def fast_council(monkeypatch):
    # Keep /decide hermetic: patch the council so convene() returns a deterministic verdict
    # instead of making real OpenRouter network calls. The real build path is covered by
    # test_req_016_05_council_factory_builds.
    import core.llm_council as LC
    monkeypatch.setattr(LC.CouncilFactory, "create_default_council",
                        lambda self, **k: _FakeCouncil())
    return None


def _make_finding(org="spec016-org", severity="critical"):
    import uuid
    from core.security_findings_engine import SecurityFindingsEngine
    uniq = uuid.uuid4().hex[:8]  # unique per call so record_finding dedup never collides across tests
    rec = SecurityFindingsEngine().record_finding(
        org_id=org, title=f"SQLi in checkout {uniq}", finding_type="sast",
        source_tool="wiz", severity=severity, cvss_score=9.1,
        asset_id=f"svc-checkout-{uniq}", asset_type="service",
        description="union-based SQL injection", remediation="parameterize",
    )
    return rec["id"]


def test_ac_016_05_decide_renders_and_signs(client, _H, fast_council):
    fid = _make_finding(severity="critical")
    r = client.post("/api/v1/closed-loop/decide", headers=_H,
                    json={"finding_id": fid, "targets": ["jira", "servicenow", "splunk"]})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["decision"] in ("block", "defer", "allow")
    assert j["verdict"]["verdict_source"] in ("council", "severity_fallback")
    # targets unconfigured in test -> honest per-target receipts (block/defer path)
    if j["decision"] in ("block", "defer"):
        statuses = {x["target"]: x["status"] for x in j["receipts"]}
        assert statuses.get("jira") in ("not_configured", "blocked", "delivered", "failed")
    # REQ-016-10: signed bundle appended to the evidence chain
    assert j["evidence_seq"] is not None
    assert j["deduped"] is False


def test_req_016_09_replay_deduped(client, _H, fast_council):
    fid = _make_finding(severity="critical")
    a = client.post("/api/v1/closed-loop/decide", headers=_H, json={"finding_id": fid}).json()
    b = client.post("/api/v1/closed-loop/decide", headers=_H, json={"finding_id": fid}).json()
    assert a["deduped"] is False
    assert b["deduped"] is True
    assert b["receipts"] == a["receipts"]  # no re-write on replay


def test_req_016_05_council_factory_builds():
    # Regression: CouncilFactory.create_default_council is an INSTANCE method — calling it
    # unbound (CouncilFactory.create_default_council()) raised TypeError and silently forced
    # the severity fallback, killing the real council path. Lock the instance-call.
    from core.llm_council import CouncilFactory, LLMCouncilEngine
    council = CouncilFactory().create_default_council()
    assert isinstance(council, LLMCouncilEngine)
    assert hasattr(council, "convene")


def test_req_016_08_cross_org_finding_404(client, _H):
    # a finding that does not exist for this org -> 404 (never act on another org's finding)
    r = client.post("/api/v1/closed-loop/decide", headers=_H,
                    json={"finding_id": "does-not-exist-for-org"})
    assert r.status_code == 404


_BD_SAMPLE = (
    b'{"items":[{"componentName":"log4j-core","componentVersionName":"2.14.1",'
    b'"vulnerabilityWithRemediation":{"vulnerabilityName":"CVE-2021-44228",'
    b'"severity":"CRITICAL","baseScore":10.0,"description":"Log4Shell",'
    b'"remediationStatus":"NEW"}}]}'
)


class _OutcomeBD:
    def __init__(self, status, details):
        self.status, self.details = status, details


class _FakeBlackDuck:
    configured = True

    def __init__(self, settings=None, *a, **k):
        self.base_url = (settings or {}).get("base_url") or "https://blackduck.acme.local"
        self.vulnerable_bom_url = (settings or {}).get("vulnerable_bom_url") \
            or "https://blackduck.acme.local/api/projects/p/versions/v/vulnerable-bom-components"

    def get_vulnerable_components(self, limit=500):
        return _OutcomeBD("fetched", {"items": [
            {"componentName": "log4j-core", "componentVersionName": "2.14.1",
             "vulnerabilityWithRemediation": {"vulnerabilityName": "CVE-2021-44228",
                                              "severity": "CRITICAL", "baseScore": 10.0}},
        ], "count": 1})


class _UnconfiguredBlackDuck(_FakeBlackDuck):
    configured = False

    def get_vulnerable_components(self, limit=500):
        return _OutcomeBD("skipped", {"reason": "black duck not configured"})


def test_req_016_13_blackduck_normalizer_registered():
    from core.scanner_parsers import SCANNER_NORMALIZERS, BlackDuckNormalizer, parse_scanner_output
    assert SCANNER_NORMALIZERS.get("blackduck") is BlackDuckNormalizer
    # exercise the real ingest path (builds NormalizerConfig like the app does)
    findings = parse_scanner_output(_BD_SAMPLE, scanner_type="blackduck")
    assert len(findings) == 1
    f = findings[0]
    cve = getattr(f, "cve_id", None) or (f.get("cve_id") if isinstance(f, dict) else None)
    assert cve == "CVE-2021-44228"


def test_req_016_13_blackduck_unconfigured_503(client, monkeypatch, _H):
    import core.security_connectors as SC
    monkeypatch.setattr(SC, "BlackDuckConnector", _UnconfiguredBlackDuck)
    monkeypatch.setenv("BLACKDUCK_API_URL", "https://blackduck.acme.local")
    monkeypatch.delenv("BLACKDUCK_VULNERABLE_BOM_URL", raising=False)
    r = client.post("/api/v1/blackduck/ingest", headers=_H, json={})
    assert r.status_code == 503


def test_req_016_13_blackduck_ingest_correlates(client, monkeypatch, _H):
    import core.security_connectors as SC
    monkeypatch.setattr(SC, "BlackDuckConnector", _FakeBlackDuck)
    monkeypatch.setenv("BLACKDUCK_API_URL", "https://blackduck.acme.local")
    monkeypatch.setenv("BLACKDUCK_VULNERABLE_BOM_URL",
                       "https://blackduck.acme.local/api/projects/p/versions/v/vulnerable-bom-components")
    r = client.post("/api/v1/blackduck/ingest", headers=_H, json={})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["ingested"] == 1
    assert j["brain_nodes_added"] > 0
    assert j["correlated"] is True
    assert j["source"] == "blackduck"


class _OutcomeCf:
    def __init__(self, status, details):
        self.status, self.details = status, details


class _FakeConfluence:
    configured = True

    def __init__(self, settings=None, *a, **k):
        self.base_url = (settings or {}).get("base_url") or "https://confluence.acme.local"

    def get_page(self, page_id):
        return _OutcomeCf("fetched", {"page_id": page_id,
                                      "title": "ADR-007: Checkout service auth",
                                      "data": {"id": page_id, "title": "ADR-007"}})


class _UnconfiguredConfluence(_FakeConfluence):
    configured = False

    def get_page(self, page_id):
        return _OutcomeCf("skipped", {"reason": "confluence connector not fully configured"})


def test_ac_016_04_confluence_unconfigured_503(client, monkeypatch, _H):
    import core.connectors as CN
    monkeypatch.setattr(CN, "ConfluenceConnector", _UnconfiguredConfluence)
    monkeypatch.delenv("CONFLUENCE_SPACE_KEY", raising=False)
    monkeypatch.setenv("CONFLUENCE_BASE_URL", "https://confluence.acme.local")
    r = client.post("/api/v1/design-context/confluence/import", headers=_H,
                    json={"page_id": "12345"})
    assert r.status_code == 503


def test_ac_016_04_confluence_import_links_finding(client, monkeypatch, _H):
    import core.connectors as CN
    monkeypatch.setattr(CN, "ConfluenceConnector", _FakeConfluence)
    monkeypatch.setenv("CONFLUENCE_BASE_URL", "https://confluence.acme.local")
    fid = _make_finding(severity="high")
    r = client.post("/api/v1/design-context/confluence/import", headers=_H,
                    json={"page_id": "ADR-007", "link_finding_ids": [fid]})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["context_nodes"] == 1
    assert j["linked_findings"] == 1   # design-context -> finding edge created (AC-016-04)
    assert j["source"] == "confluence"


def test_ac_016_04_confluence_does_not_link_cross_org(client, monkeypatch, _H):
    import core.connectors as CN
    monkeypatch.setattr(CN, "ConfluenceConnector", _FakeConfluence)
    monkeypatch.setenv("CONFLUENCE_BASE_URL", "https://confluence.acme.local")
    r = client.post("/api/v1/design-context/confluence/import", headers=_H,
                    json={"page_id": "ADR-008", "link_finding_ids": ["nonexistent-other-org"]})
    assert r.status_code == 200
    assert r.json()["linked_findings"] == 0  # never link a finding that isn't this org's


def test_req_016_11_classification_marking():
    from apps.api.scanner_ingest_router import _index_findings_into_brain
    from core.knowledge_brain import get_brain
    res = _index_findings_into_brain(
        [{"id": "spec016-cls-node", "title": "t", "severity": "high"}],
        "spec016-org",
    )
    assert res["nodes_added"] >= 1
    node = get_brain().get_node("spec016-cls-node")
    assert node is not None
    # get_node may return a dict or an object; properties may be nested or flattened.
    props = node.get("properties") if isinstance(node, dict) else getattr(node, "properties", {})
    if isinstance(props, str):
        import json
        props = json.loads(props)
    classification = (props or {}).get("classification_level") or (
        node.get("classification_level") if isinstance(node, dict) else None
    )
    assert classification  # marking present (default UNCLASSIFIED)
