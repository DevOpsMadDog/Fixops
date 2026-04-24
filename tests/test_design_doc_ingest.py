"""Tests for GAP-056 — design-doc ingest + STRIDE extraction across 3 engines.

Covers:
  * ThreatModelingEngine.ingest_design_doc / list_ingested_docs /
    extract_stride_elements / list_extracted_stride_threats
  * ThreatModelingPipelineEngine.auto_threat_model_from_doc
  * CyberThreatModelingEngine.link_design_doc_to_model / list_doc_links
  * design_doc_router: /ingest, /extract, /ingests, /auto-model, /stride
"""
from __future__ import annotations

import os
import tempfile
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.threat_modeling_engine import ThreatModelingEngine
from core.threat_modeling_pipeline_engine import ThreatModelingPipelineEngine
from core.cyber_threat_modeling_engine import CyberThreatModelingEngine


MD_DOC = """# My Service Design

## Overview

Free-form prose we should ignore.

## Components:
- Web portal (public facing)
- Payments API
- Postgres database
- Kafka queue
- S3 bucket for receipts
- Third-party billing SaaS

## Data Flow:
- Web portal -> Payments API
- Payments API -> Postgres database
- Payments API -> Kafka queue
- Kafka queue -> Billing SaaS

## Trust Boundaries:
- Internet -> DMZ
- DMZ -> Internal services
- Internal services -> Cloud vendor
"""


@pytest.fixture()
def tme(tmp_path):
    return ThreatModelingEngine(db_path=str(tmp_path / "tm.db"))


@pytest.fixture()
def pipeline_engine(tmp_path, monkeypatch):
    # Give both engines isolated DBs so pipeline's lazy TME import in
    # auto_threat_model_from_doc still finds the design-doc ingest.  We point
    # the default DB at a tmp dir via CWD redirection.
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    return ThreatModelingPipelineEngine(db_path=str(work / "pipeline.db"))


@pytest.fixture()
def cyber_engine(tmp_path):
    return CyberThreatModelingEngine(db_path=str(tmp_path / "cyber.db"))


# ---------------------------------------------------------------------------
# 1. Markdown parser — sections extracted correctly
# ---------------------------------------------------------------------------


def test_parse_extracts_three_sections(tme):
    rec = tme.ingest_design_doc("org-a", "design.md", MD_DOC, doc_format="markdown")
    assert len(rec["parsed_components"]) == 6
    assert "Postgres database" in rec["parsed_components"]
    assert len(rec["parsed_flows"]) == 4
    assert "Web portal -> Payments API" in rec["parsed_flows"]
    assert len(rec["parsed_boundaries"]) == 3


def test_parse_ignores_free_prose(tme):
    rec = tme.ingest_design_doc("o", "d", "just plain prose without headings")
    assert rec["parsed_components"] == []
    assert rec["parsed_flows"] == []
    assert rec["parsed_boundaries"] == []


def test_parse_numbered_list(tme):
    doc = "Components:\n1. Web portal\n2. API service\n"
    rec = tme.ingest_design_doc("o", "d", doc)
    assert rec["parsed_components"] == ["Web portal", "API service"]


def test_parse_alias_headings(tme):
    doc = "## Services:\n- Auth API\n\n## Dataflow:\n- A -> B\n"
    rec = tme.ingest_design_doc("o", "d", doc)
    assert "Auth API" in rec["parsed_components"]
    assert "A -> B" in rec["parsed_flows"]


def test_ingest_unknown_format_still_parses(tme):
    rec = tme.ingest_design_doc("o", "d", MD_DOC, doc_format="weirdformat")
    assert len(rec["parsed_components"]) == 6


# ---------------------------------------------------------------------------
# 2. STRIDE heuristics on 5+ component types
# ---------------------------------------------------------------------------


def test_stride_web_component_yields_spoofing_and_tampering(tme):
    rec = tme.ingest_design_doc("org-a", "d", "Components:\n- Web portal\n")
    threats = tme.extract_stride_elements("org-a", rec["id"])
    types = {t["threat_type"] for t in threats}
    assert "spoofing" in types and "tampering" in types


def test_stride_api_component_yields_spoofing_and_eop(tme):
    rec = tme.ingest_design_doc("o", "d", "Components:\n- Payments API\n")
    threats = tme.extract_stride_elements("o", rec["id"])
    types = {t["threat_type"] for t in threats}
    assert "spoofing" in types
    assert "elevation_of_privilege" in types


def test_stride_database_component_yields_info_disclosure_and_dos(tme):
    rec = tme.ingest_design_doc("o", "d", "Components:\n- Postgres database\n")
    threats = tme.extract_stride_elements("o", rec["id"])
    types = {t["threat_type"] for t in threats}
    assert "information_disclosure" in types
    assert "denial_of_service" in types
    # Severity should include a critical tier for DB information disclosure
    assert any(t["severity"] == "critical" for t in threats
               if t["threat_type"] == "information_disclosure")


def test_stride_queue_component_yields_tampering(tme):
    rec = tme.ingest_design_doc("o", "d", "Components:\n- Kafka queue\n")
    threats = tme.extract_stride_elements("o", rec["id"])
    types = {t["threat_type"] for t in threats}
    assert "tampering" in types


def test_stride_storage_component_yields_info_disclosure(tme):
    rec = tme.ingest_design_doc("o", "d", "Components:\n- S3 bucket\n")
    threats = tme.extract_stride_elements("o", rec["id"])
    types = {t["threat_type"] for t in threats}
    assert "information_disclosure" in types


def test_stride_external_component_yields_spoofing(tme):
    rec = tme.ingest_design_doc(
        "o", "d", "Components:\n- External billing SaaS\n"
    )
    threats = tme.extract_stride_elements("o", rec["id"])
    types = {t["threat_type"] for t in threats}
    assert "spoofing" in types


def test_stride_unknown_component_is_skipped(tme):
    rec = tme.ingest_design_doc("o", "d", "Components:\n- Frobnicator widget\n")
    threats = tme.extract_stride_elements("o", rec["id"])
    assert threats == []


# ---------------------------------------------------------------------------
# 3. Persistence and listing
# ---------------------------------------------------------------------------


def test_list_ingested_docs_returns_parsed_lists(tme):
    tme.ingest_design_doc("org-a", "design1.md", MD_DOC)
    tme.ingest_design_doc("org-a", "design2.md", "Components:\n- Web portal\n")
    docs = tme.list_ingested_docs("org-a")
    assert len(docs) == 2
    # Each record should expose parsed lists (not the raw *_json columns)
    for d in docs:
        assert "parsed_components" in d
        assert "parsed_flows" in d
        assert "parsed_boundaries" in d


def test_extract_is_idempotent(tme):
    rec = tme.ingest_design_doc("o", "d", MD_DOC)
    a = tme.extract_stride_elements("o", rec["id"])
    b = tme.extract_stride_elements("o", rec["id"])
    # Same threat *count* across re-runs, content same, distinct ids each time.
    assert len(a) == len(b)
    listed = tme.list_extracted_stride_threats("o", doc_ingest_id=rec["id"])
    assert len(listed) == len(b)


def test_extract_missing_ingest_raises(tme):
    with pytest.raises(ValueError):
        tme.extract_stride_elements("o", "nonexistent-id")


# ---------------------------------------------------------------------------
# 4. Org isolation
# ---------------------------------------------------------------------------


def test_ingest_list_isolated_per_org(tme):
    tme.ingest_design_doc("org-a", "a.md", MD_DOC)
    tme.ingest_design_doc("org-b", "b.md", MD_DOC)
    assert len(tme.list_ingested_docs("org-a")) == 1
    assert len(tme.list_ingested_docs("org-b")) == 1


def test_stride_extraction_isolated_per_org(tme):
    rec_a = tme.ingest_design_doc("org-a", "a.md", "Components:\n- Web portal\n")
    rec_b = tme.ingest_design_doc("org-b", "b.md", "Components:\n- Web portal\n")
    tme.extract_stride_elements("org-a", rec_a["id"])
    tme.extract_stride_elements("org-b", rec_b["id"])
    ta = tme.list_extracted_stride_threats("org-a")
    tb = tme.list_extracted_stride_threats("org-b")
    assert all(t["org_id"] == "org-a" for t in ta)
    assert all(t["org_id"] == "org-b" for t in tb)
    # Org A should not be able to extract using org B's ingest id
    with pytest.raises(ValueError):
        tme.extract_stride_elements("org-a", rec_b["id"])


def test_ingest_missing_org_id_raises(tme):
    with pytest.raises(ValueError):
        tme.ingest_design_doc("", "d", "Components:\n- X\n")


# ---------------------------------------------------------------------------
# 5. Pipeline auto-model chain
# ---------------------------------------------------------------------------


def test_auto_model_creates_draft_and_populates(pipeline_engine):
    # Use the pipeline engine's TME instance (created lazily with default path
    # under the tmp CWD fixture).
    from core.threat_modeling_engine import ThreatModelingEngine
    tme = ThreatModelingEngine()
    rec = tme.ingest_design_doc("org-a", "design.md", MD_DOC)

    model = pipeline_engine.auto_threat_model_from_doc(
        org_id="org-a", doc_ingest_id=rec["id"]
    )
    assert model["status"] == "draft"
    assert model["components_added"] >= 1
    assert model["threats_added"] >= 1
    assert model["source"] == "design-doc-ingest"

    full = pipeline_engine.get_model(model["model_id"], "org-a")
    assert full["status"] == "draft"
    assert len(full["components"]) == model["components_added"]
    assert len(full["threats"]) == model["threats_added"]


def test_auto_model_rejects_missing_ingest(pipeline_engine):
    with pytest.raises(ValueError):
        pipeline_engine.auto_threat_model_from_doc("org-a", "nonexistent-id")


# ---------------------------------------------------------------------------
# 6. Cyber engine traceability link
# ---------------------------------------------------------------------------


def test_cyber_link_requires_existing_model(cyber_engine):
    with pytest.raises(ValueError):
        cyber_engine.link_design_doc_to_model(
            org_id="org-a", doc_ingest_id="doc1", model_id="nonexistent"
        )


def test_cyber_link_creates_and_is_idempotent(cyber_engine):
    m = cyber_engine.create_model(
        org_id="org-a", model_name="n", system_name="s",
        model_type="application", scope="", created_by="t",
    )
    a = cyber_engine.link_design_doc_to_model(
        org_id="org-a", doc_ingest_id="doc-1", model_id=m["id"]
    )
    b = cyber_engine.link_design_doc_to_model(
        org_id="org-a", doc_ingest_id="doc-1", model_id=m["id"]
    )
    assert a["id"] == b["id"]  # idempotent — same row returned
    links = cyber_engine.list_doc_links("org-a", model_id=m["id"])
    assert len(links) == 1


def test_cyber_links_isolated_per_org(cyber_engine):
    m_a = cyber_engine.create_model(
        org_id="org-a", model_name="a", system_name="sa",
        model_type="application", scope="", created_by="t",
    )
    m_b = cyber_engine.create_model(
        org_id="org-b", model_name="b", system_name="sb",
        model_type="application", scope="", created_by="t",
    )
    cyber_engine.link_design_doc_to_model("org-a", "doc-1", m_a["id"])
    cyber_engine.link_design_doc_to_model("org-b", "doc-1", m_b["id"])
    assert len(cyber_engine.list_doc_links("org-a")) == 1
    assert len(cyber_engine.list_doc_links("org-b")) == 1


# ---------------------------------------------------------------------------
# 7. Router smoke tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Build a FastAPI app with just the design_doc_router attached."""
    # Force all three engines onto tmp DBs via monkeypatched default paths.
    monkeypatch.chdir(tmp_path)
    os.environ["FIXOPS_API_TOKEN"] = "test-token"
    os.environ["FIXOPS_AUTH_DISABLED"] = "0"

    # Reset router-module singletons to pick up fresh engine state per test.
    import apps.api.design_doc_router as ddr
    ddr._tme = None
    ddr._pipeline = None
    ddr._cyber = None

    app = FastAPI()
    app.include_router(ddr.router)
    return TestClient(app)


_AUTH_HEADER = {"X-API-Key": "test-token"}


def test_router_ingest_and_extract_smoke(client):
    r = client.post(
        "/api/v1/design-doc/ingest",
        json={
            "org_id": "org-a",
            "doc_source": "svc.md",
            "doc_content": "Components:\n- Web portal\n- Postgres database\n",
            "doc_format": "markdown",
        },
        headers=_AUTH_HEADER,
    )
    assert r.status_code == 200, r.text
    rid = r.json()["id"]

    r2 = client.post(
        "/api/v1/design-doc/extract",
        json={"org_id": "org-a", "doc_ingest_id": rid},
        headers=_AUTH_HEADER,
    )
    assert r2.status_code == 200
    assert r2.json()["threat_count"] >= 2


def test_router_list_ingests_and_stride(client):
    client.post(
        "/api/v1/design-doc/ingest",
        json={"org_id": "org-a", "doc_source": "d",
              "doc_content": "Components:\n- API service\n"},
        headers=_AUTH_HEADER,
    )
    listed = client.get(
        "/api/v1/design-doc/ingests",
        params={"org_id": "org-a"},
        headers=_AUTH_HEADER,
    )
    assert listed.status_code == 200
    assert len(listed.json()) == 1

    # Trigger extract so /stride returns rows
    rid = listed.json()[0]["id"]
    client.post(
        "/api/v1/design-doc/extract",
        json={"org_id": "org-a", "doc_ingest_id": rid},
        headers=_AUTH_HEADER,
    )
    stride = client.get(
        "/api/v1/design-doc/stride",
        params={"org_id": "org-a", "doc_ingest_id": rid},
        headers=_AUTH_HEADER,
    )
    assert stride.status_code == 200
    assert len(stride.json()) >= 1


def test_router_auto_model_smoke(client):
    rid = client.post(
        "/api/v1/design-doc/ingest",
        json={"org_id": "org-a", "doc_source": "d",
              "doc_content": MD_DOC},
        headers=_AUTH_HEADER,
    ).json()["id"]
    r = client.post(
        "/api/v1/design-doc/auto-model",
        json={"org_id": "org-a", "doc_ingest_id": rid,
              "model_name": "Auto-generated test model"},
        headers=_AUTH_HEADER,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "draft"
    assert body["components_added"] >= 1
    assert body["threats_added"] >= 1


def test_router_rejects_missing_ingest(client):
    r = client.post(
        "/api/v1/design-doc/extract",
        json={"org_id": "org-a", "doc_ingest_id": "does-not-exist"},
        headers=_AUTH_HEADER,
    )
    assert r.status_code == 404


def test_router_requires_api_key(client):
    r = client.post(
        "/api/v1/design-doc/ingest",
        json={"org_id": "o", "doc_source": "d", "doc_content": "x"},
    )
    assert r.status_code in (401, 403)
