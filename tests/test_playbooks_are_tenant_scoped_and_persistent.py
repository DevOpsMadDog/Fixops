"""Playbooks belong to the organisation that created them, and outlive a restart.

These twelve routes are mounted in app.py and grc_app.py and were backed by
two module-level dicts plus:

    def _get_org_id() -> str:
        return "default"

Every tenant resolved to the same org, so the authorisation code — which was
correct, comparing playbook["org_id"] to the caller's org and raising 403 —
compared a constant to itself and never fired. Measured against the running
app with two real signed-up tenants, tenant B could list, read, overwrite and
execute tenant A's incident-response playbook, all 200.

The storage was also process-local: a customer's playbooks were lost on
restart and invisible to every other worker.

These tests run against the HTTP surface, because that is where the defect
lived — the engine underneath was org-scoped all along.
"""

from __future__ import annotations

import base64
import json
import uuid

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    import os

    data_dir = tmp_path_factory.mktemp("pbdata")
    os.environ["FIXOPS_DATA_DIR"] = str(data_dir)
    os.environ["FIXOPS_DISABLE_RATE_LIMIT"] = "1"
    from apps.api.app import create_app

    return TestClient(create_app(), raise_server_exceptions=False)


def _tenant(client: TestClient, tag: str):
    """A real signed-up tenant, and the org its credential actually pins."""
    suffix = uuid.uuid4().hex[:8]
    email, password = f"{tag}-{suffix}@example.com", "Aldeci-Demo-2026!x"
    client.post("/api/v1/auth/signup", json={
        "email": email, "password": password,
        "first_name": tag, "last_name": "T",
    })
    token = client.post("/api/v1/auth/login", json={
        "email": email, "password": password,
    }).json()["access_token"]
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    org = json.loads(base64.urlsafe_b64decode(payload))["org_id"]
    return {"Authorization": f"Bearer {token}"}, org


STEP = {
    "step_id": "s1", "step_type": "quarantine", "name": "isolate",
    "config": {"host": "db-01"}, "timeout_seconds": 30,
}


def test_a_playbook_records_the_creating_org_not_a_constant(client) -> None:
    headers, org = _tenant(client, "owner")
    created = client.post("/api/v1/playbooks", headers=headers, json={
        "name": "OWNED", "description": "d", "steps": [STEP],
    })
    assert created.status_code == 200, created.text
    assert created.json()["org_id"] == org, (
        'the playbook must be stamped with the caller\'s org; "default" here '
        "means _get_org_id is hardcoded again and every tenant shares one bucket"
    )


def test_another_tenant_cannot_read_update_execute_or_list_it(client) -> None:
    """The whole defect, as one test."""
    a_headers, _ = _tenant(client, "alpha")
    b_headers, _ = _tenant(client, "bravo")

    created = client.post("/api/v1/playbooks", headers=a_headers, json={
        "name": "ALPHA-SECRET-RESPONSE", "description": "alpha private",
        "steps": [STEP],
    })
    playbook_id = created.json()["playbook_id"]

    listing = client.get("/api/v1/playbooks", headers=b_headers)
    assert "ALPHA-SECRET-RESPONSE" not in listing.text

    assert client.get(f"/api/v1/playbooks/{playbook_id}", headers=b_headers).status_code == 404
    assert client.put(f"/api/v1/playbooks/{playbook_id}", headers=b_headers,
                      json={"name": "HIJACKED-BY-B"}).status_code == 404
    assert client.post(f"/api/v1/playbooks/{playbook_id}/execute", headers=b_headers,
                       json={"context": {}}).status_code == 404
    assert client.get(f"/api/v1/playbooks/{playbook_id}/runs",
                      headers=b_headers).status_code == 404

    # 404 and not 403: a wrong-tenant caller must not be able to confirm the id
    # exists. And A's copy is untouched.
    still = client.get(f"/api/v1/playbooks/{playbook_id}", headers=a_headers)
    assert still.json()["name"] == "ALPHA-SECRET-RESPONSE"


def test_a_run_is_really_executed_and_labelled_simulated(client) -> None:
    """Execution used to be invented.

    The old handler ran nothing: it minted a run id and wrote
    status="completed", duration_seconds=0.5, step_results=[] — an
    incident-response product reporting a containment that never happened.
    A real run walks the steps, and every step says it was simulated so no
    one mistakes it for a real connector action.
    """
    headers, _ = _tenant(client, "runner")
    playbook_id = client.post("/api/v1/playbooks", headers=headers, json={
        "name": "RUNME", "description": "d", "steps": [STEP],
    }).json()["playbook_id"]

    run = client.post(f"/api/v1/playbooks/{playbook_id}/execute",
                      headers=headers, json={"context": {"alert": "x"}})
    assert run.status_code == 200, run.text
    body = run.json()
    assert body["step_results"], "a playbook with one step must report one result"
    assert body["step_results"][0]["output"]["execution_mode"] == "simulated"

    runs = client.get(f"/api/v1/playbooks/{playbook_id}/runs", headers=headers)
    assert runs.json()["total"] == 1, "the run must be persisted, not just returned"


def test_playbooks_survive_a_restart(client, tmp_path) -> None:
    """Storage must not be process-local.

    Rebuilding the engine against the same file is the closest honest analogue
    of a restart; the dicts it replaced could not have passed this.
    """
    headers, org = _tenant(client, "durable")
    playbook_id = client.post("/api/v1/playbooks", headers=headers, json={
        "name": "SURVIVES", "description": "d", "steps": [STEP],
    }).json()["playbook_id"]

    import os

    from core.security_playbook_engine import SecurityPlaybookEngine

    fresh = SecurityPlaybookEngine(
        db_path=f"{os.environ['FIXOPS_DATA_DIR']}/playbooks.db"
    )
    row = fresh.get_playbook(playbook_id, org)
    assert row is not None and row["name"] == "SURVIVES"


def test_the_compliance_score_is_never_invented(client) -> None:
    """A fabricated compliance score is the worst thing this API could emit.

    It used to return overall_score=72 with two named gaps for every
    framework and every org. The library's own assess_compliance is no better
    — `overall_score = 65 + (full_auto * 2)  # Mock calculation`, with org_id
    accepted and never read — so this endpoint must report the real catalog
    and nothing more until something evaluates tenant evidence.

    null, not 0: zero would claim a measurement was taken and failed.
    """
    headers, _ = _tenant(client, "compliance")
    body = client.get("/api/v1/compliance/soc2/assessment", headers=headers).json()

    assert body["overall_score"] is None
    assert body["assessed"] is False
    assert body["gaps"] == [] and body["recommendations"] == []
    assert body["total_controls"] > 0, "the control catalog itself is real"
    assert body["note"]


def test_every_advertised_template_can_actually_be_instantiated(client) -> None:
    """The listing and the instantiate endpoint must agree on identity.

    template_id is the library KEY. Using Playbook.playbook_id instead — a
    uuid4 minted at construction — made every advertised id un-instantiable
    and random per process. Caught only by trying the round trip.
    """
    headers, _ = _tenant(client, "templates")
    listed = client.get("/api/v1/compliance/templates", headers=headers).json()
    assert listed

    for template in listed:
        response = client.post(
            f"/api/v1/compliance/templates/{template['template_id']}/instantiate",
            headers=headers,
        )
        assert response.status_code == 200, (
            f"advertised template {template['template_id']!r} cannot be "
            f"instantiated: {response.status_code}"
        )
        # Whatever steps the template really has must survive instantiation —
        # the old handler produced an empty playbook for every id, including
        # the four that are authored.
        assert len(response.json()["steps"]) == template["step_count"]


def test_the_listing_admits_which_templates_are_empty(client) -> None:
    """17 of 21 shipped templates have no steps. Say so rather than imply parity.

    This is a real content gap in core.compliance_templates, not an API bug:
    only the four SOC2 templates are authored. A customer choosing
    "PCI DSS Network Scan" from a list that looks uniform would instantiate a
    playbook that does nothing. step_count is how they can tell, so this test
    exists to keep the signal honest — if the empty templates get authored,
    the count rises and nothing here breaks; if step_count silently stops
    being reported, this fails.
    """
    headers, _ = _tenant(client, "emptiness")
    listed = client.get("/api/v1/compliance/templates", headers=headers).json()

    assert all("step_count" in t for t in listed)
    authored = [t for t in listed if t["step_count"] > 0]
    assert authored, "no template ships any steps at all — check the library"
    for template in listed:
        instantiated = client.post(
            f"/api/v1/compliance/templates/{template['template_id']}/instantiate",
            headers=headers,
        ).json()
        assert len(instantiated["steps"]) == template["step_count"]


def test_templates_and_controls_agree_on_framework_names(client) -> None:
    """Two identifier spaces for one concept is where these bugs live.

    Template keys look like "pci_dss_network_scan"; splitting on the first
    underscore yields "pci" while the control catalog is keyed "pci_dss", so a
    client filtering templates with the name the controls endpoint uses got
    nothing.
    """
    headers, _ = _tenant(client, "frameworks")
    frameworks = {t["framework"] for t in
                  client.get("/api/v1/compliance/templates", headers=headers).json()}
    assert frameworks

    for framework in frameworks:
        templates = client.get(f"/api/v1/compliance/templates/{framework}", headers=headers)
        controls = client.get(f"/api/v1/compliance/controls/{framework}", headers=headers)
        assert templates.status_code == 200 and templates.json(), framework
        assert controls.status_code == 200 and controls.json(), framework


def test_an_unknown_framework_is_refused_not_invented(client) -> None:
    """Both endpoints used to synthesise content for any string at all."""
    headers, _ = _tenant(client, "unknown")
    assert client.get("/api/v1/compliance/not-a-framework/assessment",
                      headers=headers).status_code == 404
    assert client.get("/api/v1/compliance/controls/not-a-framework",
                      headers=headers).status_code == 404
