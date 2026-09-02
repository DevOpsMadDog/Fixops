"""The credential decides the tenant on the endpoints a customer actually uses.

Each of these took org_id straight from the request body while ALSO taking a
credential, so a key pinned to one tenant could write into another by naming it.
Measured before the fix, key pinned to "acme", body naming "victim-corp":

    POST /api/v1/evidence-vault/evidence  ->  201, stored under 'victim-corp'

Evidence is what an auditor reads, so a wrong org_id there is not a display bug.

These tests drive the real app with a real managed key rather than seeding
request state, because seeding state is exactly what let the body-tenant guard
pass its unit tests while being a no-op in production.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

VICTIM = "victim-corp"


@pytest.fixture(scope="module")
def client_and_key(tmp_path_factory):
    import os

    data_dir = tmp_path_factory.mktemp("tenancy")
    os.environ["FIXOPS_DATA_DIR"] = str(data_dir)
    # The guard is a second line of defence; this file tests the routers' own
    # resolution, so it must not be what produces the pass.
    os.environ["FIXOPS_BODY_TENANT_GUARD"] = "off"

    from core.key_manager import KeyManager
    from apps.api.app import create_app

    _, raw = KeyManager().create_key(
        user_id="u1", name="acme", role="admin", org_id="acme"
    )
    return TestClient(create_app()), {"X-API-Key": raw}


CASES = [
    (
        "evidence-vault store",
        "post",
        "/api/v1/evidence-vault/evidence",
        {
            "evidence_name": "soc2-access-review",
            "evidence_type": "document",
            "framework": "SOC2",
            "control_id": "CC6.1",
            "collected_by": "auditor",
            "collection_method": "manual",
            "content": "quarterly access review",
        },
    ),
    (
        "auto-evidence collect/config",
        "post",
        "/api/v1/auto-evidence/collect/config",
        {"control_id": "CC6.1", "framework": "SOC2"},
    ),
    (
        "cloud-findings ingest",
        "post",
        "/api/v1/cloud-findings/findings",
        {
            "provider": "aws",
            "account_id": "1",
            "region": "us-east-1",
            "resource_type": "s3",
            "resource_id": "b1",
            "finding_title": "public bucket",
            "finding_type": "misconfiguration",
            "severity": "high",
        },
    ),
    (
        "universal-ingest register source",
        "post",
        "/api/v1/ingest/source",
        {"source_name": "acme-src", "schema_mapping": {"id": "id"}},
    ),
    (
        "findings lifecycle reconcile",
        "post",
        "/api/v1/findings/lifecycle/reconcile",
        {"prior_scan_id": "s1", "current_scan_id": "s2"},
    ),
]


@pytest.mark.parametrize("label,method,path,payload", CASES, ids=[c[0] for c in CASES])
def test_a_body_cannot_redirect_a_pinned_credential(
    label, method, path, payload, client_and_key
) -> None:
    client, headers = client_and_key
    response = getattr(client, method)(
        path, headers=headers, json={**payload, "org_id": VICTIM}
    )
    assert response.status_code in (200, 201), response.text[:300]
    assert response.json().get("org_id") == "acme", (
        f"{label} wrote into the tenant the BODY named, not the one the "
        f"credential pinned"
    )


def test_the_routers_resolve_rather_than_merely_dropping_org_id() -> None:
    """Absence of the bad pattern is not presence of the fix.

    A handler that deleted org_id entirely would also stop leaking, and would
    also be broken. Require the resolution helper AND the credential dependency.
    """
    import pathlib

    api = pathlib.Path(__file__).resolve().parents[1] / "suite-api" / "apps" / "api"
    for filename in (
        "evidence_vault_router.py",
        "auto_evidence_router.py",
        "cloud_security_findings_router.py",
        "universal_ingest_router.py",
        "findings_lifecycle_router.py",
    ):
        code = (api / filename).read_text()
        assert "resolve_tenant" in code, f"{filename} resolves no tenant at all"
        assert "get_org_id" in code, f"{filename} takes no credential org"
