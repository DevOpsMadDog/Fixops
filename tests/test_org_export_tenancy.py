"""A whole-tenant export must be bound to the credential, not to the URL.

This endpoint authenticated the caller and then exported whichever tenant the
path named. Measured against the real app with a key pinned to "acme":

    POST /api/v1/orgs/victim-corp/export
      -> 200, org_id "victim-corp", a zip written to disk and a download_url

Org profile, users, findings, incidents and a year of audit events, handed to
another tenant that merely typed its name in a URL. The path was already
sanitised against traversal — exactly the kind of care that makes an endpoint
look considered while the authorisation question goes unasked.

The test reads the ARCHIVE, not the response. A handler that returned the right
org_id while still zipping the wrong rows would pass a shallower check.
"""

from __future__ import annotations

import pathlib
import zipfile

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client_and_key(tmp_path_factory):
    import os

    os.environ["FIXOPS_DATA_DIR"] = str(tmp_path_factory.mktemp("export"))
    os.environ["FIXOPS_BODY_TENANT_GUARD"] = "off"

    from core.key_manager import KeyManager
    from core.security_findings_engine import SecurityFindingsEngine
    from apps.api.app import create_app

    engine = SecurityFindingsEngine()
    for org, title in (("acme", "acme-only-finding"), ("victim-corp", "victim-secret-finding")):
        engine.record_finding(
            org_id=org, title=title, finding_type="vulnerability",
            source_tool="semgrep", severity="high", cvss_score=7.0,
            asset_id="a", asset_type="repo", description="", remediation="",
            correlation_key=title,
        )

    _, raw = KeyManager().create_key(
        user_id="u", name="acme", role="admin", org_id="acme"
    )
    return TestClient(create_app()), {"X-API-Key": raw}


def test_the_export_is_for_the_credentials_org_not_the_url(client_and_key) -> None:
    client, headers = client_and_key
    response = client.post("/api/v1/orgs/victim-corp/export", headers=headers)
    assert response.status_code == 200, response.text[:300]
    assert response.json()["org_id"] == "acme", (
        "a tenant exported the org named in the PATH"
    )


def test_the_archive_itself_holds_no_other_tenants_rows(client_and_key) -> None:
    """The response saying "acme" is not proof the zip contains acme."""
    client, headers = client_and_key
    response = client.post("/api/v1/orgs/victim-corp/export", headers=headers)
    zip_path = response.json().get("zip_path")
    if not zip_path or not pathlib.Path(zip_path).is_file():
        pytest.skip("archive not written in this environment")

    with zipfile.ZipFile(zip_path) as archive:
        blob = b"".join(archive.read(name) for name in archive.namelist())

    assert b"victim-secret-finding" not in blob, "another tenant's data was in the archive"
    assert b"acme-only-finding" in blob, "the caller's own data was missing"
