"""Ingest must record WHERE a vulnerability lives, not only which package.

This is the wiring that turns ``docs/REACHABILITY_MEASURED_2026-08-29.md`` from
a script result into product behaviour. Measured there: with only a package
name, reachability answers "do you use this library" and every finding comes
back reachable — 0% noise reduction. With the symbol, two of three real CVEs
were ruled out.

The SARIF below carries the VERBATIM advisory text of two real CVEs found in
this repository's own dependencies, and it exercises both outcomes that matter:

* PYSEC-2026-3552 names three functions in backticks → symbols recorded.
* PYSEC-2026-3554 names no function, only the hostnames ``foo.example.com`` and
  ``*.example.com`` from its wildcard example → **no field at all**.

The second is the one worth guarding. A hostname is shaped exactly like a module
path, and an earlier version of the extractor happily "ruled out" that CVE by
searching a call graph for a domain name. Absent-means-undetermined keeps the
finding in the queue where a human sees it; an empty list would read downstream
as "nothing to reach", which is a safety claim nobody established.
"""

from __future__ import annotations

import io
import json

import pytest
from fastapi.testclient import TestClient


SARIF = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [
        {
            "tool": {"driver": {"name": "pip-audit"}},
            "results": [
                {
                    "ruleId": "PYSEC-2026-3552",
                    "level": "error",
                    "message": {
                        "text": "`pkcs7_decrypt_der`, `pkcs7_decrypt_pem`, and "
                        "`pkcs7_decrypt_smime` reported the outcome of decrypting a "
                        "`RecipientInfo`'s `encryptedKey` in distinguishable ways."
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "requirements.txt"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                },
                {
                    "ruleId": "PYSEC-2026-3554",
                    "level": "error",
                    "message": {
                        "text": "If an intermediate constrained CA permits the DNS name "
                        "`foo.example.com`, and the leaf certificate has a wildcard in its "
                        "DNS SAN of `*.example.com`, the verifier accepts."
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "requirements.txt"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                },
            ],
        }
    ],
}


@pytest.fixture(scope="module")
def client() -> TestClient:
    from apps.api.app import create_app

    return TestClient(create_app())


def _upload(client: TestClient) -> list[dict]:
    import os

    token = os.environ.get("FIXOPS_API_TOKEN", "")
    response = client.post(
        "/api/v1/scanner-ingest/upload",
        files={"file": ("scan.sarif", io.BytesIO(json.dumps(SARIF).encode()), "application/json")},
        data={"scanner_type": "sarif"},
        headers={"X-API-Key": token} if token else {},
    )
    if response.status_code in (401, 403):
        pytest.skip("no ingest credential configured in this environment")
    assert response.status_code == 200, response.text
    return response.json().get("findings") or []


def _by_text(findings: list[dict], needle: str) -> dict:
    for f in findings:
        blob = f"{f.get('title', '')} {f.get('description', '')}"
        if needle in blob:
            return f
    pytest.fail(f"no ingested finding mentioning {needle!r}; got {len(findings)}")


def test_an_advisory_that_names_functions_gets_them_recorded(client: TestClient) -> None:
    finding = _by_text(_upload(client), "pkcs7_decrypt_der")
    symbols = finding.get("vulnerable_symbols")
    assert symbols, (
        "the advisory names three functions in backticks and none were recorded — "
        "reachability will fall back to a package-level query and report every "
        "finding as reachable"
    )
    assert "pkcs7_decrypt_der" in symbols


def test_backticked_data_types_are_not_recorded_as_symbols(client: TestClient) -> None:
    """`RecipientInfo` is what the flaw operates on, not an entry point."""
    finding = _by_text(_upload(client), "pkcs7_decrypt_der")
    assert "RecipientInfo" not in (finding.get("vulnerable_symbols") or [])


def test_an_advisory_naming_no_function_gets_no_field(client: TestClient) -> None:
    finding = _by_text(_upload(client), "foo.example.com")
    assert "vulnerable_symbols" not in finding, (
        "a hostname is shaped like a module path; recording it would let the "
        "engine confidently rule out a CVE by searching for a domain name. "
        "Absent means undetermined and keeps the finding in the queue."
    )


def test_the_upload_response_reflects_what_was_recorded(client: TestClient) -> None:
    """The response used to re-serialise the findings a second time, bypassing
    enrichment — so it advertised findings with no symbol field while the stored
    ones had it. A caller reading the response would conclude ingest had not
    enriched anything."""
    findings = _upload(client)
    assert any(f.get("vulnerable_symbols") for f in findings), (
        "no ingested finding in the RESPONSE carries a symbol; the response is "
        "serialising separately from the path that enriches"
    )
