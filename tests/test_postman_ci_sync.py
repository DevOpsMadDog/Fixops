"""Ensure Postman CI/CD suites stay aligned with hard-block, evidence, and signature scenarios."""

from __future__ import annotations

import json
from pathlib import Path


def test_postman_collection_contains_alignment_scenarios() -> None:
    path = Path("enterprise/postman/FixOps-CICD-Tests.postman_collection.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data.get("item"), list)

    items = {item.get("name"): item for item in data["item"] if isinstance(item, dict)}

    kev = items.get("KEV Hard Block Without Waiver")
    assert kev is not None
    kev_request = kev.get("request", {})
    assert kev_request.get("method") == "POST"
    assert kev_request.get("url", "").endswith("/policy/evaluate")

    evidence = items.get("Signed Evidence Retrieval")
    assert evidence is not None
    assert evidence.get("request", {}).get("method") == "GET"
    assert "/decisions/evidence/" in evidence.get("request", {}).get("url", "")

    negative = items.get("Negative Signature Verification")
    assert negative is not None
    assert negative.get("request", {}).get("method") == "POST"
    assert "/cicd/verify-signature" in negative.get("request", {}).get("url", "")
