"""HTTP-layer tests for POST /api/v1/classification/assets/{asset_id}/auto-classify.

Covers the PII/PHI/PCI sensitive-data-discovery endpoint in
suite-api/apps/api/data_classification_router.py backed by the real
DataClassificationEngine (SQLite in-memory via tmp_path).

No mocks for business logic — engine is real, only auth + org_id
dependencies are overridden to avoid API-key infrastructure.

Tests:
    1. PII content (SSN) → detected_categories includes PII, applied=True by default
    2. PCI content (Visa card) → detected_categories includes PCI
    3. Credentials content (AWS key) → recommended_level >= SECRET
    4. Clean content → empty detected_categories, UNCLASSIFIED recommended
    5. apply=False → result not persisted (no asset record created)
    6. Auto-classify upgrades an existing lower-level asset (never downgrades)

Usage:
    pytest tests/test_data_classification_auto_classify_api.py -v --timeout=10
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure suite paths are importable
_suite_core = str(Path(__file__).parent.parent / "suite-core")
_suite_api = str(Path(__file__).parent.parent / "suite-api")
for _p in (_suite_core, _suite_api):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from core.data_classification import (
    ClassificationLevel,
    ClassifiedAsset,
    DataCategory,
    DataClassificationEngine,
)
from apps.api.data_classification_router import router, _engine
from apps.api.dependencies import get_org_id

_ORG = "org-auto-classify-tests"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return DataClassificationEngine(db_path=str(tmp_path / "test_autoclassify.db"))


@pytest.fixture
def client(engine):
    """FastAPI TestClient with auth + org_id bypassed, real engine injected."""
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[_engine] = lambda: engine
    app.dependency_overrides[get_org_id] = lambda: _ORG
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _auto_classify(client, asset_id: str, content: str, apply: bool = True):
    return client.post(
        f"/api/v1/classification/assets/{asset_id}/auto-classify",
        json={"content": content, "apply": apply},
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAutoClassifyPIIDetection:
    def test_ssn_content_detects_pii(self, client):
        r = _auto_classify(client, "ac-ssn-001", "Patient SSN: 123-45-6789")
        assert r.status_code == 200
        body = r.json()
        assert "PII" in body["detected_categories"]
        assert body["applied"] is True

    def test_visa_card_detects_pci(self, client):
        r = _auto_classify(client, "ac-pci-001", "Card: 4111-1111-1111-1111 exp 12/26")
        assert r.status_code == 200
        body = r.json()
        assert "PCI" in body["detected_categories"]

    def test_aws_key_recommends_secret_or_higher(self, client):
        r = _auto_classify(client, "ac-cred-001", "AKIAIOSFODNN7EXAMPLE secret key")
        assert r.status_code == 200
        body = r.json()
        assert "CREDENTIALS" in body["detected_categories"]
        level_order = {
            "UNCLASSIFIED": 0, "CUI": 1, "CONFIDENTIAL": 2, "SECRET": 3, "TOP_SECRET": 4
        }
        assert level_order[body["recommended_level"]] >= level_order["SECRET"]

    def test_clean_content_no_categories_unclassified(self, client):
        r = _auto_classify(
            client, "ac-clean-001",
            "The quick brown fox jumps over the lazy dog."
        )
        assert r.status_code == 200
        body = r.json()
        assert body["detected_categories"] == []
        assert body["recommended_level"] == "UNCLASSIFIED"

    def test_apply_false_does_not_persist_asset(self, client, engine):
        asset_id = "ac-noapply-001"
        r = _auto_classify(client, asset_id, "SSN: 123-45-6789", apply=False)
        assert r.status_code == 200
        assert r.json()["applied"] is False
        # Engine must have no record for this asset
        assert engine.get_asset_classification(asset_id) is None

    def test_auto_classify_upgrades_existing_asset_never_downgrades(self, client, engine):
        # Pre-create a CUI asset
        existing = ClassifiedAsset(
            id="ac-upgrade-001",
            name="upgrade test",
            classification_level=ClassificationLevel.CUI,
            categories=[DataCategory.CONFIGURATION],
            org_id=_ORG,
        )
        engine.classify_asset(existing)

        # Scan credentials content — should upgrade to SECRET+
        r = _auto_classify(client, "ac-upgrade-001", "AKIAIOSFODNN7EXAMPLE private key")
        assert r.status_code == 200
        assert r.json()["applied"] is True

        stored = engine.get_asset_classification("ac-upgrade-001")
        level_order = {
            "UNCLASSIFIED": 0, "CUI": 1, "CONFIDENTIAL": 2, "SECRET": 3, "TOP_SECRET": 4
        }
        assert level_order[stored.classification_level.value] >= level_order["SECRET"]
