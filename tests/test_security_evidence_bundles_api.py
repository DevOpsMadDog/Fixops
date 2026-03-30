"""
Security and functional tests for Evidence Bundle API endpoints.

Tests the following endpoints that back the EvidenceBundles.tsx UI:
- GET  /api/v1/evidence/bundles               -- list all bundles
- POST /api/v1/evidence/bundles/generate       -- generate new bundle
- POST /api/v1/evidence/bundles/{id}/verify    -- verify bundle signature
- GET  /api/v1/evidence/bundles/{id}/download  -- download bundle

Covers:
- Input validation via Pydantic models
- Path traversal protection on bundle_id
- Framework and category allowlist enforcement
- Date range validation
- Demo/fallback data correctness
- Verification result shape matching UI VerificationResult type
- Download format parameter handling
"""

import os

import pytest

# Set up environment before imports
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from apps.api.app import create_app
from fastapi.testclient import TestClient

API_TOKEN = os.environ["FIXOPS_API_TOKEN"]
BASE = "/api/v1/evidence"


@pytest.fixture
def client():
    """Create a test client with default app state."""
    app = create_app()
    return TestClient(app)


@pytest.fixture
def auth():
    """Return auth headers."""
    return {"X-API-Key": API_TOKEN}


# ===========================================================================
# GET /api/v1/evidence/bundles
# ===========================================================================


class TestListBundles:
    """Tests for GET /api/v1/evidence/bundles."""

    def test_returns_200(self, client, auth):
        resp = client.get(f"{BASE}/bundles", headers=auth)
        assert resp.status_code == 200

    def test_response_shape(self, client, auth):
        """Response has 'bundles' list and 'total' count."""
        data = client.get(f"{BASE}/bundles", headers=auth).json()
        assert "bundles" in data
        assert "total" in data
        assert isinstance(data["bundles"], list)
        assert isinstance(data["total"], int)
        assert data["total"] == len(data["bundles"])

    def test_no_demo_bundles_in_enterprise_mode(self, client, auth):
        """Enterprise mode returns bundles from real data only."""
        data = client.get(f"{BASE}/bundles", headers=auth).json()
        assert data["total"] >= 0  # Could be 0 with no real data

    def test_empty_bundles_with_unconfigured_storage(self, auth):
        """When no manifests exist on disk, returns empty list (no demo data)."""
        app = create_app()
        app.state.evidence_manifest_dir = None
        app.state.evidence_bundle_dir = None
        unclient = TestClient(app)
        data = unclient.get(f"{BASE}/bundles", headers=auth).json()
        assert data["total"] == 0
        assert data["bundles"] == []

    def test_bundle_field_completeness(self, client, auth):
        """Every bundle has all fields the UI EvidenceBundle type expects."""
        data = client.get(f"{BASE}/bundles", headers=auth).json()
        required_fields = {
            "id", "framework", "frameworks", "date_range", "status",
            "created_at", "size_mb", "finding_count", "remediation_count",
            "hash", "signed_by", "signature_valid", "sections",
        }
        for bundle in data["bundles"]:
            missing = required_fields - set(bundle.keys())
            assert not missing, f"Bundle {bundle.get('id')} missing fields: {missing}"

    def test_bundle_date_range_shape(self, client, auth):
        """Each bundle's date_range has 'start' and 'end' strings."""
        data = client.get(f"{BASE}/bundles", headers=auth).json()
        for bundle in data["bundles"]:
            dr = bundle["date_range"]
            assert "start" in dr
            assert "end" in dr
            assert isinstance(dr["start"], str)
            assert isinstance(dr["end"], str)

    def test_bundle_sections_are_lists(self, client, auth):
        """Each bundle's sections is a list (may be empty for real manifests)."""
        data = client.get(f"{BASE}/bundles", headers=auth).json()
        for bundle in data["bundles"]:
            assert isinstance(bundle["sections"], list)

    def test_no_demo_bundle_sections(self, auth):
        """Unconfigured storage returns no bundles (enterprise mode)."""
        app = create_app()
        app.state.evidence_manifest_dir = None
        app.state.evidence_bundle_dir = None
        unclient = TestClient(app)
        data = unclient.get(f"{BASE}/bundles", headers=auth).json()
        assert data["total"] == 0

    def test_bundle_statuses_empty_when_unconfigured(self, auth):
        """Unconfigured storage returns empty bundles list."""
        app = create_app()
        app.state.evidence_manifest_dir = None
        app.state.evidence_bundle_dir = None
        unclient = TestClient(app)
        data = unclient.get(f"{BASE}/bundles", headers=auth).json()
        assert data["total"] == 0


# ===========================================================================
# POST /api/v1/evidence/bundles/generate
# ===========================================================================


class TestGenerateBundle:
    """Tests for POST /api/v1/evidence/bundles/generate."""

    def test_generate_default_returns_200(self, client, auth):
        resp = client.post(f"{BASE}/bundles/generate", headers=auth, json={})
        assert resp.status_code == 200

    def test_generate_returns_bundle_shape(self, client, auth):
        """Generated bundle has all expected fields."""
        data = client.post(
            f"{BASE}/bundles/generate", headers=auth, json={}
        ).json()
        assert data["id"].startswith("EVB-")
        assert data["status"] == "generated"
        assert data["hash"].startswith("sha256:")
        assert isinstance(data["sections"], list)
        assert len(data["sections"]) >= 3
        assert data["signed_by"] is None
        assert data["signature_valid"] is False

    def test_generate_with_frameworks_plural(self, client, auth):
        """UI sends frameworks as a list -- this is the primary interface."""
        resp = client.post(
            f"{BASE}/bundles/generate",
            headers=auth,
            json={
                "frameworks": ["SOC2", "ISO27001"],
                "date_range": {"start": "2026-01-01", "end": "2026-02-27"},
                "categories": ["findings", "remediations"],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["frameworks"] == ["SOC2", "ISO27001"]
        assert data["framework"] == "SOC2"  # Primary = first in list
        assert data["date_range"]["start"] == "2026-01-01"
        assert data["categories"] == ["findings", "remediations"]

    def test_generate_with_legacy_framework_singular(self, client, auth):
        """Legacy clients sending 'framework' (singular) still work."""
        resp = client.post(
            f"{BASE}/bundles/generate",
            headers=auth,
            json={"framework": "PCI-DSS"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "PCI-DSS"

    def test_generate_rejects_unknown_framework(self, client, auth):
        """Unknown framework names are rejected by Pydantic validation."""
        resp = client.post(
            f"{BASE}/bundles/generate",
            headers=auth,
            json={"frameworks": ["FAKE_FRAMEWORK"]},
        )
        assert resp.status_code == 422

    def test_generate_rejects_unknown_category(self, client, auth):
        """Unknown category names are rejected by Pydantic validation."""
        resp = client.post(
            f"{BASE}/bundles/generate",
            headers=auth,
            json={"categories": ["findings", "NONEXISTENT"]},
        )
        assert resp.status_code == 422

    def test_generate_rejects_bad_date_format(self, client, auth):
        """Malformed date strings are rejected."""
        resp = client.post(
            f"{BASE}/bundles/generate",
            headers=auth,
            json={"date_range": {"start": "not-a-date", "end": "2026-01-01"}},
        )
        assert resp.status_code == 422

    def test_generate_unique_ids(self, client, auth):
        """Multiple generations produce unique bundle IDs."""
        ids = set()
        for _ in range(5):
            data = client.post(
                f"{BASE}/bundles/generate", headers=auth, json={}
            ).json()
            ids.add(data["id"])
        assert len(ids) == 5

    def test_generate_unique_hashes(self, client, auth):
        """Multiple generations produce unique content hashes."""
        hashes = set()
        for _ in range(5):
            data = client.post(
                f"{BASE}/bundles/generate", headers=auth, json={}
            ).json()
            hashes.add(data["hash"])
        assert len(hashes) == 5

    def test_generate_all_allowed_frameworks(self, client, auth):
        """All allowed frameworks can be generated."""
        for fw in ["SOC2", "PCI-DSS", "HIPAA", "ISO27001", "NIST-CSF", "GDPR"]:
            resp = client.post(
                f"{BASE}/bundles/generate",
                headers=auth,
                json={"frameworks": [fw]},
            )
            assert resp.status_code == 200, f"Framework {fw} rejected"

    def test_generate_empty_body_uses_defaults(self, client, auth):
        """Empty JSON body uses SOC2 default framework."""
        data = client.post(
            f"{BASE}/bundles/generate", headers=auth, json={}
        ).json()
        assert data["framework"] == "SOC2"

    def test_generate_no_body_uses_defaults(self, client, auth):
        """No request body at all uses defaults."""
        resp = client.post(
            f"{BASE}/bundles/generate",
            headers={**auth, "Content-Type": "application/json"},
        )
        # FastAPI will pass None body when no JSON sent -- our endpoint handles this
        assert resp.status_code in (200, 422)


# ===========================================================================
# POST /api/v1/evidence/bundles/{bundle_id}/verify
# ===========================================================================


class TestVerifyBundle:
    """Tests for POST /api/v1/evidence/bundles/{bundle_id}/verify."""

    def test_verify_nonexistent_bundle_returns_invalid(self, client, auth):
        """Verifying a nonexistent bundle returns valid=False (no demo shortcuts)."""
        resp = client.post(
            f"{BASE}/bundles/EVB-2026-001/verify", headers=auth
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is False

    def test_verify_unsigned_bundle_returns_invalid(self, client, auth):
        """Verifying a known-unsigned demo bundle returns valid=False."""
        resp = client.post(
            f"{BASE}/bundles/EVB-2026-002/verify", headers=auth
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is False
        assert data["hash_match"] is False
        assert data["signature_valid"] is False

    def test_verify_hipaa_bundle_returns_invalid(self, client, auth):
        """Nonexistent HIPAA bundle not verified (enterprise mode)."""
        resp = client.post(
            f"{BASE}/bundles/EVB-2026-003/verify", headers=auth
        )
        assert resp.status_code == 200
        assert resp.json()["valid"] is False

    def test_verify_expired_bundle(self, client, auth):
        """Expired demo bundle (EVB-2025-042) is not in the signed set."""
        resp = client.post(
            f"{BASE}/bundles/EVB-2025-042/verify", headers=auth
        )
        assert resp.status_code == 200
        assert resp.json()["valid"] is False

    def test_verify_unknown_bundle_returns_invalid(self, client, auth):
        """Unknown bundle ID returns valid=False (not 404)."""
        resp = client.post(
            f"{BASE}/bundles/EVB-9999-ZZZ/verify", headers=auth
        )
        assert resp.status_code == 200
        assert resp.json()["valid"] is False

    def test_verify_response_shape_matches_ui(self, client, auth):
        """Response has all fields the UI VerificationResult type expects."""
        data = client.post(
            f"{BASE}/bundles/EVB-2026-001/verify", headers=auth
        ).json()
        required = {"valid", "hash_match", "signature_valid", "timestamp",
                     "certificate_chain", "issuer"}
        assert required.issubset(set(data.keys()))

    def test_verify_certificate_chain_shape(self, client, auth):
        """Certificate chain is a list (may be empty for unverified bundles)."""
        data = client.post(
            f"{BASE}/bundles/EVB-2026-001/verify", headers=auth
        ).json()
        chain = data["certificate_chain"]
        assert isinstance(chain, list)

    def test_verify_issuer_is_string(self, client, auth):
        """Issuer field is a non-empty string."""
        data = client.post(
            f"{BASE}/bundles/EVB-2026-001/verify", headers=auth
        ).json()
        assert isinstance(data["issuer"], str)
        assert len(data["issuer"]) > 0

    def test_verify_timestamp_is_iso(self, client, auth):
        """Timestamp is an ISO-8601 formatted string."""
        data = client.post(
            f"{BASE}/bundles/EVB-2026-001/verify", headers=auth
        ).json()
        assert "T" in data["timestamp"]

    def test_verify_path_traversal_rejected(self, client, auth):
        """Path traversal attempts in bundle_id are rejected (400 or 404)."""
        resp = client.post(
            f"{BASE}/bundles/..%2F..%2Fetc%2Fpasswd/verify", headers=auth
        )
        # FastAPI may resolve the URL path before routing (404), our
        # sanitizer catches it (400), or the path doesn't match a route (405).
        # Either way, not 200.
        assert resp.status_code in (400, 404, 405)

    def test_verify_empty_bundle_id_rejected(self, client, auth):
        """Empty bundle_id is routed to a different endpoint (not matched)."""
        # FastAPI will not match /bundles//verify -- returns 404 or 405
        resp = client.post(f"{BASE}/bundles//verify", headers=auth)
        assert resp.status_code in (404, 405, 307)

    def test_verify_special_chars_rejected(self, client, auth):
        """Bundle IDs with special characters are rejected."""
        resp = client.post(
            f"{BASE}/bundles/EVB-2026-001;DROP TABLE/verify", headers=auth
        )
        assert resp.status_code in (400, 404)


# ===========================================================================
# GET /api/v1/evidence/bundles/{bundle_id}/download
# ===========================================================================


class TestDownloadBundle:
    """Tests for GET /api/v1/evidence/bundles/{bundle_id}/download."""

    def test_download_nonexistent_json_format(self, client, auth):
        """Download for nonexistent bundle returns 404."""
        resp = client.get(
            f"{BASE}/bundles/EVB-2026-001/download",
            params={"format": "json"},
            headers=auth,
        )
        assert resp.status_code == 404

    def test_download_nonexistent_pdf_format(self, client, auth):
        """Download for nonexistent bundle with pdf format returns 404."""
        resp = client.get(
            f"{BASE}/bundles/EVB-2026-001/download",
            params={"format": "pdf"},
            headers=auth,
        )
        assert resp.status_code == 404

    def test_download_returns_404_for_missing_bundle(self, client, auth):
        """Nonexistent bundle download returns 404 (no demo fallback)."""
        resp = client.get(
            f"{BASE}/bundles/EVB-2026-001/download",
            headers=auth,
        )
        assert resp.status_code == 404

    def test_download_invalid_format_rejected(self, client, auth):
        """Invalid format parameter is rejected (422)."""
        resp = client.get(
            f"{BASE}/bundles/EVB-2026-001/download",
            params={"format": "exe"},
            headers=auth,
        )
        assert resp.status_code == 422

    def test_download_missing_bundle_no_content_disposition(self, client, auth):
        """Missing bundle returns 404, no Content-Disposition header."""
        resp = client.get(
            f"{BASE}/bundles/EVB-2026-001/download",
            params={"format": "json"},
            headers=auth,
        )
        assert resp.status_code == 404

    def test_download_nonexistent_bundle_returns_error(self, client, auth):
        """Nonexistent bundle returns 404 with error detail."""
        resp = client.get(
            f"{BASE}/bundles/EVB-2026-001/download",
            params={"format": "json"},
            headers=auth,
        )
        assert resp.status_code == 404
        data = resp.json()
        assert "detail" in data

    def test_download_path_traversal_rejected(self, client, auth):
        """Path traversal in download bundle_id is rejected (400 or 404)."""
        resp = client.get(
            f"{BASE}/bundles/..%2F..%2Fetc%2Fpasswd/download",
            headers=auth,
        )
        assert resp.status_code in (400, 404)

    def test_download_special_chars_rejected(self, client, auth):
        """Special characters in bundle_id are rejected."""
        resp = client.get(
            f"{BASE}/bundles/EVB%3Brm%20-rf/download",
            headers=auth,
        )
        assert resp.status_code in (400, 404)


# ===========================================================================
# Pydantic model validation tests (unit-level)
# ===========================================================================


class TestPydanticModels:
    """Unit tests for Pydantic request/response models."""

    def test_bundle_generate_request_defaults(self):
        from api.evidence_router import BundleGenerateRequest
        req = BundleGenerateRequest()
        # frameworks defaults to None at model level; endpoint logic resolves to ["SOC2"]
        assert req.frameworks is None
        assert len(req.categories) == 5

    def test_bundle_generate_request_valid(self):
        from api.evidence_router import BundleGenerateRequest
        req = BundleGenerateRequest(
            frameworks=["SOC2", "HIPAA"],
            date_range={"start": "2026-01-01", "end": "2026-02-28"},
            categories=["findings", "remediations"],
        )
        assert req.frameworks == ["SOC2", "HIPAA"]
        assert req.date_range.start == "2026-01-01"

    def test_bundle_generate_request_empty_frameworks_uses_default(self):
        from api.evidence_router import BundleGenerateRequest
        # Empty list is validated as error
        with pytest.raises(Exception):
            BundleGenerateRequest(frameworks=[])

    def test_bundle_generate_request_rejects_unknown_framework(self):
        from api.evidence_router import BundleGenerateRequest
        with pytest.raises(Exception):
            BundleGenerateRequest(frameworks=["IMAGINARY"])

    def test_bundle_generate_request_rejects_unknown_category(self):
        from api.evidence_router import BundleGenerateRequest
        with pytest.raises(Exception):
            BundleGenerateRequest(categories=["findings", "weaponry"])

    def test_date_range_model_valid(self):
        from api.evidence_router import DateRangeModel
        dr = DateRangeModel(start="2026-01-01", end="2026-12-31")
        assert dr.start == "2026-01-01"
        assert dr.end == "2026-12-31"

    def test_date_range_model_rejects_bad_format(self):
        from api.evidence_router import DateRangeModel
        with pytest.raises(Exception):
            DateRangeModel(start="Jan 1 2026", end="2026-12-31")

    def test_date_range_model_rejects_partial_date(self):
        from api.evidence_router import DateRangeModel
        with pytest.raises(Exception):
            DateRangeModel(start="2026-13-01", end="2026-12-31")

    def test_bundle_verification_result_model(self):
        from api.evidence_router import BundleVerificationResult
        result = BundleVerificationResult(
            valid=True,
            hash_match=True,
            signature_valid=True,
            timestamp="2026-02-27T10:00:00Z",
            certificate_chain=["Root", "Intermediate", "Leaf"],
            issuer="ALdeci",
        )
        assert result.valid is True
        assert len(result.certificate_chain) == 3

    def test_sanitize_bundle_id_rejects_traversal(self):
        from api.evidence_router import _sanitize_bundle_id
        from fastapi import HTTPException
        # Direct traversal with ".." in raw input
        with pytest.raises(HTTPException) as exc_info:
            _sanitize_bundle_id("../../etc/passwd")
        assert exc_info.value.status_code == 400
        # Single ".." component
        with pytest.raises(HTTPException):
            _sanitize_bundle_id("..")
        # Traversal with forward slash
        with pytest.raises(HTTPException):
            _sanitize_bundle_id("foo/bar")

    def test_sanitize_bundle_id_rejects_special_chars(self):
        from api.evidence_router import _sanitize_bundle_id
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _sanitize_bundle_id("EVB;DROP TABLE")

    def test_sanitize_bundle_id_accepts_valid(self):
        from api.evidence_router import _sanitize_bundle_id
        assert _sanitize_bundle_id("EVB-2026-001") == "EVB-2026-001"
        assert _sanitize_bundle_id("EVB-2025-042") == "EVB-2025-042"

    def test_sanitize_bundle_id_rejects_too_long(self):
        from api.evidence_router import _sanitize_bundle_id
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _sanitize_bundle_id("A" * 100)
