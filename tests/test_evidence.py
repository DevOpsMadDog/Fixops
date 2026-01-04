import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from core.configuration import OverlayConfig
from core.evidence import EvidenceHub


def test_evidence_hub_persists_manifest_and_checksum(tmp_path: Path) -> None:
    overlay = OverlayConfig(
        mode="enterprise",
        data={"evidence_dir": str(tmp_path / "evidence")},
        limits={
            "evidence": {"bundle_max_bytes": 4096, "compress": False, "encrypt": False}
        },
        evidence_hub={"bundle_name": "integration-test"},
    )
    overlay.allowed_data_roots = (tmp_path,)

    hub = EvidenceHub(overlay)
    pipeline_result = {
        "design_summary": {"rows": 3},
        "sbom_summary": {"components": 2},
        "sarif_summary": {"findings": 4},
        "cve_summary": {"records": 2},
        "severity_overview": {"highest": "high"},
    }
    context_summary = {"summary": {"highest_score": 9}}
    compliance_status = {"status": "satisfied"}
    policy_summary = {"status": "ready"}

    result = hub.persist(
        pipeline_result, context_summary, compliance_status, policy_summary
    )

    bundle_path = Path(result["files"]["bundle"])
    manifest_path = Path(result["files"]["manifest"])
    assert bundle_path.exists()
    assert manifest_path.exists()
    assert result["sha256"]

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["sha256"] == result["sha256"]

    # Audit log is written to the parent of the evidence directory (shared across runs)
    # bundle_path.parent = run_id directory
    # bundle_path.parent.parent = evidence directory (base_directory)
    # bundle_path.parent.parent.parent = parent of evidence directory (where audit.log is)
    audit_log = bundle_path.parent.parent.parent / "audit.log"
    assert audit_log.exists()
    assert bundle_path.name in audit_log.read_text(encoding="utf-8")


class TestEvidenceHubCoverageGaps:
    """Tests to cover missing lines in evidence.py for diff-cover compliance."""

    def test_flag_provider_bool_exception_handling(self, tmp_path: Path) -> None:
        """Test that flag_provider.bool() exception is handled gracefully.

        Covers lines 184-185 in evidence.py.
        """
        overlay = OverlayConfig(
            mode="enterprise",
            data={"evidence_dir": str(tmp_path / "evidence")},
            limits={
                "evidence": {
                    "bundle_max_bytes": 4096,
                    "compress": False,
                    "encrypt": False,
                    "sign": True,
                }
            },
        )
        overlay.allowed_data_roots = (tmp_path,)

        # Create a mock flag_provider that raises on bool()
        class RaisingFlagProvider:
            def bool(self, key, default):
                raise Exception("Flag provider error")

            def number(self, key, default):
                return default

            def json(self, key, default):
                return default

        # Patch the flag_provider property
        with patch.object(
            type(overlay), "flag_provider", property(lambda self: RaisingFlagProvider())
        ):
            # Should not raise, just use the default sign_flag value
            hub = EvidenceHub(overlay)
            assert hub is not None

    def test_sign_bundles_disabled_in_demo_mode_when_rsa_unavailable(
        self, tmp_path: Path
    ) -> None:
        """Test that signing is disabled in demo mode when RSA module unavailable.

        Covers lines 189-190, 193-194, 199 in evidence.py.
        """
        overlay = OverlayConfig(
            mode="demo",
            data={"evidence_dir": str(tmp_path / "evidence")},
            limits={
                "evidence": {
                    "bundle_max_bytes": 4096,
                    "compress": False,
                    "encrypt": False,
                    "sign": True,
                }
            },
        )
        overlay.allowed_data_roots = (tmp_path,)

        # Patch _rsa_sign to None to simulate RSA module unavailable
        with patch("core.evidence._rsa_sign", None):
            hub = EvidenceHub(overlay)
            # In demo mode, signing should be disabled gracefully
            assert hub.sign_bundles is False

    def test_sign_bundles_raises_in_production_when_rsa_unavailable(
        self, tmp_path: Path
    ) -> None:
        """Test that RuntimeError is raised in production when RSA unavailable.

        Covers line 201 in evidence.py.
        """
        overlay = OverlayConfig(
            mode="production",
            data={"evidence_dir": str(tmp_path / "evidence")},
            limits={
                "evidence": {
                    "bundle_max_bytes": 4096,
                    "compress": False,
                    "encrypt": False,
                    "sign": True,
                }
            },
        )
        overlay.allowed_data_roots = (tmp_path,)

        # Patch _rsa_sign to None and ensure we're not in CI mode
        with patch("core.evidence._rsa_sign", None):
            with patch.dict(os.environ, {"CI": "", "GITHUB_ACTIONS": ""}, clear=False):
                with pytest.raises(RuntimeError) as exc_info:
                    EvidenceHub(overlay)
                assert (
                    "Evidence signing requested but RSA signing module not available"
                    in str(exc_info.value)
                )

    def test_persist_with_signing_success(self, tmp_path: Path) -> None:
        """Test persist() with successful RSA signing.

        Covers lines 344-349, 383-387, 409-411 in evidence.py.
        """
        overlay = OverlayConfig(
            mode="enterprise",
            data={"evidence_dir": str(tmp_path / "evidence")},
            limits={
                "evidence": {
                    "bundle_max_bytes": 4096,
                    "compress": False,
                    "encrypt": False,
                    "sign": True,
                }
            },
        )
        overlay.allowed_data_roots = (tmp_path,)

        # Create a mock rsa_sign function
        mock_signature = b"mock_signature_bytes"
        mock_fingerprint = "abc123fingerprint"

        def mock_rsa_sign(data: bytes):
            return (mock_signature, mock_fingerprint)

        with patch("core.evidence._rsa_sign", mock_rsa_sign):
            hub = EvidenceHub(overlay)
            assert hub.sign_bundles is True

            pipeline_result = {
                "design_summary": {"rows": 3},
                "sbom_summary": {"components": 2},
            }

            result = hub.persist(pipeline_result, None, None, None)

            # Verify signing metadata in result
            assert result.get("signed") is True
            assert result.get("fingerprint") == mock_fingerprint
            assert "signed_at" in result

            # Verify manifest contains signing info
            manifest_path = Path(result["files"]["manifest"])
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            assert manifest.get("signed") is True
            assert manifest.get("signature") is not None
            assert manifest.get("fingerprint") == mock_fingerprint
            assert manifest.get("signature_algorithm") == "RSA-SHA256"

    def test_persist_with_signing_failure_raises(self, tmp_path: Path) -> None:
        """Test persist() raises RuntimeError when signing fails.

        Covers lines 357-358, 362 in evidence.py.
        """
        overlay = OverlayConfig(
            mode="enterprise",
            data={"evidence_dir": str(tmp_path / "evidence")},
            limits={
                "evidence": {
                    "bundle_max_bytes": 4096,
                    "compress": False,
                    "encrypt": False,
                    "sign": True,
                }
            },
        )
        overlay.allowed_data_roots = (tmp_path,)

        # Create a mock rsa_sign function that raises
        def mock_rsa_sign_failure(data: bytes):
            raise Exception("Signing failed")

        with patch("core.evidence._rsa_sign", mock_rsa_sign_failure):
            hub = EvidenceHub(overlay)
            assert hub.sign_bundles is True

            pipeline_result = {
                "design_summary": {"rows": 3},
            }

            with pytest.raises(RuntimeError) as exc_info:
                hub.persist(pipeline_result, None, None, None)
            assert "Evidence signing failed" in str(exc_info.value)

    def test_persist_with_signing_failure_and_cleanup_failure(
        self, tmp_path: Path, caplog
    ) -> None:
        """Test persist() handles cleanup failure after signing failure.

        Covers lines 356-357 in evidence.py - the exception handling when
        cleanup of orphaned bundle file fails.
        """
        overlay = OverlayConfig(
            mode="enterprise",
            data={"evidence_dir": str(tmp_path / "evidence")},
            limits={
                "evidence": {
                    "bundle_max_bytes": 4096,
                    "compress": False,
                    "encrypt": False,
                    "sign": True,
                }
            },
        )
        overlay.allowed_data_roots = (tmp_path,)

        # Create a mock rsa_sign function that raises
        def mock_rsa_sign_failure(data: bytes):
            raise Exception("Signing failed")

        # Track the original unlink method
        original_unlink = Path.unlink

        def mock_unlink_failure(self, missing_ok=False):
            # Only fail for bundle files in the evidence directory
            if "evidence" in str(self) and self.suffix == ".json":
                raise PermissionError("Cannot delete file")
            return original_unlink(self, missing_ok=missing_ok)

        with patch("core.evidence._rsa_sign", mock_rsa_sign_failure):
            with patch.object(Path, "unlink", mock_unlink_failure):
                hub = EvidenceHub(overlay)
                assert hub.sign_bundles is True

                pipeline_result = {
                    "design_summary": {"rows": 3},
                }

                with pytest.raises(RuntimeError) as exc_info:
                    hub.persist(pipeline_result, None, None, None)
                assert "Evidence signing failed" in str(exc_info.value)

                # Verify the cleanup failure warning was logged
                assert any(
                    "Failed to clean up orphaned bundle file" in record.message
                    for record in caplog.records
                )

    def test_sign_bundles_disabled_in_ci_environment(self, tmp_path: Path) -> None:
        """Test that signing is disabled in CI environment when RSA unavailable.

        Covers lines 189-194, 199 in evidence.py (CI branch).
        """
        overlay = OverlayConfig(
            mode="production",  # Even in production mode
            data={"evidence_dir": str(tmp_path / "evidence")},
            limits={
                "evidence": {
                    "bundle_max_bytes": 4096,
                    "compress": False,
                    "encrypt": False,
                    "sign": True,
                }
            },
        )
        overlay.allowed_data_roots = (tmp_path,)

        # Patch _rsa_sign to None and set CI environment
        with patch("core.evidence._rsa_sign", None):
            with patch.dict(os.environ, {"CI": "true"}, clear=False):
                hub = EvidenceHub(overlay)
                # In CI, signing should be disabled gracefully even in production mode
                assert hub.sign_bundles is False

    def test_sign_bundles_disabled_in_github_actions(self, tmp_path: Path) -> None:
        """Test that signing is disabled in GitHub Actions when RSA unavailable.

        Covers lines 189-194, 199 in evidence.py (GitHub Actions branch).
        """
        overlay = OverlayConfig(
            mode="production",
            data={"evidence_dir": str(tmp_path / "evidence")},
            limits={
                "evidence": {
                    "bundle_max_bytes": 4096,
                    "compress": False,
                    "encrypt": False,
                    "sign": True,
                }
            },
        )
        overlay.allowed_data_roots = (tmp_path,)

        # Patch _rsa_sign to None and set GITHUB_ACTIONS environment
        with patch("core.evidence._rsa_sign", None):
            with patch.dict(
                os.environ, {"CI": "", "GITHUB_ACTIONS": "true"}, clear=False
            ):
                hub = EvidenceHub(overlay)
                # In GitHub Actions, signing should be disabled gracefully
                assert hub.sign_bundles is False

    def test_base_directory_fallback_when_evidence_dir_not_set(
        self, tmp_path: Path
    ) -> None:
        """Test _base_directory fallback when evidence_dir is not set.

        Covers lines 201, 206 in evidence.py.
        """
        overlay = OverlayConfig(
            mode="enterprise",
            data={},  # No evidence_dir set
            limits={
                "evidence": {
                    "bundle_max_bytes": 4096,
                    "compress": False,
                    "encrypt": False,
                }
            },
        )
        overlay.allowed_data_roots = (tmp_path,)

        hub = EvidenceHub(overlay)
        base_dir = hub._base_directory()

        # Should use allowed_data_roots[0] / "evidence" / mode
        expected_dir = tmp_path / "evidence" / "enterprise"
        assert base_dir == expected_dir
        assert base_dir.exists()
