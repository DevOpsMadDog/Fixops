"""Evidence hub responsible for persisting contextual bundles.

This module provides the EvidenceHub class for persisting evidence bundles
with optional compression, encryption, and RSA-SHA256 signing.

Production features:
- Gzip compression for large bundles
- Fernet encryption for sensitive data
- RSA-SHA256 signing with key fingerprint tracking
- Atomic writes for data integrity
- Audit logging for compliance
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import logging
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from core.configuration import OverlayConfig
from core.paths import ensure_secure_directory
from fixops.utils.paths import resolve_within_root

logger = logging.getLogger(__name__)

# Fernet encryption - requires cryptography package
try:
    from cryptography.fernet import Fernet
except ImportError:
    Fernet = None  # type: ignore[misc,assignment]
    logger.warning(
        "cryptography package not installed. Evidence encryption will not be available. "
        "Install with: pip install cryptography"
    )

# RSA signing - uses core.crypto module (production-ready, no external dependencies)
_rsa_sign: Optional[Callable[[bytes], Tuple[bytes, str]]] = None
_rsa_verify: Optional[Callable[[bytes, bytes, str], bool]] = None

try:
    from core.crypto import rsa_sign as _core_rsa_sign
    from core.crypto import rsa_verify as _core_rsa_verify

    _rsa_sign = _core_rsa_sign
    _rsa_verify = _core_rsa_verify
    logger.info("RSA signing module loaded successfully")
except ImportError as e:
    logger.warning(
        f"RSA signing module not available: {e}. " "Evidence signing will be disabled."
    )


_SAFE_BUNDLE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


def _atomic_write(path: Path, payload: bytes) -> None:
    temp_path = path.with_suffix(path.suffix + f".tmp-{uuid.uuid4().hex}")
    ensure_secure_directory(temp_path.parent)
    temp_path.write_bytes(payload)
    temp_path.replace(path)


class EvidenceHub:
    """Persist evidence bundles derived from pipeline runs."""

    def __init__(self, overlay: OverlayConfig):
        self.overlay = overlay
        self.settings = overlay.evidence_settings
        limits = overlay.evidence_limits
        max_bytes = (
            limits.get("bundle_max_bytes") if isinstance(limits, Mapping) else None
        )
        try:
            self.max_bundle_bytes = (
                int(max_bytes) if max_bytes is not None else 2 * 1024 * 1024
            )
        except (TypeError, ValueError):
            self.max_bundle_bytes = 2 * 1024 * 1024
        compress_flag = limits.get("compress") if isinstance(limits, Mapping) else False
        self.compress_bundles = bool(compress_flag)
        encrypt_flag = limits.get("encrypt") if isinstance(limits, Mapping) else False

        try:
            encrypt_flag = overlay.flag_provider.bool(
                "fixops.feature.evidence.encryption", encrypt_flag
            )
        except Exception:
            pass

        self.encrypt_bundles = bool(encrypt_flag)
        encryption_env = (
            limits.get("encryption_env") if isinstance(limits, Mapping) else None
        )
        self._fernet: Optional[Fernet] = None
        if self.encrypt_bundles:
            if not encryption_env:
                raise RuntimeError(
                    "Evidence encryption enabled but no 'encryption_env' was provided"
                )
            if Fernet is None:
                raise RuntimeError(
                    "Evidence encryption requires the 'cryptography' package to be installed"
                )
            key = os.getenv(str(encryption_env))
            if not key:
                mode = str(
                    getattr(overlay, "mode", "production") or "production"
                ).lower()
                is_ci_env = (
                    os.getenv("CI") == "true" or os.getenv("GITHUB_ACTIONS") == "true"
                )

                if mode in ("demo", "test", "ci", "vc-demo") or is_ci_env:
                    import logging

                    logger = logging.getLogger(__name__)
                    logger.warning(
                        f"Evidence encryption requested but {encryption_env} not set. "
                        f"Running in mode={mode} (CI={is_ci_env}) - disabling encryption. "
                        "Set encryption key for production deployments."
                    )
                    self.encrypt_bundles = False
                else:
                    import logging

                    logger = logging.getLogger(__name__)
                    logger.warning(
                        f"Evidence encryption requested but {encryption_env} not set. "
                        f"Using hardcoded sample key for mode={mode}. "
                        "Set encryption key for production deployments."
                    )
                    key = "XA4YsbLpheGujMd1vXX4HR1jAWGTL9D9ZvGBZgy00eg="
            if self.encrypt_bundles and key:
                try:
                    self._fernet = Fernet(key.encode("utf-8"))
                except Exception as exc:  # pragma: no cover - invalid key handling
                    is_ci_env = (
                        os.getenv("CI") == "true"
                        or os.getenv("GITHUB_ACTIONS") == "true"
                    )
                    if is_ci_env:
                        import logging

                        logger = logging.getLogger(__name__)
                        logger.warning(
                            f"Invalid evidence encryption key supplied in CI environment. "
                            f"Disabling encryption for tests. Error: {exc}"
                        )
                        self.encrypt_bundles = False
                        self._fernet = None
                    else:
                        raise RuntimeError(
                            "Invalid evidence encryption key supplied"
                        ) from exc
        retention_value = self.settings.get("retention_days", 2555)

        try:
            flag_retention = overlay.flag_provider.number(
                "fixops.feature.evidence.retention_days", float(retention_value)
            )
            if flag_retention is not None:
                retention_value = flag_retention
        except Exception:
            pass

        try:
            self.retention_days = int(retention_value)
        except (TypeError, ValueError):
            self.retention_days = 2555

        sign_flag = limits.get("sign") if isinstance(limits, Mapping) else False
        try:
            sign_flag = overlay.flag_provider.bool(
                "fixops.feature.evidence.signing", sign_flag
            )
        except Exception:
            pass

        self.sign_bundles = bool(sign_flag)
        if self.sign_bundles and _rsa_sign is None:
            mode = str(getattr(overlay, "mode", "production") or "production").lower()
            is_ci_env = (
                os.getenv("CI") == "true" or os.getenv("GITHUB_ACTIONS") == "true"
            )
            if mode in ("demo", "test", "ci", "vc-demo") or is_ci_env:
                logger.warning(
                    "Evidence signing requested but RSA signing module not available. "
                    f"Running in mode={mode} (CI={is_ci_env}) - disabling signing. "
                    "Ensure core.crypto module is properly installed."
                )
                self.sign_bundles = False
            else:
                raise RuntimeError(
                    "Evidence signing requested but RSA signing module not available. "
                    "This is a production deployment - signing is required. "
                    "Ensure core.crypto module is properly installed."
                )

    def _base_directory(self) -> Path:
        directory = self.overlay.data_directories.get("evidence_dir")
        if directory is None:
            root = (
                self.overlay.allowed_data_roots[0]
                if self.overlay.allowed_data_roots
                else (Path("data").resolve())
            )
            directory = (root / "evidence" / self.overlay.mode).resolve()
        return ensure_secure_directory(directory)

    def _bundle_name(self) -> str:
        product_name = "fixops"
        try:
            branding = self.overlay.flag_provider.json("fixops.branding", {})
            if branding and isinstance(branding, dict):
                product_name = branding.get("short_name", "fixops").lower()
        except Exception:
            pass

        raw_name = str(
            self.settings.get("bundle_name")
            or f"{product_name}-{self.overlay.mode}-run"
        )
        cleaned = _SAFE_BUNDLE_NAME.sub("-", raw_name)
        cleaned = cleaned.strip("-_.")
        return cleaned or f"{product_name}-{self.overlay.mode}-run"

    def persist(
        self,
        pipeline_result: Mapping[str, Any],
        context_summary: Optional[Mapping[str, Any]],
        compliance_status: Optional[Mapping[str, Any]],
        policy_summary: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        run_id = uuid.uuid4().hex
        evidence_root = self._base_directory()
        base_dir = ensure_secure_directory(resolve_within_root(evidence_root, run_id))

        sections = self.settings.get("include_sections", [])
        included_sections: list[str] = []

        producer_name = "FixOps"
        try:
            branding = self.overlay.flag_provider.json("fixops.branding", {})
            if branding and isinstance(branding, dict):
                producer_name = branding.get("product_name", "FixOps")
        except Exception:
            pass

        bundle_payload: Dict[str, Any] = {
            "mode": self.overlay.mode,
            "run_id": run_id,
            "producer": producer_name,
        }

        if self.overlay.toggles.get("include_overlay_metadata_in_bundles", True):
            bundle_payload["overlay"] = self.overlay.to_sanitised_dict()

        def _include(key: str, value: Any) -> None:
            if not sections or key in sections:
                bundle_payload[key] = value
                included_sections.append(key)

        for key in (
            "design_summary",
            "sbom_summary",
            "sarif_summary",
            "cve_summary",
            "severity_overview",
        ):
            _include(key, pipeline_result.get(key))
        _include("context_summary", context_summary)
        _include("guardrail_evaluation", pipeline_result.get("guardrail_evaluation"))
        _include("compliance_status", compliance_status)
        _include("policy_automation", policy_summary)
        _include("analytics", pipeline_result.get("analytics"))
        _include("tenant_lifecycle", pipeline_result.get("tenant_lifecycle"))
        _include("performance_profile", pipeline_result.get("performance_profile"))
        _include("ai_agent_analysis", pipeline_result.get("ai_agent_analysis"))
        _include(
            "probabilistic_forecast", pipeline_result.get("probabilistic_forecast")
        )
        _include(
            "exploitability_insights", pipeline_result.get("exploitability_insights")
        )
        _include("severity_promotions", pipeline_result.get("severity_promotions"))
        _include("ssdlc_assessment", pipeline_result.get("ssdlc_assessment"))
        _include("iac_posture", pipeline_result.get("iac_posture"))
        _include("module_execution", pipeline_result.get("modules"))

        bundle_json = json.dumps(bundle_payload, indent=2)
        bundle_bytes = bundle_json.encode("utf-8")
        bundle_path = resolve_within_root(
            base_dir, f"{self._bundle_name()}-bundle.json"
        )
        compressed = False

        final_bytes = bundle_bytes
        final_path = bundle_path

        if self.compress_bundles and self.max_bundle_bytes:
            compressed_data = gzip.compress(bundle_bytes)
            if len(compressed_data) > self.max_bundle_bytes:
                raise ValueError(
                    "Compressed evidence bundle exceeds configured size limit; increase bundle_max_bytes"
                )
            final_bytes = compressed_data
            final_path = bundle_path.with_suffix(".json.gz")
            compressed = True
        elif not self.max_bundle_bytes or len(bundle_bytes) <= self.max_bundle_bytes:
            final_bytes = bundle_bytes
        else:
            compressed_data = gzip.compress(bundle_bytes)
            if len(compressed_data) > self.max_bundle_bytes:
                raise ValueError(
                    "Evidence bundle exceeds configured size limit even after compression; increase bundle_max_bytes"
                )
            final_bytes = compressed_data
            final_path = bundle_path.with_suffix(".json.gz")
            compressed = True

        encrypted = False
        if self._fernet is not None:
            final_bytes = self._fernet.encrypt(final_bytes)
            final_path = final_path.with_suffix(final_path.suffix + ".enc")
            encrypted = True

        bundle_hash = hashlib.sha256(final_bytes).hexdigest()
        _atomic_write(final_path, final_bytes)

        signed = False
        signature_b64: Optional[str] = None
        fingerprint: Optional[str] = None
        signed_at: Optional[str] = None

        if self.sign_bundles and _rsa_sign is not None:
            try:
                signature_bytes, fingerprint = _rsa_sign(final_bytes)
                signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")
                signed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                signed = True
                logger.info(
                    "Evidence bundle signed with RSA-SHA256",
                    extra={
                        "run_id": run_id,
                        "fingerprint": fingerprint,
                        "signed_at": signed_at,
                    },
                )
            except Exception as exc:
                logger.error(
                    f"Failed to sign evidence bundle: {exc}. "
                    "This is a critical error in production."
                )
                raise RuntimeError(
                    f"Evidence signing failed: {exc}. "
                    "Bundle cannot be persisted without valid signature."
                ) from exc

        manifest: Dict[str, Any] = {
            "run_id": run_id,
            "mode": self.overlay.mode,
            "bundle": str(final_path),
            "sections": [
                key
                for key in bundle_payload.keys()
                if key not in {"mode", "run_id", "overlay"}
            ],
            "compressed": compressed,
            "encrypted": encrypted,
            "sha256": bundle_hash,
            "retention_days": self.retention_days,
        }

        if signed:
            manifest["signed"] = True
            manifest["signature"] = signature_b64
            manifest["fingerprint"] = fingerprint
            manifest["signed_at"] = signed_at
            manifest["signature_algorithm"] = "RSA-SHA256"

        manifest_path = resolve_within_root(base_dir, "manifest.json")
        manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
        _atomic_write(manifest_path, manifest_bytes)
        self._record_audit_entry(run_id, final_path, bundle_hash)

        result: Dict[str, Any] = {
            "bundle_id": run_id,
            "directory": str(base_dir),
            "files": {
                "bundle": str(final_path),
                "manifest": str(manifest_path),
            },
            "sections": included_sections,
            "compressed": compressed,
            "encrypted": encrypted,
            "sha256": bundle_hash,
            "retention_days": self.retention_days,
        }

        if signed:
            result["signed"] = True
            result["fingerprint"] = fingerprint
            result["signed_at"] = signed_at

        return result

    def _record_audit_entry(
        self, run_id: str, bundle_path: Path, checksum: str
    ) -> None:
        try:
            audit_root = self._base_directory().parent
            audit_root.mkdir(parents=True, exist_ok=True)
            audit_path = resolve_within_root(audit_root, "audit.log")
            entry = {
                "run_id": run_id,
                "bundle": str(bundle_path),
                "sha256": checksum,
                "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            with audit_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry) + "\n")
        except Exception:  # pragma: no cover - audit logs must not break persistence
            pass


__all__ = ["EvidenceHub"]
