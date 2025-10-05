"""Evidence hub responsible for persisting contextual bundles."""
from __future__ import annotations

import gzip
import json
import os
import re
import uuid
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from fixops.configuration import OverlayConfig
from fixops.paths import ensure_secure_directory

try:  # Optional dependency used when regulated tenants request encryption
    from cryptography.fernet import Fernet
except Exception:  # pragma: no cover - cryptography is optional
    Fernet = None  # type: ignore[assignment]


_SAFE_BUNDLE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


class EvidenceHub:
    """Persist evidence bundles derived from pipeline runs."""

    def __init__(self, overlay: OverlayConfig):
        self.overlay = overlay
        self.settings = overlay.evidence_settings
        limits = overlay.evidence_limits
        max_bytes = limits.get("bundle_max_bytes") if isinstance(limits, Mapping) else None
        try:
            self.max_bundle_bytes = int(max_bytes) if max_bytes is not None else 2 * 1024 * 1024
        except (TypeError, ValueError):
            self.max_bundle_bytes = 2 * 1024 * 1024
        compress_flag = limits.get("compress") if isinstance(limits, Mapping) else False
        self.compress_bundles = bool(compress_flag)
        encrypt_flag = limits.get("encrypt") if isinstance(limits, Mapping) else False
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
                raise RuntimeError(
                    f"Evidence encryption requested but environment variable '{encryption_env}' is not set"
                )
            try:
                self._fernet = Fernet(key.encode("utf-8"))
            except Exception as exc:  # pragma: no cover - invalid key handling
                raise RuntimeError("Invalid evidence encryption key supplied") from exc

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
        raw_name = str(
            self.settings.get("bundle_name") or f"fixops-{self.overlay.mode}-run"
        )
        cleaned = _SAFE_BUNDLE_NAME.sub("-", raw_name)
        cleaned = cleaned.strip("-_.")
        return cleaned or f"fixops-{self.overlay.mode}-run"

    def persist(
        self,
        pipeline_result: Mapping[str, Any],
        context_summary: Optional[Mapping[str, Any]],
        compliance_status: Optional[Mapping[str, Any]],
        policy_summary: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        run_id = uuid.uuid4().hex
        base_dir = ensure_secure_directory(self._base_directory() / run_id)

        sections = self.settings.get("include_sections", [])
        included_sections: list[str] = []
        bundle_payload: Dict[str, Any] = {
            "mode": self.overlay.mode,
            "run_id": run_id,
        }

        if self.overlay.toggles.get("include_overlay_metadata_in_bundles", True):
            bundle_payload["overlay"] = self.overlay.to_sanitised_dict()

        def _include(key: str, value: Any) -> None:
            if not sections or key in sections:
                bundle_payload[key] = value
                included_sections.append(key)

        for key in ("design_summary", "sbom_summary", "sarif_summary", "cve_summary", "severity_overview"):
            _include(key, pipeline_result.get(key))
        _include("context_summary", context_summary)
        _include("guardrail_evaluation", pipeline_result.get("guardrail_evaluation"))
        _include("compliance_status", compliance_status)
        _include("policy_automation", policy_summary)
        _include("analytics", pipeline_result.get("analytics"))
        _include("tenant_lifecycle", pipeline_result.get("tenant_lifecycle"))
        _include("performance_profile", pipeline_result.get("performance_profile"))
        _include("ai_agent_analysis", pipeline_result.get("ai_agent_analysis"))
        _include("probabilistic_forecast", pipeline_result.get("probabilistic_forecast"))
        _include("exploitability_insights", pipeline_result.get("exploitability_insights"))
        _include("ssdlc_assessment", pipeline_result.get("ssdlc_assessment"))
        _include("iac_posture", pipeline_result.get("iac_posture"))
        _include("module_execution", pipeline_result.get("modules"))

        bundle_json = json.dumps(bundle_payload, indent=2)
        bundle_bytes = bundle_json.encode("utf-8")
        bundle_path = base_dir / f"{self._bundle_name()}-bundle.json"
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

        final_path.write_bytes(final_bytes)

        manifest = {
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
        }
        manifest_path = base_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        return {
            "bundle_id": run_id,
            "directory": str(base_dir),
            "files": {
                "bundle": str(final_path),
                "manifest": str(manifest_path),
            },
            "sections": included_sections,
            "compressed": compressed,
            "encrypted": encrypted,
        }


__all__ = ["EvidenceHub"]
