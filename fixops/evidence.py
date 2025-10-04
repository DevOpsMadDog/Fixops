"""Evidence hub responsible for persisting contextual bundles."""
from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from fixops.configuration import OverlayConfig


class EvidenceHub:
    """Persist evidence bundles derived from pipeline runs."""

    def __init__(self, overlay: OverlayConfig):
        self.overlay = overlay
        self.settings = overlay.evidence_settings

    def _base_directory(self) -> Path:
        directory = self.overlay.data_directories.get("evidence_dir")
        if directory is None:
            directory = Path("data") / "evidence" / self.overlay.mode
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def _bundle_name(self) -> str:
        return str(self.settings.get("bundle_name") or f"fixops-{self.overlay.mode}-run")

    def persist(
        self,
        pipeline_result: Mapping[str, Any],
        context_summary: Optional[Mapping[str, Any]],
        compliance_status: Optional[Mapping[str, Any]],
        policy_summary: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        run_id = uuid.uuid4().hex
        base_dir = self._base_directory() / run_id
        base_dir.mkdir(parents=True, exist_ok=True)

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
        _include("ai_agent_analysis", pipeline_result.get("ai_agent_analysis"))
        _include("ssdlc_assessment", pipeline_result.get("ssdlc_assessment"))

        bundle_path = base_dir / f"{self._bundle_name()}-bundle.json"
        bundle_path.write_text(json.dumps(bundle_payload, indent=2), encoding="utf-8")

        manifest = {
            "run_id": run_id,
            "mode": self.overlay.mode,
            "bundle": str(bundle_path),
            "sections": [
                key
                for key in bundle_payload.keys()
                if key not in {"mode", "run_id", "overlay"}
            ],
        }
        manifest_path = base_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        return {
            "bundle_id": run_id,
            "directory": str(base_dir),
            "files": {
                "bundle": str(bundle_path),
                "manifest": str(manifest_path),
            },
            "sections": included_sections,
        }


__all__ = ["EvidenceHub"]
