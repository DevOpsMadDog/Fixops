"""Evidence lifecycle helpers with a minimal public surface."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Mapping, MutableMapping

from core.configuration import OverlayConfig
from domain import EvidenceAttachment, EvidenceRun


class EvidenceStore:
    """Track run-scoped evidence attachments before packaging."""

    def __init__(self) -> None:
        self._runs: MutableMapping[str, EvidenceRun] = {}

    def register_run(self, overlay: OverlayConfig | Mapping[str, object]) -> EvidenceRun:
        """Create a new evidence run anchored to the overlay mode."""

        mode = overlay.mode if isinstance(overlay, OverlayConfig) else str(overlay.get("mode", "demo"))
        run_id = uuid.uuid4().hex
        run = EvidenceRun(run_id=run_id, overlay_mode=mode)
        self._runs[run_id] = run
        return run

    def attach_artifact(self, run_id: str, kind: str, path: Path, sha256: str) -> EvidenceAttachment:
        """Associate an artefact with the stored run."""

        run = self._require_run(run_id)
        attachment = EvidenceAttachment(kind=kind, path=path, sha256=sha256)
        run.add_attachment(attachment)
        return attachment

    def sign_manifest(self, run_id: str, manifest: Mapping[str, object]) -> Mapping[str, object]:
        """Persist the manifest metadata alongside attachments."""

        run = self._require_run(run_id)
        run.manifest.update(manifest)
        payload = run.to_manifest()
        run.manifest = dict(payload)
        return payload

    def _require_run(self, run_id: str) -> EvidenceRun:
        try:
            return self._runs[run_id]
        except KeyError as exc:  # pragma: no cover - defensive guard
            raise KeyError(f"Evidence run '{run_id}' is not registered") from exc
