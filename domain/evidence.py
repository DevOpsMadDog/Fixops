"""Domain objects for evidence lifecycle management."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List


@dataclass(slots=True)
class EvidenceAttachment:
    """Single artefact associated with a run."""

    kind: str
    path: Path
    sha256: str


@dataclass(slots=True)
class EvidenceRun:
    """State container for evidence collected during a run."""

    run_id: str
    overlay_mode: str
    attachments: List[EvidenceAttachment] = field(default_factory=list)
    manifest: Dict[str, Any] = field(default_factory=dict)

    def add_attachment(self, attachment: EvidenceAttachment) -> None:
        self.attachments.append(attachment)

    def to_manifest(self) -> Dict[str, Any]:
        payload = dict(self.manifest)
        payload.setdefault("run_id", self.run_id)
        payload.setdefault("mode", self.overlay_mode)
        payload["attachments"] = [
            {"kind": item.kind, "path": str(item.path), "sha256": item.sha256}
            for item in self.attachments
        ]
        return payload
