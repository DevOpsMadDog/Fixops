"""High-level evidence bundling helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from evidence.packager import BundleInputs, create_bundle, evaluate_policy, load_policy

from .store import EvidenceStore


class EvidencePackager:
    """Compose bundle generation with the new lifecycle store."""

    def __init__(self, store: EvidenceStore | None = None) -> None:
        self._store = store or EvidenceStore()

    def register_run(self, overlay: Mapping[str, Any]) -> str:
        """Register a run and return its identifier."""

        run = self._store.register_run(overlay)
        return run.run_id

    def attach_artifact(self, run_id: str, kind: str, path: Path, sha256: str) -> None:
        """Record an artefact in the lifecycle store."""

        self._store.attach_artifact(run_id, kind, path, sha256)

    def sign_manifest(self, run_id: str, manifest: Mapping[str, Any]) -> Mapping[str, Any]:
        """Persist manifest metadata before bundling."""

        return self._store.sign_manifest(run_id, manifest)

    def bundle(self, inputs: BundleInputs) -> Mapping[str, Any]:
        """Create the evidence bundle using canonical packager helpers."""

        return create_bundle(inputs)


__all__ = [
    "BundleInputs",
    "EvidencePackager",
    "evaluate_policy",
    "load_policy",
]
