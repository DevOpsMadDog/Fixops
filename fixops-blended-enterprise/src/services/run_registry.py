"""Run registry for organising per-run artefacts."""

from __future__ import annotations

import datetime as _dt
import json
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from src.services import signing

ARTEFACTS_ROOT = Path("artefacts")

_CANONICAL_OUTPUTS: set[str] = {
    "requirements.json",
    "design.manifest.json",
    "build.report.json",
    "test.report.json",
    "deploy.manifest.json",
    "operate.snapshot.json",
    "decision.json",
}


@dataclass(slots=True)
class RunContext:
    """Represents a materialised run folder for an application."""

    app_id: str
    run_id: str
    root: Path

    @property
    def run_path(self) -> Path:
        return self.root / self.app_id / self.run_id

    @property
    def inputs_dir(self) -> Path:
        return self.run_path / "inputs"

    @property
    def outputs_dir(self) -> Path:
        return self.run_path / "outputs"

    @property
    def signed_outputs_dir(self) -> Path:
        return self.outputs_dir / "signed"

    @property
    def transparency_index(self) -> Path:
        return self.outputs_dir / "transparency.index"

    def save_input(self, name: str, payload: bytes | bytearray | Mapping[str, Any] | Iterable[Any] | str) -> Path:
        """Persist an input payload beneath the run's inputs directory."""

        target = self.inputs_dir / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(payload, (bytes, bytearray)):
            target.write_bytes(bytes(payload))
        elif isinstance(payload, Mapping) or isinstance(payload, Iterable) and not isinstance(payload, (str, bytes, bytearray)):
            # Treat mapping or iterable structures as JSON
            target.write_text(_json_dumps(payload))
        else:
            target.write_text(str(payload))
        return target

    def write_output(self, name: str, document: Mapping[str, Any] | Iterable[Any]) -> Path:
        """Persist a canonical output document and return the file path."""

        if name not in _CANONICAL_OUTPUTS:
            raise ValueError(f"Unsupported output name: {name}")
        target = self.outputs_dir / name
        target.parent.mkdir(parents=True, exist_ok=True)
        content = _json_dumps(document)
        target.write_text(content)
        self._maybe_sign(name, document, content)
        return target

    def write_binary_output(self, name: str, blob: bytes) -> Path:
        target = self.outputs_dir / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
        return target

    def load_input_json(self, name: str) -> Any:
        path = self.inputs_dir / name
        if not path.exists():
            raise FileNotFoundError(path)
        return json.loads(path.read_text())

    def load_output_json(self, name: str) -> Any:
        path = self.outputs_dir / name
        if not path.exists():
            raise FileNotFoundError(path)
        return json.loads(path.read_text())

    def relative_to_outputs(self, path: Path) -> str:
        rel = Path("..") / path.relative_to(self.run_path)
        return str(rel)

    def _maybe_sign(self, name: str, document: Mapping[str, Any] | Iterable[Any], content: str) -> None:
        if not isinstance(document, Mapping):
            return
        try:
            envelope = signing.sign_manifest(document)
        except signing.SigningError:
            return
        signature_path = self.signed_outputs_dir / f"{name}.manifest.json"
        signature_path.parent.mkdir(parents=True, exist_ok=True)
        signature_path.write_text(_json_dumps(envelope))
        digest = envelope.get("digest", {}).get("sha256")
        timestamp = _dt.datetime.utcnow().isoformat() + "Z"
        line = f"{timestamp} {name} sha256={digest or hashlib.sha256(content.encode('utf-8')).hexdigest()} kid={envelope.get('kid') or 'unknown'}\n"
        self.transparency_index.parent.mkdir(parents=True, exist_ok=True)
        with self.transparency_index.open("a", encoding="utf-8") as handle:
            handle.write(line)


def resolve_run(app_id: str | None) -> RunContext:
    """Resolve or create the run context for the provided application identifier."""

    normalised_app = _normalise_app_id(app_id)
    run_id = _dt.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    root = ARTEFACTS_ROOT
    run_dir = root / normalised_app / run_id
    _prepare_directories(run_dir)
    return RunContext(app_id=normalised_app, run_id=run_id, root=root)


def _normalise_app_id(app_id: str | None) -> str:
    if not app_id:
        return "APP-UNKNOWN"
    candidate = app_id.strip() or "APP-UNKNOWN"
    safe = [ch if ch.isalnum() or ch in ("-", "_") else "-" for ch in candidate]
    return "".join(safe)


def _json_dumps(data: Mapping[str, Any] | Iterable[Any]) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)


def reopen_run(app_id: str | None, run_id: str) -> RunContext:
    """Return a run context for an existing run identifier."""

    normalised_app = _normalise_app_id(app_id)
    root = ARTEFACTS_ROOT
    run_dir = root / normalised_app / run_id
    if not run_dir.exists():
        raise FileNotFoundError(run_dir)
    _prepare_directories(run_dir)
    return RunContext(app_id=normalised_app, run_id=run_id, root=root)


def _prepare_directories(run_dir: Path) -> None:
    (run_dir / "inputs").mkdir(parents=True, exist_ok=True)
    (run_dir / "outputs" / "signed").mkdir(parents=True, exist_ok=True)
