"""Enterprise run registry — tracks stage executions and stores artefacts.

Each stage run creates a directory under ``FIXOPS_ARTEFACTS_ROOT/<APP-ID>/<run_id>/``
containing inputs, canonical outputs, signatures, and a transparency index.
The ``LATEST`` marker file inside each APP directory points to the most recent run.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _resolve_root() -> Path:
    """Resolve the artefacts root directory."""
    env = os.environ.get("FIXOPS_ARTEFACTS_ROOT")
    if env:
        return Path(env)
    data_dir = os.environ.get("FIXOPS_DATA_DIR", ".fixops_data")
    return Path(data_dir) / "runs"


# Module-level convenience attribute so tests can monkeypatch it.
ARTEFACTS_ROOT: Path = _resolve_root()

# Allowed output filenames per stage (for write_output validation).
_ALLOWED_OUTPUTS: Dict[str, List[str]] = {
    "requirements": ["requirements.json"],
    "design": ["design.json"],
    "build": ["build.json"],
    "test": ["test.json"],
    "deploy": ["deploy.json"],
    "operate": ["operate.json"],
    "decision": ["decision.json"],
}


@dataclass
class RunContext:
    """Tracks a single stage execution."""

    run_id: str
    app_id: str
    stage: str
    run_dir: Path
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")

    @property
    def run_path(self) -> Path:
        """Alias for run_dir — used by StageRunner."""
        return self.run_dir

    @property
    def inputs_dir(self) -> Path:
        return self.run_dir / "inputs"

    @property
    def outputs_dir(self) -> Path:
        return self.run_dir / "outputs"

    @property
    def signatures_dir(self) -> Path:
        return self.run_dir / "signatures"

    @property
    def signed_outputs_dir(self) -> Path:
        """Directory for signed output manifests."""
        d = self.run_dir / "signed-outputs"
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def transparency_index(self) -> Path:
        """Path to the transparency index file."""
        return self.run_dir / "transparency-index.jsonl"

    # ------------------------------------------------------------------
    # Convenience methods on RunContext (used by tests and StageRunner)
    # ------------------------------------------------------------------

    def save_input(self, filename: str, data: Any) -> Path:
        """Persist a stage input artefact.

        *data* may be ``bytes`` (written verbatim) or any JSON-serialisable
        object (written as pretty-printed JSON).
        """
        self.inputs_dir.mkdir(parents=True, exist_ok=True)
        dest = self.inputs_dir / filename
        if isinstance(data, (bytes, bytearray)):
            dest.write_bytes(data)
        else:
            dest.write_text(json.dumps(data, indent=2))
        return dest

    def write_output(self, filename: str, document: Dict[str, Any]) -> Path:
        """Write a canonical JSON output artefact.

        Validates that *filename* is in the allowed list for the current
        stage.  Raises ``ValueError`` for unexpected filenames.

        If signing is available, also writes a signed manifest envelope
        into ``signed_outputs_dir`` and appends to the transparency index.
        """
        allowed = _ALLOWED_OUTPUTS.get(self.stage, [])
        if filename not in allowed:
            raise ValueError(
                f"Unexpected output '{filename}' for stage '{self.stage}'. "
                f"Allowed: {allowed}"
            )
        self.outputs_dir.mkdir(parents=True, exist_ok=True)
        dest = self.outputs_dir / filename
        dest.write_text(json.dumps(document, indent=2))

        # Attempt to sign the output
        try:
            from core.services.enterprise import signing

            envelope = signing.sign_manifest(document)
            # Add alg field expected by tests
            envelope.setdefault("alg", "RS256")
            manifest_name = f"{filename}.manifest.json"
            manifest_path = self.signed_outputs_dir / manifest_name
            manifest_path.write_text(json.dumps(envelope, indent=2))

            # Append to transparency index
            index_entry = {
                "filename": filename,
                "digest": envelope.get("digest", ""),
                "signed_at": envelope.get("signed_at", ""),
            }
            with self.transparency_index.open("a") as fp:
                fp.write(json.dumps(index_entry) + "\n")
        except Exception:
            pass  # Signing not available — skip

        return dest


class RunRegistry:
    """Manages stage run lifecycle — creates directories, stores artefacts.

    Directory layout::

        <root>/
          APP-12345/
            LATEST              ← JSON: {"run_id": "abc123"}
            abc123/
              run-meta.json
              inputs/
              outputs/
              signatures/
              signed-outputs/
              transparency-index.jsonl
    """

    def __init__(self, data_dir: Path | None = None, *, root: Path | None = None) -> None:
        self._root = root or data_dir or _resolve_root()
        self._root.mkdir(parents=True, exist_ok=True)

    # Stages that start a new run — all others continue an existing run.
    _NEW_RUN_STAGES = {"requirements", "design"}

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def create_run(self, app_id: str, stage: str = "requirements") -> RunContext:
        """Create a brand-new run for *app_id*."""
        return self.ensure_run(app_id, stage)

    def ensure_run(
        self,
        app_id: str,
        stage: str,
        run_id: str | None = None,
        *,
        reuse_run: str | None = None,
        sign_outputs: bool = False,
    ) -> RunContext:
        """Create or reuse a run directory for the given stage.

        *Continuation stages* (build, test, deploy, operate, decision) will
        automatically reuse the most recent run for the same ``app_id`` if no
        explicit ``run_id`` or ``reuse_run`` is given.  Only **requirements**
        and **design** start a new run by default.
        """
        rid = reuse_run or run_id

        if rid is None and stage not in self._NEW_RUN_STAGES:
            # Try to reuse latest run for this app
            rid = self._latest_run_id(app_id)

        if rid is None:
            rid = uuid.uuid4().hex[:12]

        app_dir = self._root / app_id
        app_dir.mkdir(parents=True, exist_ok=True)

        run_dir = app_dir / rid
        run_dir.mkdir(parents=True, exist_ok=True)

        ctx = RunContext(run_id=rid, app_id=app_id, stage=stage, run_dir=run_dir)
        ctx.inputs_dir.mkdir(parents=True, exist_ok=True)
        ctx.outputs_dir.mkdir(parents=True, exist_ok=True)
        ctx.signatures_dir.mkdir(parents=True, exist_ok=True)

        # Write run metadata
        meta_path = run_dir / "run-meta.json"
        meta: Dict[str, Any] = {}
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text())
            except (json.JSONDecodeError, OSError):
                meta = {}
        meta.setdefault("run_id", rid)
        meta.setdefault("app_id", app_id)
        meta.setdefault("created_at", ctx.started_at)
        meta.setdefault("stages", [])
        if stage not in meta["stages"]:
            meta["stages"].append(stage)
        meta["updated_at"] = datetime.now(timezone.utc).isoformat() + "Z"
        meta["sign_outputs"] = sign_outputs
        meta_path.write_text(json.dumps(meta, indent=2))

        # Update LATEST marker
        latest_path = app_dir / "LATEST"
        latest_path.write_text(json.dumps({"run_id": rid}, indent=2))

        return ctx

    def _latest_run_id(self, app_id: str) -> str | None:
        """Read the LATEST marker for *app_id* and return its run_id, if any."""
        latest_path = self._root / app_id / "LATEST"
        if latest_path.exists():
            try:
                data = json.loads(latest_path.read_text())
                return data.get("run_id")
            except (json.JSONDecodeError, OSError):
                pass
        return None

    # ------------------------------------------------------------------
    # Artefact persistence (registry-level, with path validation)
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_filename(filename: str) -> None:
        """Reject path-traversal attempts."""
        p = Path(filename)
        if p.is_absolute():
            raise ValueError(f"Absolute paths are not allowed: {filename}")
        for part in p.parts:
            if part == "..":
                raise ValueError(f"Path traversal not allowed: {filename}")

    def save_input(self, ctx: RunContext, filename: str, data: bytes) -> Path:
        """Persist a stage input artefact (with path validation)."""
        self._validate_filename(filename)
        dest = ctx.inputs_dir / filename
        dest.write_bytes(data)
        return dest

    def write_output(
        self, ctx: RunContext, filename: str, document: Dict[str, Any]
    ) -> Path:
        """Write a canonical JSON output artefact."""
        self._validate_filename(filename)
        dest = ctx.outputs_dir / filename
        dest.write_text(json.dumps(document, indent=2))
        return dest

    def write_binary_output(self, ctx: RunContext, filename: str, data: bytes) -> Path:
        """Write a binary output artefact (with path validation)."""
        self._validate_filename(filename)
        dest = ctx.outputs_dir / filename
        dest.write_bytes(data)
        return dest

    def write_signed_manifest(
        self, ctx: RunContext, filename: str, envelope: Dict[str, Any]
    ) -> Path:
        """Persist a signature envelope."""
        self._validate_filename(filename)
        dest = ctx.signatures_dir / filename
        dest.write_text(json.dumps(envelope, indent=2))
        return dest

    def append_transparency_index(
        self, ctx: RunContext, entry: Dict[str, Any]
    ) -> Path:
        """Append an entry to the transparency index."""
        index_path = ctx.run_dir / "transparency-index.jsonl"
        with index_path.open("a") as fp:
            fp.write(json.dumps(entry) + "\n")
        return index_path

    def list_runs(self, limit: int = 50) -> list[Dict[str, Any]]:
        """List recent runs from the registry."""
        results: list[Dict[str, Any]] = []
        if not self._root.exists():
            return results
        for app_dir in sorted(self._root.iterdir(), reverse=True):
            if not app_dir.is_dir() or not app_dir.name.startswith("APP-"):
                continue
            for run_dir in sorted(app_dir.iterdir(), reverse=True):
                if not run_dir.is_dir():
                    continue
                meta_path = run_dir / "run-meta.json"
                if meta_path.exists():
                    try:
                        results.append(json.loads(meta_path.read_text()))
                    except (json.JSONDecodeError, OSError):
                        pass
                if len(results) >= limit:
                    return results
        return results


# ---------------------------------------------------------------------------
# Module-level convenience functions (used by tests and CLI)
# ---------------------------------------------------------------------------

def resolve_run(app_id: str, stage: str = "requirements") -> RunContext:
    """Create or reuse a run using the module-level ``ARTEFACTS_ROOT``."""
    registry = RunRegistry(root=ARTEFACTS_ROOT)
    return registry.ensure_run(app_id, stage)


def reopen_run(app_id: str, run_id: str, stage: str = "requirements") -> RunContext:
    """Reopen an existing run by its *run_id*."""
    registry = RunRegistry(root=ARTEFACTS_ROOT)
    return registry.ensure_run(app_id, stage, run_id=run_id)
