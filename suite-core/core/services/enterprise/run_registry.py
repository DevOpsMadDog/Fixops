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
from typing import Any, Dict


def _resolve_root() -> Path:
    """Resolve the artefacts root directory."""
    env = os.environ.get("FIXOPS_ARTEFACTS_ROOT")
    if env:
        return Path(env)
    data_dir = os.environ.get("FIXOPS_DATA_DIR", ".fixops_data")
    return Path(data_dir) / "runs"


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
    """

    def __init__(self, data_dir: Path | None = None) -> None:
        self._root = data_dir or _resolve_root()
        self._root.mkdir(parents=True, exist_ok=True)

    # Stages that start a new run — all others continue an existing run.
    _NEW_RUN_STAGES = {"requirements", "design"}

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

    def save_input(self, ctx: RunContext, filename: str, data: bytes) -> Path:
        """Persist a stage input artefact."""
        dest = ctx.inputs_dir / filename
        dest.write_bytes(data)
        return dest

    def write_output(
        self, ctx: RunContext, filename: str, document: Dict[str, Any]
    ) -> Path:
        """Write a canonical JSON output artefact."""
        dest = ctx.outputs_dir / filename
        dest.write_text(json.dumps(document, indent=2))
        return dest

    def write_binary_output(self, ctx: RunContext, filename: str, data: bytes) -> Path:
        """Write a binary output artefact."""
        dest = ctx.outputs_dir / filename
        dest.write_bytes(data)
        return dest

    def write_signed_manifest(
        self, ctx: RunContext, filename: str, envelope: Dict[str, Any]
    ) -> Path:
        """Persist a signature envelope."""
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
        results = []
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
