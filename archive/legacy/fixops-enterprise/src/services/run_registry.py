"""Lightweight artefact registry used by the unified stage runner."""

from __future__ import annotations

import datetime as _dt
import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from fixops.utils.paths import resolve_within_root

ARTEFACTS_ROOT = Path("artefacts")

_CANONICAL_OUTPUTS: set[str] = {
    "requirements.json",
    "design.manifest.json",
    "build.report.json",
    "test.report.json",
    "deploy.manifest.json",
    "operate.snapshot.json",
    "decision.json",
    "manifest.json",
}


_CANONICAL_OUTPUTS_SET: set[str] = {
    "requirements.json",
    "design.manifest.json",
    "build.report.json",
    "test.report.json",
    "deploy.manifest.json",
    "operate.snapshot.json",
    "decision.json",
    "manifest.json",
}


@dataclass(slots=False)
class RunContext:
    """Represents a materialised run folder for an application."""

    app_id: str
    run_id: str
    root: Path
    sign_outputs: bool = False

    @property
    def run_path(self) -> Path:
        return (self.root / self.app_id / self.run_id).resolve()

    @property
    def inputs_dir(self) -> Path:
        return (self.run_path / "inputs").resolve()

    @property
    def outputs_dir(self) -> Path:
        return (self.run_path / "outputs").resolve()

    @property
    def signed_outputs_dir(self) -> Path:
        return (self.outputs_dir / "signed").resolve()

    @property
    def transparency_index(self) -> Path:
        return resolve_within_root(self.outputs_dir, "transparency.index")

    def save_input(
        self,
        filename: str,
        payload: bytes | bytearray | Mapping[str, Any] | Iterable[Any] | str,
    ) -> Path:
        """Persist an input payload beneath the run's inputs directory."""
        target = resolve_within_root(self.inputs_dir, filename)
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(payload, (bytes, bytearray)):
            target.write_bytes(bytes(payload))
        elif isinstance(payload, Mapping) or (
            isinstance(payload, Iterable)
            and not isinstance(payload, (str, bytes, bytearray))
        ):
            target.write_text(
                json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)
            )
        else:
            target.write_text(str(payload))
        return target

    def write_output(
        self,
        name: str,
        document: Mapping[str, Any] | Iterable[Any],
    ) -> Path:
        """Persist *document* to the outputs directory and return the file path."""
        if name not in _CANONICAL_OUTPUTS_SET:
            raise ValueError(f"Unsupported output name: {name}")
        target = resolve_within_root(self.outputs_dir, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False)
        target.write_text(text, encoding="utf-8")

        # Sign the output if configured
        if self.sign_outputs:
            try:
                from src.services import signing

                envelope = signing.sign_manifest(document)
                signed_path = self.signed_outputs_dir / f"{name}.manifest.json"
                signed_path.parent.mkdir(parents=True, exist_ok=True)
                signed_path.write_text(
                    json.dumps(envelope, indent=2, sort_keys=True, ensure_ascii=False),
                    encoding="utf-8",
                )
                # Append to transparency index
                digest = envelope.get("digest", "unknown")
                kid = envelope.get("kid")
                self._append_transparency_index(name, digest, kid)
            except (ImportError, Exception):
                pass

        return target

    def _append_transparency_index(
        self, canonical: str, digest: str, kid: str | None
    ) -> Path:
        """Append an entry to the transparency index."""
        import datetime as _dt

        self.transparency_index.parent.mkdir(parents=True, exist_ok=True)
        timestamp = (
            _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")
        )
        line = (
            f"TS={timestamp} FILE={canonical} SHA256={digest} KID={kid or 'unknown'}\n"
        )
        with self.transparency_index.open("a", encoding="utf-8") as handle:
            handle.write(line)
        return self.transparency_index


class RunRegistry:
    """Persist stage inputs/outputs under ``artefacts/<app>/<run_id>``."""

    def __init__(self, root: Path | None = None) -> None:
        env_root = os.environ.get("FIXOPS_ARTEFACTS_ROOT")
        resolved_root = Path(env_root) if env_root else (root or ARTEFACTS_ROOT)
        self.root = resolved_root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public helpers
    def create_run(
        self, app_id: str | None, *, sign_outputs: bool = False
    ) -> RunContext:
        """Create a brand new run directory for *app_id*."""

        context = self._make_context(app_id, sign_outputs=sign_outputs)
        self._prepare_directories(context)
        self._write_latest_marker(context)
        return context

    def reopen_run(
        self, app_id: str | None, run_id: str, *, sign_outputs: bool = False
    ) -> RunContext:
        """Re-open an existing run directory."""

        normalised = self._normalise_app_id(app_id)
        context = RunContext(
            app_id=normalised, run_id=run_id, root=self.root, sign_outputs=sign_outputs
        )
        if not context.run_path.exists():
            raise FileNotFoundError(context.run_path)
        self._prepare_directories(context)
        self._write_latest_marker(context)
        return context

    def active_run(self, app_id: str | None) -> RunContext | None:
        """Return the most recent run for *app_id* if available."""

        normalised = self._normalise_app_id(app_id)
        marker = self._latest_marker(normalised)
        if not marker.exists():
            return None
        try:
            payload = json.loads(marker.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
        run_id = payload.get("run_id")
        if not isinstance(run_id, str):
            return None
        context = RunContext(
            app_id=normalised, run_id=run_id, root=self.root, sign_outputs=False
        )
        if not context.run_path.exists():
            return None
        return context

    def ensure_run(
        self,
        app_id: str | None,
        *,
        stage: str,
        sign_outputs: bool = False,
    ) -> RunContext:
        """Return a run context, recycling runs only when appropriate."""

        stage_key = (stage or "").strip().lower()
        existing = self.active_run(app_id)
        if existing is None:
            return self.create_run(app_id, sign_outputs=sign_outputs)

        # Requirements and design runs should always materialise a fresh run to
        # avoid bleeding artefacts between distinct planning cycles. Downstream
        # stages can safely reuse the most recent design run for incremental
        # updates.
        if stage_key == "requirements":
            return self.create_run(app_id, sign_outputs=sign_outputs)

        if stage_key == "design":
            if existing is None:
                return self.create_run(app_id, sign_outputs=sign_outputs)
            rollover = self.create_run(app_id, sign_outputs=sign_outputs)
            self._carry_requirements(existing, rollover)
            return rollover

        context = RunContext(
            app_id=existing.app_id,
            run_id=existing.run_id,
            root=self.root,
            sign_outputs=sign_outputs,
        )
        self._prepare_directories(context)
        self._write_latest_marker(context)
        return context

    def save_input(
        self,
        context: RunContext,
        filename: str,
        payload: bytes | bytearray | Mapping[str, Any] | Iterable[Any] | str,
    ) -> Path:
        """Persist an input payload beneath the run's inputs directory."""

        target = resolve_within_root(context.inputs_dir, filename)
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(payload, (bytes, bytearray)):
            target.write_bytes(bytes(payload))
        elif isinstance(payload, Mapping) or (
            isinstance(payload, Iterable)
            and not isinstance(payload, (str, bytes, bytearray))
        ):
            target.write_text(self._json_dumps(payload))
        else:
            target.write_text(str(payload))
        return target

    def write_output(
        self,
        context: RunContext,
        name: str,
        document: Mapping[str, Any] | Iterable[Any],
    ) -> Path:
        """Persist *document* to the outputs directory and return the file path."""

        if name not in _CANONICAL_OUTPUTS:
            raise ValueError(f"Unsupported output name: {name}")
        target = resolve_within_root(context.outputs_dir, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        text = self._json_dumps(document)
        target.write_text(text, encoding="utf-8")
        return target

    def write_binary_output(self, context: RunContext, name: str, blob: bytes) -> Path:
        target = resolve_within_root(context.outputs_dir, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
        return target

    def write_signed_manifest(
        self, context: RunContext, name: str, envelope: Mapping[str, Any]
    ) -> Path:
        target = resolve_within_root(
            context.signed_outputs_dir, f"{name}.manifest.json"
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self._json_dumps(envelope), encoding="utf-8")
        return target

    def append_transparency_index(
        self, context: RunContext, canonical: str, digest: str, kid: str | None
    ) -> Path:
        context.transparency_index.parent.mkdir(parents=True, exist_ok=True)
        timestamp = (
            _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")
        )
        line = (
            f"TS={timestamp} FILE={canonical} SHA256={digest} KID={kid or 'unknown'}\n"
        )
        with context.transparency_index.open("a", encoding="utf-8") as handle:
            handle.write(line)
        return context.transparency_index

    def list_runs(self, app_id: str | None) -> list[str]:
        normalised = self._normalise_app_id(app_id)
        app_root = self.root / normalised
        if not app_root.exists():
            return []
        runs = [entry.name for entry in app_root.iterdir() if entry.is_dir()]
        runs.sort()
        return runs

    # ------------------------------------------------------------------
    # Internal helpers
    def _make_context(
        self, app_id: str | None, *, sign_outputs: bool = False
    ) -> RunContext:
        normalised = self._normalise_app_id(app_id)
        seed = os.environ.get("FIXOPS_RUN_ID_SEED")
        timestamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
        if seed:
            sanitized = "".join(
                ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in seed.strip()
            )
            if sanitized:
                timestamp = sanitized
        run_id = timestamp
        counter = 1
        while (self.root / normalised / run_id).exists():
            counter += 1
            run_id = f"{timestamp}-{counter:02d}"
        return RunContext(
            app_id=normalised, run_id=run_id, root=self.root, sign_outputs=sign_outputs
        )

    def _prepare_directories(self, context: RunContext) -> None:
        context.inputs_dir.mkdir(parents=True, exist_ok=True)
        context.signed_outputs_dir.mkdir(parents=True, exist_ok=True)

    def _write_latest_marker(self, context: RunContext) -> None:
        marker = self._latest_marker(context.app_id)
        marker.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "run_id": context.run_id,
            "updated_at": _dt.datetime.now(_dt.timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        marker.write_text(self._json_dumps(payload), encoding="utf-8")

    def _latest_marker(self, app_id: str) -> Path:
        return self.root / app_id / "LATEST"

    @staticmethod
    def _json_dumps(data: Mapping[str, Any] | Iterable[Any]) -> str:
        return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)

    @staticmethod
    def _normalise_app_id(app_id: str | None) -> str:
        if not app_id:
            return "APP-UNKNOWN"
        candidate = app_id.strip()
        if not candidate:
            return "APP-UNKNOWN"
        safe = [ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in candidate]
        return "".join(safe)

    def _carry_requirements(self, source: RunContext, target: RunContext) -> None:
        """Copy requirements artefacts from *source* into *target* if present."""

        source_requirements = source.outputs_dir / "requirements.json"
        if source_requirements.exists():
            target.outputs_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(
                source_requirements, target.outputs_dir / source_requirements.name
            )

        source_inputs = list(source.inputs_dir.glob("requirements*"))
        if source_inputs:
            target.inputs_dir.mkdir(parents=True, exist_ok=True)
            for path in source_inputs:
                shutil.copy2(path, target.inputs_dir / path.name)


_DEFAULT_REGISTRY = RunRegistry()


def resolve_run(app_id: str | None, *, sign_outputs: bool = False) -> RunContext:
    return _DEFAULT_REGISTRY.create_run(app_id, sign_outputs=sign_outputs)


def reopen_run(
    app_id: str | None, run_id: str, *, sign_outputs: bool = False
) -> RunContext:
    return _DEFAULT_REGISTRY.reopen_run(app_id, run_id, sign_outputs=sign_outputs)


def list_runs(app_id: str | None) -> list[str]:
    return _DEFAULT_REGISTRY.list_runs(app_id)


__all__ = ["RunRegistry", "RunContext", "resolve_run", "reopen_run", "list_runs"]
