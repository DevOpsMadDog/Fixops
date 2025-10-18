"""Artefact archival utilities for persisting uploaded inputs."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping, Optional

from core.paths import ensure_secure_directory, verify_allowlisted_path


def _serialise_payload(payload: Any) -> Any:
    if payload is None:
        return None
    if hasattr(payload, "to_dict") and callable(getattr(payload, "to_dict")):
        return payload.to_dict()  # type: ignore[no-any-return]
    if isinstance(payload, (str, int, float, bool)):
        return payload
    if isinstance(payload, Mapping):
        return {key: _serialise_payload(value) for key, value in payload.items()}
    if isinstance(payload, (list, tuple)):
        return [_serialise_payload(item) for item in payload]
    return str(payload)


class ArtefactArchive:
    """Persist normalised artefacts on disk for post-run analysis."""

    def __init__(
        self, base_directory: Path, *, allowlist: Optional[Iterable[Path]] = None
    ) -> None:
        self._allowlist: tuple[Path, ...] = (
            tuple(Path(entry).resolve() for entry in allowlist)
            if allowlist
            else tuple()
        )
        if self._allowlist:
            base_directory = verify_allowlisted_path(base_directory, self._allowlist)
        self.base_directory = ensure_secure_directory(base_directory)

    def _stage_directory(self, stage: str) -> Path:
        candidate = self.base_directory / stage
        if self._allowlist:
            candidate = verify_allowlisted_path(candidate, self._allowlist)
        return ensure_secure_directory(candidate)

    def persist(
        self,
        stage: str,
        payload: Any,
        *,
        original_filename: Optional[str] = None,
        raw_bytes: Optional[bytes] = None,
    ) -> Mapping[str, Any]:
        identifier = uuid.uuid4().hex
        timestamp = datetime.utcnow().isoformat() + "Z"
        stage_dir = self._stage_directory(stage)

        record: MutableMapping[str, Any] = {
            "id": identifier,
            "stage": stage,
            "stored_at": timestamp,
        }
        if original_filename:
            record["original_filename"] = original_filename

        if raw_bytes is not None:
            raw_path = stage_dir / f"{timestamp.replace(':', '')}-{identifier}.raw"
            raw_path.write_bytes(raw_bytes)
            record["raw_path"] = str(raw_path)

        serialised = _serialise_payload(payload)
        data_path = stage_dir / f"{timestamp.replace(':', '')}-{identifier}.json"
        data_path.write_text(json.dumps(serialised, indent=2), encoding="utf-8")
        record["normalized_path"] = str(data_path)

        manifest_path = (
            stage_dir / f"{timestamp.replace(':', '')}-{identifier}-manifest.json"
        )
        manifest_payload = dict(record)
        manifest_path.write_text(
            json.dumps(manifest_payload, indent=2), encoding="utf-8"
        )
        record["manifest"] = str(manifest_path)

        return record

    @staticmethod
    def summarise(records: Mapping[str, Mapping[str, Any]]) -> Mapping[str, Any]:
        summary: MutableMapping[str, Any] = {}
        for stage, record in records.items():
            trimmed = {
                key: value
                for key, value in record.items()
                if key
                in {
                    "id",
                    "stored_at",
                    "normalized_path",
                    "raw_path",
                    "original_filename",
                }
            }
            summary[stage] = trimmed
        return summary


__all__ = ["ArtefactArchive"]
