"""Feedback capture utilities respecting overlay configuration."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, Mapping

from fixops.configuration import OverlayConfig
from fixops.paths import ensure_secure_directory


_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]+$")


class FeedbackRecorder:
    """Persist feedback decisions to a secure directory."""

    def __init__(self, overlay: OverlayConfig):
        self.overlay = overlay
        directories = overlay.data_directories
        base_dir = directories.get("feedback_dir") or directories.get("evidence_dir")
        if base_dir is None:
            root = (
                overlay.allowed_data_roots[0]
                if overlay.allowed_data_roots
                else Path("data").resolve()
            )
            base_dir = (root / "feedback" / overlay.mode).resolve()
        self.base_dir = ensure_secure_directory(base_dir)

    def _validate_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        run_id = payload.get("run_id")
        decision = payload.get("decision")
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("Feedback payload must include non-empty 'run_id'")
        if not isinstance(decision, str) or not decision.strip():
            raise ValueError("Feedback payload must include non-empty 'decision'")
        notes = payload.get("notes")
        if notes is not None and not isinstance(notes, str):
            raise ValueError("Feedback 'notes' must be a string if provided")
        submitted_by = payload.get("submitted_by")
        if submitted_by is not None and not isinstance(submitted_by, str):
            raise ValueError("'submitted_by' must be a string if provided")
        tags = payload.get("tags")
        if tags is not None:
            if not isinstance(tags, (list, tuple)):
                raise ValueError("'tags' must be a list of strings if provided")
            cleaned_tags = []
            for item in tags:
                if not isinstance(item, str):
                    raise ValueError("Feedback tag entries must be strings")
                cleaned_tags.append(item)
            tags = cleaned_tags
        timestamp = payload.get("timestamp")
        if timestamp is not None and not isinstance(timestamp, (int, float)):
            raise ValueError("'timestamp' must be a UNIX timestamp")
        candidate = run_id.strip()
        if not candidate:
            raise ValueError("Feedback 'run_id' must be non-empty")
        if not _SAFE_IDENTIFIER.match(candidate):
            raise ValueError(
                "Feedback 'run_id' may only contain letters, numbers, dashes, and underscores"
            )

        return {
            "run_id": candidate,
            "decision": decision.strip(),
            "notes": notes.strip() if isinstance(notes, str) and notes.strip() else None,
            "submitted_by": submitted_by.strip()
            if isinstance(submitted_by, str) and submitted_by.strip()
            else None,
            "tags": tags,
            "timestamp": int(timestamp) if isinstance(timestamp, (int, float)) else int(time.time()),
        }

    def record(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Write a validated feedback entry to disk."""

        entry = self._validate_payload(payload)
        run_dir = ensure_secure_directory(self.base_dir / entry["run_id"])
        feedback_path = run_dir / "feedback.jsonl"
        line = json.dumps(entry, sort_keys=True)
        with feedback_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        return {
            "run_id": entry["run_id"],
            "path": str(feedback_path),
            "decision": entry["decision"],
            "timestamp": entry["timestamp"],
        }


__all__ = ["FeedbackRecorder"]
