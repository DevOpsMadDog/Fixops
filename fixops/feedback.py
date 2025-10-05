"""Feedback capture utilities respecting overlay configuration."""
from __future__ import annotations

import json
import logging
import re
import time
from html import escape
from pathlib import Path
from typing import Any, Dict, Mapping, MutableMapping, Optional

from fixops.analytics import AnalyticsStore, FeedbackOutcomeStore
from fixops.configuration import OverlayConfig
from fixops.connectors import ConfluenceConnector, ConnectorOutcome, JiraConnector
from fixops.paths import ensure_secure_directory


_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]+$")


logger = logging.getLogger(__name__)


class FeedbackRecorder:
    """Persist feedback decisions to a secure directory."""

    def __init__(
        self,
        overlay: OverlayConfig,
        *,
        connectors: Optional[Mapping[str, Any]] = None,
        outcome_store: Optional[FeedbackOutcomeStore] = None,
        analytics_store: Optional[AnalyticsStore] = None,
    ):
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
        self._connectors: Dict[str, Any] = {}
        if connectors is not None:
            self._connectors.update(connectors)
        else:
            self._connectors.update(
                {
                    "jira": JiraConnector(overlay.jira),
                    "confluence": ConfluenceConnector(overlay.confluence),
                }
            )
        if outcome_store is not None:
            self._outcome_store = outcome_store
        else:
            self._outcome_store = FeedbackOutcomeStore(
                self.base_dir, analytics_store=analytics_store
            )

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
        connectors = self._forward_to_connectors(entry)
        try:
            self._outcome_store.record_feedback_event(entry)
        except Exception:  # pragma: no cover - persistence best effort
            logger.exception("Failed to persist feedback analytics for run %s", entry["run_id"])
        if connectors:
            try:
                self._outcome_store.record(entry["run_id"], connectors)
            except Exception as exc:  # pragma: no cover - persistence should not break flow
                logger.exception("Failed to persist feedback connector outcomes for run %s", entry["run_id"])
                connectors.setdefault("_errors", {})
                connectors["_errors"]["persistence_error"] = str(exc)
        return {
            "run_id": entry["run_id"],
            "path": str(feedback_path),
            "decision": entry["decision"],
            "timestamp": entry["timestamp"],
            "connectors": connectors,
        }

    def _forward_to_connectors(self, entry: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
        outcomes: Dict[str, Dict[str, Any]] = {}
        if not self._connectors:
            return outcomes

        for name, connector in self._connectors.items():
            try:
                outcome = self._send_to_connector(name, connector, entry)
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.exception("Feedback forwarding failed for connector %s", name)
                outcomes[str(name)] = {"status": "error", "error": str(exc)}
                continue

            if outcome is None:
                continue
            if isinstance(outcome, ConnectorOutcome):
                outcomes[str(name)] = outcome.to_dict()
            elif isinstance(outcome, Mapping):
                data = dict(outcome)
                data.setdefault("status", data.get("status", "unknown"))
                outcomes[str(name)] = data
            else:
                outcomes[str(name)] = {"status": "unknown", "result": str(outcome)}

        return outcomes

    def _send_to_connector(
        self,
        name: str,
        connector: Any,
        entry: Mapping[str, Any],
    ) -> Optional[ConnectorOutcome]:
        action: MutableMapping[str, Any]
        decision = entry.get("decision", "")
        run_id = entry.get("run_id", "")
        notes = entry.get("notes") or "No reviewer notes provided."
        submitted_by = entry.get("submitted_by") or "anonymous"
        tags = entry.get("tags") or []
        tag_text = ", ".join(tags) if tags else "none"
        summary = f"Feedback for FixOps run {run_id}: {decision}".strip()

        description_lines = [
            f"Run ID: {run_id}",
            f"Decision: {decision}",
            f"Submitted by: {submitted_by}",
            f"Tags: {tag_text}",
            "Notes:",
            str(notes),
        ]
        description = "\n".join(description_lines)

        if name == "jira" and hasattr(connector, "create_issue"):
            action = {
                "type": "jira_issue",
                "summary": summary or f"Feedback for FixOps run {run_id}",
                "description": description,
                "labels": list(tags) if isinstance(tags, list) else [],
                "run_id": run_id,
            }
            return connector.create_issue(action)

        if name == "confluence" and hasattr(connector, "create_page"):
            body = (
                "<p><strong>Run ID:</strong> {run}</p>"
                "<p><strong>Decision:</strong> {decision}</p>"
                "<p><strong>Submitted by:</strong> {submitted}</p>"
                "<p><strong>Tags:</strong> {tags}</p>"
                "<p><strong>Notes:</strong><br/>{notes}</p>"
            ).format(
                run=escape(str(run_id)),
                decision=escape(str(decision)),
                submitted=escape(str(submitted_by)),
                tags=escape(tag_text),
                notes=escape(str(notes)),
            )
            action = {
                "type": "confluence_page",
                "title": summary or f"FixOps Feedback {run_id}",
                "body": body,
                "representation": "storage",
                "metadata": {
                    "run_id": run_id,
                    "decision": decision,
                },
            }
            return connector.create_page(action)

        return None


__all__ = ["FeedbackRecorder"]
