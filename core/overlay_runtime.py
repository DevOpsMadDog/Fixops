"""Runtime helpers for working with overlay configurations."""
from __future__ import annotations

import os
from pathlib import Path
from typing import List, Mapping, Optional

from core.configuration import OverlayConfig, load_overlay
from core.evidence import Fernet  # type: ignore
from core.paths import ensure_secure_directory


def _normalise_evidence_limits(limits: Mapping[str, object]) -> dict:
    evidence_limits = limits.get("evidence")
    if isinstance(evidence_limits, Mapping):
        return dict(evidence_limits)
    return {}


def prepare_overlay(
    *,
    mode: Optional[str] = None,
    path: Optional[Path | str] = None,
    ensure_directories: bool = True,
    allow_demo_token_fallback: bool = False,
) -> OverlayConfig:
    """Load an overlay and apply runtime safeguards.

    The returned overlay mirrors what the pipeline uses at runtime:

    * evidence encryption is disabled automatically when the optional
      ``cryptography`` dependency (``Fernet``) is unavailable
    * missing encryption keys fall back to plaintext bundles for local
      walkthroughs rather than raising runtime errors
    * configured data directories are created to avoid later I/O errors
    """

    overlay = load_overlay(
        path,
        mode_override=mode,
        allow_demo_token_fallback=allow_demo_token_fallback,
    )

    limits = dict(getattr(overlay, "limits", {}) or {})
    evidence_limits = _normalise_evidence_limits(limits)
    if evidence_limits.get("encrypt"):
        encryption_env = str(evidence_limits.get("encryption_env") or "").strip()
        key_missing = bool(encryption_env and not os.getenv(encryption_env))
        crypto_missing = Fernet is None
        if crypto_missing or key_missing:
            evidence_limits["encrypt"] = False
    if evidence_limits:
        limits["evidence"] = evidence_limits
        overlay.limits = limits

    runtime_warnings: List[str] = []
    missing_tokens: set[tuple[str, str]] = set()

    def _check_token(section: Mapping[str, object], label: str) -> None:
        token_env = str(section.get("token_env") or "").strip()
        key = (label, token_env)
        if token_env and not os.getenv(token_env) and key not in missing_tokens:
            missing_tokens.add(key)
            runtime_warnings.append(
                f"{label} automation token '{token_env}' is not set; automation runs will be skipped."
            )

    _check_token(getattr(overlay, "jira", {}) or {}, "Jira")
    _check_token(getattr(overlay, "confluence", {}) or {}, "Confluence")

    policy_settings = getattr(overlay, "policy_automation", {}) or {}
    actions = policy_settings.get("actions")
    if isinstance(actions, list):
        for action in actions:
            if not isinstance(action, Mapping):
                continue
            action_type = str(action.get("type") or "").lower()
            if action_type == "jira_issue":
                _check_token(getattr(overlay, "jira", {}) or {}, "Jira")
            elif action_type == "confluence_page":
                _check_token(getattr(overlay, "confluence", {}) or {}, "Confluence")

    if runtime_warnings:
        metadata = dict(getattr(overlay, "metadata", {}) or {})
        existing = metadata.get("runtime_warnings")
        if isinstance(existing, list):
            runtime_warnings = existing + runtime_warnings
        elif isinstance(existing, tuple):
            runtime_warnings = list(existing) + runtime_warnings
        metadata["runtime_warnings"] = runtime_warnings
        overlay.metadata = metadata

    if ensure_directories:
        for directory in overlay.data_directories.values():
            ensure_secure_directory(directory)

    return overlay


__all__ = ["prepare_overlay"]
