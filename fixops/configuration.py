"""Overlay configuration loading and validation utilities for FixOps."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, MutableMapping, Optional

DEFAULT_OVERLAY_PATH = Path(__file__).resolve().parent.parent / "config" / "fixops.overlay.yml"
_OVERRIDDEN_PATH_ENV = "FIXOPS_OVERLAY_PATH"


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _parse_overlay(text: str) -> Dict[str, Any]:
    if not text.strip():
        return {}

    try:
        import yaml  # type: ignore
    except Exception:  # pragma: no cover - PyYAML is optional
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive branch
            raise ValueError("Overlay file is not valid JSON and PyYAML is unavailable") from exc
    else:
        loaded = yaml.safe_load(text)
        if loaded is None:
            return {}
        if not isinstance(loaded, Mapping):
            raise TypeError("Overlay configuration must be a mapping at the root")
        return dict(loaded)


def _deep_merge(base: MutableMapping[str, Any], overrides: Mapping[str, Any]) -> MutableMapping[str, Any]:
    for key, value in overrides.items():
        if (
            key in base
            and isinstance(base[key], MutableMapping)
            and isinstance(value, Mapping)
        ):
            base[key] = _deep_merge(base[key], value)  # type: ignore[assignment]
        else:
            base[key] = value  # type: ignore[assignment]
    return base


@dataclass
class OverlayConfig:
    """Validated overlay configuration with convenience helpers."""

    mode: str = "demo"
    jira: Dict[str, Any] = field(default_factory=dict)
    confluence: Dict[str, Any] = field(default_factory=dict)
    git: Dict[str, Any] = field(default_factory=dict)
    ci: Dict[str, Any] = field(default_factory=dict)
    auth: Dict[str, Any] = field(default_factory=dict)
    data: Dict[str, Any] = field(default_factory=dict)
    toggles: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def required_inputs(self) -> tuple[str, ...]:
        base = ("sbom", "sarif", "cve")
        require_design = self.toggles.get("require_design_input", True)
        if require_design:
            return ("design",) + base
        return base

    @property
    def data_directories(self) -> Dict[str, Path]:
        directories: Dict[str, Path] = {}
        for key, value in self.data.items():
            if not isinstance(value, str):
                continue
            directories[key] = Path(value).expanduser()
        return directories

    def to_sanitised_dict(self) -> Dict[str, Any]:
        payload = {
            "mode": self.mode,
            "jira": self._mask(self.jira),
            "confluence": self._mask(self.confluence),
            "git": self._mask(self.git),
            "ci": self._mask(self.ci),
            "auth": self._mask(self.auth),
            "data": self.data,
            "toggles": self.toggles,
            "metadata": self.metadata,
        }
        return payload

    @staticmethod
    def _mask(section: Mapping[str, Any]) -> Dict[str, Any]:
        masked: Dict[str, Any] = {}
        for key, value in section.items():
            if any(token in key.lower() for token in ("secret", "token", "password")):
                masked[key] = "***"
            else:
                masked[key] = value
        return masked


def load_overlay(path: Optional[Path | str] = None) -> OverlayConfig:
    """Load the overlay configuration and merge profile overrides."""

    override_path = os.getenv(_OVERRIDDEN_PATH_ENV)
    candidate_path = Path(path or override_path or DEFAULT_OVERLAY_PATH)
    text = _read_text(candidate_path)
    raw = _parse_overlay(text)

    profiles = raw.pop("profiles", {}) if isinstance(raw, dict) else {}
    base = {
        "mode": raw.get("mode", "demo"),
        "jira": raw.get("jira", {}),
        "confluence": raw.get("confluence", {}),
        "git": raw.get("git", {}),
        "ci": raw.get("ci", {}),
        "auth": raw.get("auth", {}),
        "data": raw.get("data", {}),
        "toggles": raw.get("toggles", {}),
        "metadata": {"source_path": str(candidate_path)},
    }

    selected_mode = str(base["mode"]).lower()
    if isinstance(profiles, Mapping):
        profile_overrides = profiles.get(selected_mode)
        if isinstance(profile_overrides, Mapping):
            _deep_merge(base, dict(profile_overrides))

    toggles = base.setdefault("toggles", {})
    toggles.setdefault("require_design_input", True)
    toggles.setdefault("auto_attach_overlay_metadata", True)

    metadata = base.setdefault("metadata", {})
    metadata.setdefault("profile_applied", selected_mode)
    metadata.setdefault("available_profiles", sorted(profiles.keys()) if isinstance(profiles, Mapping) else [])

    return OverlayConfig(
        mode=selected_mode,
        jira=dict(base.get("jira", {})),
        confluence=dict(base.get("confluence", {})),
        git=dict(base.get("git", {})),
        ci=dict(base.get("ci", {})),
        auth=dict(base.get("auth", {})),
        data=dict(base.get("data", {})),
        toggles=dict(toggles),
        metadata=dict(metadata),
    )


__all__ = ["OverlayConfig", "load_overlay", "DEFAULT_OVERLAY_PATH"]
