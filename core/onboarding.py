"""Overlay-guided onboarding helpers."""
from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping, Sequence

from core.configuration import OverlayConfig


class OnboardingGuide:
    """Produce onboarding steps tailored to the active overlay mode."""

    def __init__(self, overlay: OverlayConfig):
        self.overlay = overlay
        self.settings = overlay.onboarding_settings

    def _iter_steps(self) -> Iterable[Mapping[str, Any]]:
        for step in self.settings.get("checklist", []):
            if isinstance(step, Mapping):
                modes = step.get("modes")
                if modes and self.overlay.mode not in modes:
                    continue
                yield step

    def build(
        self,
        required_inputs: Sequence[str],
    ) -> Dict[str, Any]:
        steps = []
        for step in self._iter_steps():
            steps.append({"label": step.get("step"), "modes": step.get("modes", [])})
        steps.extend({"label": f"Provide {item.upper()} artefact", "modes": [self.overlay.mode]} for item in required_inputs)
        integrations = {
            "jira": self.overlay.jira,
            "confluence": self.overlay.confluence,
            "git": self.overlay.git,
            "ci": self.overlay.ci,
        }
        return {
            "mode": self.overlay.mode,
            "time_to_value_minutes": self.settings.get("time_to_value_minutes", 30),
            "steps": steps,
            "integrations": integrations,
        }


__all__ = ["OnboardingGuide"]
