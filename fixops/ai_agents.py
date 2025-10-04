"""Advisor for AI-agent components detected in design artefacts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional


def _extract_component_name(design_row: Mapping[str, Any]) -> Optional[str]:
    for key in ("component", "Component", "service", "name"):
        value = design_row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


@dataclass
class FrameworkSignature:
    name: str
    keywords: List[str]
    threat_profile: Optional[str] = None


class AIAgentAdvisor:
    """Identify AI-agent frameworks and recommend controls."""

    def __init__(self, settings: Mapping[str, Any]):
        self.settings = settings
        signatures: List[FrameworkSignature] = []
        for entry in settings.get("framework_signatures", []):
            if not isinstance(entry, Mapping):
                continue
            name = entry.get("name")
            keywords = [
                token.lower()
                for token in entry.get("keywords", [])
                if isinstance(token, str) and token.strip()
            ]
            if not name or not keywords:
                continue
            signatures.append(
                FrameworkSignature(
                    name=str(name),
                    keywords=keywords,
                    threat_profile=entry.get("threat_profile"),
                )
            )
        self.signatures = signatures
        self.controls: Mapping[str, Any] = settings.get("controls", {})
        self.playbooks: Iterable[Mapping[str, Any]] = settings.get("playbooks", [])
        self.watchlist_version = settings.get("watchlist_version")

    def enabled(self) -> bool:
        return bool(self.signatures)

    def _match_frameworks(self, text: str) -> List[FrameworkSignature]:
        matches: List[FrameworkSignature] = []
        lowered = text.lower()
        for signature in self.signatures:
            if any(keyword in lowered for keyword in signature.keywords):
                matches.append(signature)
        return matches

    def _controls_for(self, framework: FrameworkSignature) -> Dict[str, Any]:
        key = framework.name.lower()
        controls = self.controls.get(key) if isinstance(self.controls, Mapping) else None
        default = self.controls.get("default") if isinstance(self.controls, Mapping) else None
        payload: Dict[str, Any] = {}
        if isinstance(default, Mapping):
            payload.update(default)
        if isinstance(controls, Mapping):
            payload.update(controls)
        return payload

    def _playbooks_for(self, framework: FrameworkSignature) -> List[Mapping[str, Any]]:
        playbooks: List[Mapping[str, Any]] = []
        for playbook in self.playbooks:
            if not isinstance(playbook, Mapping):
                continue
            frameworks = playbook.get("frameworks")
            triggers = playbook.get("triggers")
            if frameworks and isinstance(frameworks, Iterable):
                if framework.name not in list(frameworks):
                    continue
            if triggers and isinstance(triggers, Iterable):
                if "agent" not in [str(trigger).lower() for trigger in triggers]:
                    continue
            playbooks.append(playbook)
        return playbooks

    def analyse(
        self,
        design_rows: Iterable[Mapping[str, Any]],
        crosswalk: Iterable[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        if not self.enabled():
            return None

        matches: List[Dict[str, Any]] = []
        frameworks_detected: Dict[str, int] = {}
        components_flagged: set[str] = set()

        for item in crosswalk:
            design_row = item.get("design_row") if isinstance(item, Mapping) else None
            if not isinstance(design_row, Mapping):
                continue
            component_name = _extract_component_name(design_row)
            if not component_name:
                continue
            haystack_parts = [component_name]
            haystack_parts.extend(
                str(value)
                for value in design_row.values()
                if isinstance(value, str)
            )
            sbom_component = item.get("sbom_component") if isinstance(item, Mapping) else None
            if isinstance(sbom_component, Mapping):
                haystack_parts.extend(
                    str(value)
                    for value in sbom_component.values()
                    if isinstance(value, str)
                )
            haystack = " ".join(haystack_parts)
            signature_matches = self._match_frameworks(haystack)
            if not signature_matches:
                continue

            findings = item.get("findings") if isinstance(item, Mapping) else None
            cves = item.get("cves") if isinstance(item, Mapping) else None
            for signature in signature_matches:
                frameworks_detected[signature.name] = frameworks_detected.get(signature.name, 0) + 1
                components_flagged.add(component_name)
                controls = self._controls_for(signature)
                playbooks = self._playbooks_for(signature)
                matches.append(
                    {
                        "component": component_name,
                        "framework": signature.name,
                        "threat_profile": signature.threat_profile,
                        "recommended_controls": controls.get("recommended_controls"),
                        "residual_risks": controls.get("residual_risks"),
                        "playbooks": playbooks,
                        "findings": findings if isinstance(findings, list) else [],
                        "cves": cves if isinstance(cves, list) else [],
                    }
                )

        if not matches:
            return None

        summary = {
            "components_with_agents": len(components_flagged),
            "frameworks_detected": sorted(frameworks_detected.keys()),
            "watchlist_version": self.watchlist_version,
            "total_matches": len(matches),
        }

        return {
            "summary": summary,
            "matches": matches,
        }


__all__ = ["AIAgentAdvisor"]
