"""Cybersecurity Skills Knowledge Loader.

Loads and indexes Anthropic Cybersecurity Skills (753 skills, 38 domains,
MITRE ATT&CK mapped, Apache 2.0) as context enrichment for:
  1. BrainPipeline Step 9 — relevant skills for ATT&CK technique triage
  2. AutoFix — skill workflows for better LLM remediation prompts
  3. MCP — expose skill discovery for external AI agents

Air-gap compatible: reads static .md files from local directory.
Token-efficient: YAML frontmatter index (~40K tokens for full catalog).
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:  # pragma: no cover - bus optional
    _get_tg_bus = None

logger = logging.getLogger(__name__)

# Default skills directory (relative to repo root)
_DEFAULT_SKILLS_DIR = os.environ.get(
    "FIXOPS_CYBERSEC_SKILLS_DIR",
    os.path.join(os.path.dirname(__file__), "..", "..", "data", "cybersec_skills"),
)

# ---------------------------------------------------------------------------
# YAML frontmatter parser (no PyYAML dependency)
# ---------------------------------------------------------------------------
_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
_KV_RE = re.compile(r"^(\w[\w_]*)\s*:\s*(.+)$", re.MULTILINE)
_LIST_ITEM_RE = re.compile(r"^\s*-\s+(.+)$", re.MULTILINE)


def _parse_frontmatter(text: str) -> Dict[str, Any]:
    """Parse YAML-like frontmatter without PyYAML."""
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}
    block = m.group(1)
    result: Dict[str, Any] = {}
    for kv in _KV_RE.finditer(block):
        key, val = kv.group(1), kv.group(2).strip()
        if val.startswith("[") and val.endswith("]"):
            result[key] = [v.strip().strip("'\"") for v in val[1:-1].split(",") if v.strip()]
        else:
            result[key] = val.strip("'\"")
    return result


# ---------------------------------------------------------------------------
# Skill index
# ---------------------------------------------------------------------------

class CybersecSkill:
    """A single cybersecurity skill entry."""
    __slots__ = ("id", "name", "domain", "mitre_techniques", "description", "file_path", "tags")

    def __init__(self, **kwargs: Any):
        self.id: str = kwargs.get("id", "")
        self.name: str = kwargs.get("name", "")
        self.domain: str = kwargs.get("domain", "")
        self.mitre_techniques: List[str] = kwargs.get("mitre_techniques", [])
        self.description: str = kwargs.get("description", "")
        self.file_path: str = kwargs.get("file_path", "")
        self.tags: List[str] = kwargs.get("tags", [])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "domain": self.domain,
            "mitre_techniques": self.mitre_techniques,
            "description": self.description[:300],
            "file_path": self.file_path, "tags": self.tags,
        }


class CybersecSkillsLoader:
    """Load and index cybersecurity skills from .md files."""

    def __init__(self, skills_dir: Optional[str] = None):
        self._dir = Path(skills_dir or _DEFAULT_SKILLS_DIR)
        self._skills: List[CybersecSkill] = []
        self._by_technique: Dict[str, List[CybersecSkill]] = {}
        self._by_domain: Dict[str, List[CybersecSkill]] = {}
        self._loaded = False

    def load(self) -> int:
        """Scan skills directory and build index. Returns count loaded."""
        if not self._dir.exists():
            logger.info("Cybersec skills dir not found: %s — using built-in index", self._dir)
            self._load_builtin_index()
            self._loaded = True
            self._emit_event(
                "skills.loaded",
                {"source": "builtin", "count": len(self._skills), "dir": str(self._dir)},
            )
            return len(self._skills)

        count = 0
        for md_file in sorted(self._dir.rglob("*.md")):
            try:
                text = md_file.read_text(encoding="utf-8", errors="ignore")
                meta = _parse_frontmatter(text)
                if not meta.get("name"):
                    continue
                skill = CybersecSkill(
                    id=meta.get("id", md_file.stem),
                    name=meta["name"],
                    domain=meta.get("domain", meta.get("category", "general")),
                    mitre_techniques=meta.get("mitre_techniques", meta.get("attack_techniques", [])),
                    description=text[text.find("---", 3) + 3:].strip()[:500],
                    file_path=str(md_file.relative_to(self._dir)),
                    tags=meta.get("tags", []),
                )
                self._skills.append(skill)
                for tech in skill.mitre_techniques:
                    self._by_technique.setdefault(tech, []).append(skill)
                self._by_domain.setdefault(skill.domain, []).append(skill)
                count += 1
            except (OSError, ValueError) as exc:
                logger.debug("Skip %s: %s", md_file, exc)

        self._loaded = True
        logger.info("Loaded %d cybersec skills from %s", count, self._dir)
        self._emit_event(
            "skills.loaded",
            {"source": "filesystem", "count": count, "dir": str(self._dir)},
        )
        return count

    def _load_builtin_index(self) -> None:
        """Load a minimal built-in skill index for air-gap mode."""
        # Core MITRE ATT&CK domains with representative skills
        builtin = [
            ("initial_access", "T1190", "Exploit Public-Facing Application", ["web_security", "exploit_analysis"]),
            ("execution", "T1059", "Command and Scripting Interpreter", ["malware_analysis", "scripting"]),
            ("persistence", "T1053", "Scheduled Task/Job", ["system_hardening", "persistence_detection"]),
            ("privilege_escalation", "T1068", "Exploitation for Privilege Escalation", ["privilege_analysis"]),
            ("defense_evasion", "T1027", "Obfuscated Files or Information", ["malware_analysis", "forensics"]),
            ("credential_access", "T1003", "OS Credential Dumping", ["credential_security", "forensics"]),
            ("discovery", "T1046", "Network Service Discovery", ["network_security", "reconnaissance"]),
            ("lateral_movement", "T1021", "Remote Services", ["network_security", "lateral_movement"]),
            ("collection", "T1005", "Data from Local System", ["data_protection", "forensics"]),
            ("exfiltration", "T1041", "Exfiltration Over C2 Channel", ["network_security", "data_loss_prevention"]),
            ("impact", "T1486", "Data Encrypted for Impact", ["incident_response", "ransomware"]),
            ("supply_chain", "T1195", "Supply Chain Compromise", ["supply_chain_security", "sca"]),
        ]
        for domain, tech_id, name, tags in builtin:
            skill = CybersecSkill(
                id=f"builtin_{tech_id.lower()}", name=name, domain=domain,
                mitre_techniques=[tech_id],
                description=f"Built-in skill for {name} ({tech_id})",
                file_path="builtin", tags=tags,
            )
            self._skills.append(skill)
            self._by_technique.setdefault(tech_id, []).append(skill)
            self._by_domain.setdefault(domain, []).append(skill)

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------

    def find_by_technique(self, technique_id: str) -> List[CybersecSkill]:
        """Find skills mapped to a MITRE ATT&CK technique ID (e.g. T1190)."""
        if not self._loaded:
            self.load()
        return self._by_technique.get(technique_id, [])

    def find_by_domain(self, domain: str) -> List[CybersecSkill]:
        """Find all skills in a given domain (e.g. 'initial_access')."""
        if not self._loaded:
            self.load()
        return self._by_domain.get(domain, [])

    def search(self, query: str, limit: int = 10) -> List[CybersecSkill]:
        """Simple text search across skill names and descriptions."""
        if not self._loaded:
            self.load()
        q = query.lower()
        scored = []
        for s in self._skills:
            score = 0
            if q in s.name.lower():
                score += 3
            if q in s.description.lower():
                score += 1
            if any(q in t.lower() for t in s.tags):
                score += 2
            if score > 0:
                scored.append((score, s))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [s for _, s in scored[:limit]]

    def get_enrichment_context(self, technique_ids: List[str], max_skills: int = 5) -> str:
        """Build a compact text context from skills matching given ATT&CK techniques.

        Suitable for injecting into LLM prompts to enrich triage/remediation.
        """
        if not self._loaded:
            self.load()
        skills: List[CybersecSkill] = []
        seen = set()
        for tid in technique_ids:
            for s in self._by_technique.get(tid, []):
                if s.id not in seen:
                    seen.add(s.id)
                    skills.append(s)
                    if len(skills) >= max_skills:
                        break
        if not skills:
            return ""
        lines = ["## Relevant Cybersecurity Skills"]
        for s in skills:
            lines.append(f"- **{s.name}** ({', '.join(s.mitre_techniques)}): {s.description[:200]}")
        return "\n".join(lines)

    def get_stats(self) -> Dict[str, Any]:
        """Return loader statistics."""
        if not self._loaded:
            self.load()
        return {
            "total_skills": len(self._skills),
            "domains": list(self._by_domain.keys()),
            "techniques_mapped": len(self._by_technique),
            "source": str(self._dir) if self._dir.exists() else "builtin",
        }

    # ------------------------------------------------------------------
    # TrustGraph event emission (best-effort, non-blocking)
    # ------------------------------------------------------------------

    def _emit_event(self, event_type: str, payload: "dict[str, Any]") -> None:
        """Emit an event to the TrustGraph event bus. Never raises."""
        if _get_tg_bus is None:
            return
        try:
            bus = _get_tg_bus()
            if bus is None:
                return
            emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
            if emit is None:
                return
            result = emit(event_type, payload)
            try:
                import asyncio
                import inspect
                if inspect.iscoroutine(result):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(result)
                    except RuntimeError:
                        result.close()
            except Exception:  # pragma: no cover
                pass
        except Exception:  # pragma: no cover - best-effort telemetry
            pass




# ---------------------------------------------------------------------------
# Module singleton
# ---------------------------------------------------------------------------
_instance: Optional[CybersecSkillsLoader] = None


def get_cybersec_skills_loader(**kwargs: Any) -> CybersecSkillsLoader:
    """Get or create the singleton CybersecSkillsLoader."""
    global _instance
    if _instance is None:
        _instance = CybersecSkillsLoader(**kwargs)
    return _instance

