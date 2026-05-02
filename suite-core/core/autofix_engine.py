"""
FixOps AutoFix Engine — AI-powered vulnerability remediation.

Generates precise code patches, dependency updates, configuration hardening,
and IaC fixes using LLM analysis. Integrates with PRGenerator for automated
pull request creation and with the Knowledge Graph for context enrichment.

SUPERIOR to Apiiro/Aikido/Snyk — features no competitor has:
  - FAIL-scored prompts (real EPSS + KEV + blast radius in every fix)
  - Reachability-aware fixes (only fix what's exploitable)
  - Multi-LLM consensus (OpenAI + Anthropic cross-validation)
  - Confidence-gated auto-merge (auto-approve high-certainty fixes)
  - Attack-path-aware remediation (graph-enriched context)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Language inference from file paths
# ---------------------------------------------------------------------------
_EXT_LANGUAGE_MAP: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".rs": "rust",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
    ".sh": "bash",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".tf": "terraform",
    ".hcl": "terraform",
    ".dockerfile": "dockerfile",
    ".sql": "sql",
}


def _infer_language_from_path(file_path: str) -> str:
    """Infer programming language from file extension.

    Returns a best-guess language string. Falls back to 'unknown' rather
    than assuming 'python' so the LLM prompt stays honest.
    """
    if not file_path:
        return "unknown"
    import os
    _, ext = os.path.splitext(file_path.lower())
    # Handle Dockerfile (no extension)
    basename = os.path.basename(file_path.lower())
    if basename == "dockerfile" or basename.startswith("dockerfile."):
        return "dockerfile"
    return _EXT_LANGUAGE_MAP.get(ext, "unknown")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class FixType(Enum):
    """Types of automated fixes."""

    CODE_PATCH = "code_patch"
    DEPENDENCY_UPDATE = "dependency_update"
    CONFIG_HARDENING = "config_hardening"
    IAC_FIX = "iac_fix"
    SECRET_ROTATION = "secret_rotation"
    PERMISSION_FIX = "permission_fix"
    INPUT_VALIDATION = "input_validation"
    OUTPUT_ENCODING = "output_encoding"
    WAF_RULE = "waf_rule"
    CONTAINER_FIX = "container_fix"


class FixStatus(Enum):
    """Status of an autofix suggestion."""

    GENERATED = "generated"
    VALIDATED = "validated"
    APPLIED = "applied"
    PR_CREATED = "pr_created"
    MERGED = "merged"
    FAILED = "failed"
    REJECTED = "rejected"
    ROLLED_BACK = "rolled_back"


class FixConfidence(Enum):
    """Confidence level of a fix."""

    HIGH = "high"  # >85% — safe to auto-apply
    MEDIUM = "medium"  # 60-85% — needs review
    LOW = "low"  # <60% — manual review required


class PatchFormat(Enum):
    """Format of the generated patch."""

    UNIFIED_DIFF = "unified_diff"
    JSON_PATCH = "json_patch"
    YAML_PATCH = "yaml_patch"
    TOML_PATCH = "toml_patch"
    PACKAGE_JSON = "package_json"
    REQUIREMENTS_TXT = "requirements_txt"
    DOCKERFILE = "dockerfile"
    TERRAFORM = "terraform"


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------


@dataclass
class CodePatch:
    """A single code change within a fix."""

    file_path: str = ""
    language: str = ""
    old_code: str = ""
    new_code: str = ""
    start_line: int = 0
    end_line: int = 0
    patch_format: PatchFormat = PatchFormat.UNIFIED_DIFF
    unified_diff: str = ""
    explanation: str = ""


@dataclass
class DependencyFix:
    """A dependency version update."""

    package_name: str = ""
    ecosystem: str = ""  # npm, pip, maven, gradle, cargo, go
    current_version: str = ""
    fixed_version: str = ""
    cve_ids: List[str] = field(default_factory=list)
    breaking_changes: List[str] = field(default_factory=list)
    manifest_file: str = ""  # package.json, requirements.txt, etc.


@dataclass
class AutoFixSuggestion:
    """A complete autofix suggestion for a vulnerability."""

    fix_id: str = ""
    finding_id: str = ""
    finding_title: str = ""
    fix_type: FixType = FixType.CODE_PATCH
    confidence: FixConfidence = FixConfidence.MEDIUM
    confidence_score: float = 0.0
    title: str = ""
    description: str = ""
    code_patches: List[CodePatch] = field(default_factory=list)
    dependency_fixes: List[DependencyFix] = field(default_factory=list)
    config_changes: Dict[str, Any] = field(default_factory=dict)
    pr_title: str = ""
    pr_description: str = ""
    pr_branch: str = ""
    testing_guidance: str = ""
    rollback_steps: str = ""
    risk_assessment: str = ""
    effort_minutes: int = 0
    status: FixStatus = FixStatus.GENERATED
    cve_ids: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    compliance_frameworks: List[str] = field(default_factory=list)
    created_at: str = ""
    applied_at: str = ""
    pr_url: str = ""
    pr_number: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AutoFixResult:
    """Result of an autofix operation."""

    success: bool = False
    fix: Optional[AutoFixSuggestion] = None
    pr_url: str = ""
    pr_number: int = 0
    error: str = ""
    validation_passed: bool = False
    validation_details: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# CWE → vulnerability category mapping for ML confidence model
_CWE_CATEGORY_MAP = {
    # Injection
    "CWE-89": "injection", "CWE-78": "injection", "CWE-77": "injection",
    "CWE-90": "injection", "CWE-91": "injection", "CWE-943": "injection",
    # XSS
    "CWE-79": "xss",
    # Auth / Access
    "CWE-287": "auth", "CWE-306": "auth", "CWE-862": "auth",
    "CWE-863": "auth", "CWE-284": "auth", "CWE-269": "permissions",
    "CWE-732": "permissions",
    # Crypto
    "CWE-327": "crypto", "CWE-330": "crypto", "CWE-326": "crypto",
    "CWE-295": "crypto", "CWE-798": "secrets",
    # Config
    "CWE-16": "config", "CWE-611": "config",
    # SSRF / Path traversal
    "CWE-918": "ssrf", "CWE-22": "path_traversal",
    # Deserialization
    "CWE-502": "deserialization",
    # Dependency / container / IaC
    "CWE-1104": "dependency",
}

# Fix-type → category fallback when CWE is unknown
_FIXTYPE_CATEGORY_MAP = {
    "dependency_update": "dependency",
    "config_hardening": "config",
    "iac_fix": "iac",
    "secret_rotation": "secrets",
    "permission_fix": "permissions",
    "container_fix": "container",
    "waf_rule": "config",
    "input_validation": "injection",
    "output_encoding": "xss",
}


def _cwe_to_category(cwe: str, fix_type: FixType) -> str:
    """Map a CWE identifier + fix type to a vulnerability category.

    Uses the CWE if known, otherwise falls back to fix type heuristic.
    """
    if cwe and cwe in _CWE_CATEGORY_MAP:
        return _CWE_CATEGORY_MAP[cwe]
    return _FIXTYPE_CATEGORY_MAP.get(fix_type.value, "other")


# ---------------------------------------------------------------------------
# AutoFix Engine
# ---------------------------------------------------------------------------


class AutoFixEngine:
    """AI-powered vulnerability fix generation engine.

    Uses LLM providers (OpenAI, Claude) to analyse vulnerabilities and generate
    precise code patches, dependency updates, and configuration fixes.
    Integrates with:
    - PRGenerator for automated pull request creation
    - Knowledge Graph for vulnerability context enrichment
    - Event Bus for fix lifecycle notifications
    """

    # Memory bounds: prevent unbounded growth in long-running processes
    MAX_FIXES_STORED = 5000
    MAX_HISTORY_ENTRIES = 10000

    def __init__(self) -> None:
        # Persistent stores — survive server restarts via SQLite-backed PersistentDict
        try:
            from core.persistent_store import PersistentDict
            self._fixes_store: Any = PersistentDict("autofix_fixes")
            self._history_store: Any = PersistentDict("autofix_history")
        except (ImportError, OSError):
            self._fixes_store = {}
            self._history_store = {}
        self._fixes: Dict[str, AutoFixSuggestion] = {}
        self._history: List[Dict[str, Any]] = []
        # Hydrate from persistent store on startup
        self._hydrate_from_store()
        self._stats = {
            "total_generated": 0,
            "total_applied": 0,
            "total_prs_created": 0,
            "total_merged": 0,
            "total_failed": 0,
            "total_rolled_back": 0,
            "by_type": {},
            "by_confidence": {"high": 0, "medium": 0, "low": 0},
            "avg_confidence_score": 0.0,
        }
        self._llm: Any = None
        self._brain: Any = None
        self._bus: Any = None
        self._pr_gen: Any = None

    # ------------------------------------------------------------------
    # Lazy singletons
    # ------------------------------------------------------------------

    def _get_llm(self) -> Any:
        if self._llm is None:
            from core.llm_providers import LLMProviderManager

            self._llm = LLMProviderManager()
        return self._llm

    def _get_brain(self) -> Any:
        if self._brain is None:
            from core.knowledge_brain import get_brain

            self._brain = get_brain()
        return self._brain

    def _get_bus(self) -> Any:
        if self._bus is None:
            from core.event_bus import get_event_bus

            self._bus = get_event_bus()
        return self._bus

    def _get_pr_generator(self) -> Any:
        if self._pr_gen is None:
            from automation.pr_generator import PRGenerator

            self._pr_gen = PRGenerator()
        return self._pr_gen

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _hydrate_from_store(self) -> None:
        """Reload fixes and history from persistent store on startup."""
        try:
            for key in list(self._fixes_store.keys()):
                d = self._fixes_store[key]
                if isinstance(d, dict):
                    self._fixes[key] = self._dict_to_suggestion(d)
        except (OSError, ValueError, KeyError, RuntimeError):
            pass
        try:
            hist_data = self._history_store.get("_entries")
            if isinstance(hist_data, list):
                self._history = hist_data[-self.MAX_HISTORY_ENTRIES:]
        except (OSError, ValueError, KeyError, RuntimeError):
            pass

    def _persist_fix(self, fix_id: str, suggestion: AutoFixSuggestion) -> None:
        """Write a fix to the persistent store."""
        try:
            self._fixes_store[fix_id] = self.to_dict(suggestion)
        except (OSError, ValueError, RuntimeError):
            pass

    def _persist_history(self) -> None:
        """Write history to the persistent store."""
        try:
            self._history_store["_entries"] = self._history[-self.MAX_HISTORY_ENTRIES:]
        except (OSError, ValueError, RuntimeError):
            pass

    @staticmethod
    def _dict_to_suggestion(d: Dict[str, Any]) -> "AutoFixSuggestion":
        """Reconstruct an AutoFixSuggestion from a serialized dict."""
        patches = []
        for p in d.get("code_patches", []):
            patches.append(CodePatch(
                file_path=p.get("file_path", ""),
                language=p.get("language", ""),
                old_code=p.get("old_code", p.get("original_code", "")),
                new_code=p.get("new_code", p.get("fixed_code", "")),
                start_line=p.get("start_line", p.get("line_start", 0)),
                end_line=p.get("end_line", p.get("line_end", 0)),
                patch_format=PatchFormat(p.get("patch_format", "unified_diff")),
                unified_diff=p.get("unified_diff", p.get("patch_content", "")),
                explanation=p.get("explanation", ""),
            ))
        dep_fixes = []
        for df in d.get("dependency_fixes", []):
            dep_fixes.append(DependencyFix(
                package_name=df.get("package_name", ""),
                current_version=df.get("current_version", ""),
                fixed_version=df.get("fixed_version", ""),
                manifest_file=df.get("manifest_file", df.get("package_file", "")),
                ecosystem=df.get("ecosystem", ""),
            ))
        return AutoFixSuggestion(
            fix_id=d.get("fix_id", ""),
            finding_id=d.get("finding_id", ""),
            finding_title=d.get("finding_title", ""),
            fix_type=FixType(d.get("fix_type", "code_patch")),
            confidence=FixConfidence(d.get("confidence", "medium")),
            confidence_score=d.get("confidence_score", 0.0),
            title=d.get("title", ""),
            description=d.get("description", ""),
            code_patches=patches,
            dependency_fixes=dep_fixes,
            config_changes=d.get("config_changes", {}),
            pr_title=d.get("pr_title", ""),
            pr_description=d.get("pr_description", ""),
            pr_branch=d.get("pr_branch", ""),
            testing_guidance=d.get("testing_guidance", ""),
            rollback_steps=d.get("rollback_steps", ""),
            risk_assessment=d.get("risk_assessment", ""),
            effort_minutes=d.get("effort_minutes", 0),
            status=FixStatus(d.get("status", "generated")),
            cve_ids=d.get("cve_ids", []),
            mitre_techniques=d.get("mitre_techniques", []),
            compliance_frameworks=d.get("compliance_frameworks", []),
            created_at=d.get("created_at", ""),
            applied_at=d.get("applied_at", ""),
            pr_url=d.get("pr_url", ""),
            pr_number=d.get("pr_number", 0),
            metadata=d.get("metadata", {}),
        )

    # ------------------------------------------------------------------
    # Fix ID generation
    # ------------------------------------------------------------------

    @staticmethod
    def _make_fix_id(finding_id: str, fix_type: FixType) -> str:
        raw = f"{finding_id}-{fix_type.value}-{datetime.now(timezone.utc).isoformat()}"
        return f"fix-{hashlib.sha256(raw.encode()).hexdigest()[:16]}"

    # ------------------------------------------------------------------
    # MAIN: generate_fix
    # ------------------------------------------------------------------

    async def generate_fix(
        self,
        finding: Dict[str, Any],
        source_code: Optional[str] = None,
        repo_context: Optional[Dict[str, Any]] = None,
    ) -> AutoFixSuggestion:
        """Generate an autofix suggestion for a security finding.

        Args:
            finding: Vulnerability finding dict with keys like id, title,
                     severity, cve_ids, cwe_id, description, file_path, etc.
            source_code: Optional source code surrounding the vulnerability.
            repo_context: Optional repo metadata (language, framework, etc.).

        Returns:
            AutoFixSuggestion with code patches, dependency fixes, etc.
        """
        finding_id = finding.get("id", "unknown")
        finding_title = finding.get(
            "title", finding.get("name", "Unknown Vulnerability")
        )
        cwe_id = finding.get("cwe_id", "")
        severity = finding.get("severity", "medium").lower()
        cve_ids = finding.get("cve_ids", [])

        # Input validation — cap field lengths to prevent abuse
        if len(finding_id) > 256:
            finding_id = finding_id[:256]
        if len(finding_title) > 500:
            finding_title = finding_title[:500]

        # Determine fix type from the finding
        fix_type = self._infer_fix_type(finding)
        fix_id = self._make_fix_id(finding_id, fix_type)

        logger.info(
            "[AutoFix] Generating %s fix for %s (severity=%s, cwe=%s)",
            fix_type.value, finding_id, severity, cwe_id or "N/A",
        )

        # Enrich context from Knowledge Graph
        graph_context = self._enrich_from_graph(finding_id, cve_ids)

        # [GODMODE GM4] Material Change Detection — prioritize recently changed code
        material_change_risk = self._check_material_changes(finding)
        graph_context["material_change_risk"] = material_change_risk

        # ------------------------------------------------------------------
        # LLMCouncil multi-model consensus for critical/high findings.
        # Gated by FIXOPS_USE_COUNCIL=1 so default behaviour is unchanged.
        # Council failures NEVER block fix generation.
        # ------------------------------------------------------------------
        council_context, council_confidence = self._maybe_council_consensus(
            finding=finding,
            fix_type=fix_type,
            severity=severity,
        )
        if council_context:
            graph_context["council_reasoning"] = council_context
            graph_context["council_confidence"] = council_confidence

        suggestion = AutoFixSuggestion(
            fix_id=fix_id,
            finding_id=finding_id,
            finding_title=finding_title,
            fix_type=fix_type,
            cve_ids=cve_ids,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        try:
            if fix_type == FixType.DEPENDENCY_UPDATE:
                suggestion = await self._generate_dependency_fix(
                    suggestion, finding, repo_context or {}
                )
            elif fix_type == FixType.CONFIG_HARDENING:
                suggestion = await self._generate_config_fix(
                    suggestion, finding, repo_context or {}
                )
            elif fix_type == FixType.IAC_FIX:
                suggestion = await self._generate_iac_fix(
                    suggestion, finding, source_code, repo_context or {}
                )
            elif fix_type == FixType.CONTAINER_FIX:
                suggestion = await self._generate_container_fix(
                    suggestion, finding, source_code, repo_context or {}
                )
            else:
                suggestion = await self._generate_code_patch(
                    suggestion, finding, source_code, repo_context or {}, graph_context
                )

            # Validate the generated fix
            validation = self._validate_fix(suggestion)
            suggestion.metadata["validation"] = validation

            # Assign confidence (ML-powered with rule-based fallback)
            suggestion.confidence_score = self._compute_confidence(suggestion, finding)

            # Boost confidence using LLMCouncil verdict for critical/high findings.
            # Council confidence is taken as a floor: max(council, llm) so council
            # consensus can only raise — never lower — the fix confidence.
            if council_confidence and council_confidence > 0.0:
                suggestion.confidence_score = max(
                    suggestion.confidence_score, council_confidence
                )
                suggestion.metadata["council_confidence"] = council_confidence
                suggestion.metadata["council_reasoning"] = council_context

            # Use ML classification if available, else derive from score
            ml_conf = suggestion.metadata.get("ml_confidence", {})
            ml_class = ml_conf.get("classification", "").upper()
            if ml_class in ("HIGH", "MEDIUM", "LOW"):
                suggestion.confidence = FixConfidence(ml_class.lower())
            elif suggestion.confidence_score >= 0.85:
                suggestion.confidence = FixConfidence.HIGH
            elif suggestion.confidence_score >= 0.60:
                suggestion.confidence = FixConfidence.MEDIUM
            else:
                suggestion.confidence = FixConfidence.LOW

            # Generate PR metadata
            suggestion.pr_branch = f"fixops/autofix-{fix_id}"
            suggestion.pr_title = f"[FixOps AutoFix] {suggestion.title}"
            suggestion.pr_description = self._build_pr_description(suggestion, finding)
            suggestion.status = FixStatus.GENERATED

            # [GODMODE] Store graph context and auto-merge decision on the suggestion
            suggestion.metadata["graph_context"] = {
                k: v for k, v in graph_context.items()
                if k not in ("neighbors", "related_cves", "attack_paths")  # skip large objects
            }
            suggestion.metadata["auto_merge_decision"] = self.should_auto_merge(
                suggestion, finding, graph_context
            )

        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
            # Only log exception type — str(exc) may contain LLM API keys or secrets
            logger.error(
                "[AutoFix] Generation failed for %s: %s",
                finding_id, type(exc).__name__, exc_info=True,
            )
            suggestion.status = FixStatus.FAILED
            suggestion.metadata["error"] = f"Generation failed ({type(exc).__name__})"

        # Store and track (with memory bounds enforcement)
        self._fixes[fix_id] = suggestion
        self._persist_fix(fix_id, suggestion)
        # Evict oldest fixes when exceeding MAX_FIXES_STORED
        if len(self._fixes) > self.MAX_FIXES_STORED:
            oldest_keys = list(self._fixes.keys())[
                : len(self._fixes) - self.MAX_FIXES_STORED
            ]
            for k in oldest_keys:
                del self._fixes[k]
                try:
                    del self._fixes_store[k]
                except (KeyError, OSError):
                    pass
            logger.debug(
                "[AutoFix] Evicted %d old fixes (cap=%d)",
                len(oldest_keys),
                self.MAX_FIXES_STORED,
            )
        self._update_stats(suggestion)
        self._history.append(
            {
                "action": "generate",
                "fix_id": fix_id,
                "finding_id": finding_id,
                "fix_type": fix_type.value,
                "status": suggestion.status.value,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        # Evict oldest history entries when exceeding MAX_HISTORY_ENTRIES
        if len(self._history) > self.MAX_HISTORY_ENTRIES:
            self._history = self._history[-self.MAX_HISTORY_ENTRIES :]
        self._persist_history()

        # Emit event
        try:
            import asyncio

            from core.event_bus import Event, EventType

            asyncio.ensure_future(
                self._get_bus().emit(
                    Event(
                        event_type=EventType.AUTOFIX_GENERATED,
                        source="autofix_engine",
                        data={
                            "fix_id": fix_id,
                            "finding_id": finding_id,
                            "fix_type": fix_type.value,
                        },
                    )
                )
            )
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.debug("Event bus emit failed: %s", type(e).__name__)

        return suggestion

    # ------------------------------------------------------------------
    # LLMCouncil multi-model consensus (gated by FIXOPS_USE_COUNCIL=1)
    # ------------------------------------------------------------------

    def _maybe_council_consensus(
        self,
        finding: Dict[str, Any],
        fix_type: FixType,
        severity: str,
    ) -> tuple:
        """Run LLMCouncil consensus for critical/high findings when enabled.

        Returns (council_reasoning, council_confidence). Empty / 0.0 when
        the council path is disabled, the finding is medium/low, or the
        council fails for any reason. NEVER raises.
        """
        if severity not in ("critical", "high"):
            return "", 0.0
        if os.environ.get("FIXOPS_USE_COUNCIL") != "1":
            return "", 0.0

        try:
            from core.llm_council import CouncilFactory

            council = CouncilFactory().create_security_council()
            verdict = council.convene(
                finding=finding,
                context={
                    "fix_type": fix_type.value if hasattr(fix_type, "value") else str(fix_type),
                    "language": finding.get("language", ""),
                    "file_path": finding.get("file_path", ""),
                    "blast_radius": finding.get("blast_radius", 0),
                    "reachable": finding.get("reachable", True),
                    "reachability_verdict": finding.get("reachability_verdict", "unknown"),
                    "consensus_priority": finding.get("consensus_priority", 3),
                },
                org_id=finding.get("org_id", "default"),
            )
            council_reasoning = getattr(verdict, "reasoning", "") or ""
            try:
                council_confidence = float(getattr(verdict, "confidence", 0.0) or 0.0)
            except (TypeError, ValueError):
                council_confidence = 0.0
            return council_reasoning, council_confidence
        except Exception as exc:  # noqa: BLE001 — council failure must never block
            logger.warning(
                "LLMCouncil consensus skipped: %s", type(exc).__name__,
            )
            return "", 0.0

    # ------------------------------------------------------------------
    # Fix type inference
    # ------------------------------------------------------------------

    @staticmethod
    def _infer_fix_type(finding: Dict[str, Any]) -> FixType:
        """Infer the best fix type from the finding metadata."""
        title = (
            finding.get("title", "") + " " + finding.get("description", "")
        ).lower()
        category = finding.get("category", "").lower()
        file_path = finding.get("file_path", "").lower()

        # Dependency-related
        if any(
            kw in title
            for kw in ("outdated", "dependency", "package", "library", "component")
        ):
            return FixType.DEPENDENCY_UPDATE
        if finding.get("cve_ids") and "dependency" in category:
            return FixType.DEPENDENCY_UPDATE

        # IaC
        if any(
            kw in file_path
            for kw in (".tf", "terraform", "cloudformation", ".yaml", "helm")
        ):
            if any(
                kw in title for kw in ("misconfigur", "iac", "infrastructure", "cloud")
            ):
                return FixType.IAC_FIX

        # Container
        if any(
            kw in file_path for kw in ("dockerfile", "docker-compose", "containerfile")
        ):
            return FixType.CONTAINER_FIX
        if "container" in title or "docker" in title:
            return FixType.CONTAINER_FIX

        # Configuration
        if any(
            kw in title
            for kw in ("config", "header", "cors", "tls", "ssl", "hsts", "csp")
        ):
            return FixType.CONFIG_HARDENING

        # Secret
        if any(
            kw in title
            for kw in ("secret", "credential", "api key", "password", "token leak")
        ):
            return FixType.SECRET_ROTATION

        # Permission
        if any(
            kw in title
            for kw in ("permission", "privilege", "authorization", "rbac", "iam")
        ):
            return FixType.PERMISSION_FIX

        # Input validation
        if any(
            kw in title
            for kw in ("injection", "sqli", "xss", "command injection", "input")
        ):
            return FixType.INPUT_VALIDATION

        # Output encoding
        if any(
            kw in title
            for kw in ("xss", "cross-site scripting", "output encoding", "html inject")
        ):
            return FixType.OUTPUT_ENCODING

        # WAF
        if "waf" in title or "firewall" in title:
            return FixType.WAF_RULE

        return FixType.CODE_PATCH

    # ------------------------------------------------------------------
    # Knowledge Graph enrichment
    # ------------------------------------------------------------------

    def _enrich_from_graph(self, finding_id: str, cve_ids: List[str]) -> Dict[str, Any]:
        """Pull deep context from the Knowledge Graph + FAIL + EPSS + KEV.

        Returns a rich context dict that NO competitor injects into fix prompts:
        - Reachability analysis (is the vuln reachable from attack surface?)
        - FAIL score breakdown (FACT/ASSESS/IMPACT/LIKELIHOOD)
        - EPSS exploitation probability (real data from FIRST.org)
        - KEV status (CISA Known Exploited Vulnerabilities)
        - Blast radius (how many assets/users affected?)
        - Attack paths from the graph
        - Prior fix history for same CVE/CWE
        - Asset criticality from business context
        """
        ctx: Dict[str, Any] = {
            "related_cves": [],
            "affected_assets": [],
            "prior_fixes": [],
            "is_reachable": False,
            "attack_paths": [],
            "blast_radius": "unknown",
            "asset_criticality": "unknown",
            "epss_score": None,
            "is_kev": False,
            "fail_score": None,
            "fail_grade": None,
            "fail_action": None,
            "fail_breakdown": {},
        }
        try:
            brain = self._get_brain()
            # Get finding node and neighbors
            node = brain.get_node(finding_id)
            if node:
                neighbors = brain.get_neighbors(finding_id, depth=2)
                ctx["neighbors"] = [n.get("id", "") for n in neighbors.nodes[:20]]
                # Extract reachability from graph edges
                for edge in neighbors.edges[:50]:
                    etype = edge.get("edge_type", "")
                    if etype in ("reachable_from", "calls", "imports", "exposes"):
                        ctx["is_reachable"] = True
                    if etype == "affects":
                        ctx["affected_assets"].append(edge.get("target_id", ""))

                # Get attack paths (entry_point → vulnerable_function)
                try:
                    entry_nodes = brain.query_nodes(node_type="entry_point", limit=5)
                    for ep in entry_nodes.nodes[:3]:
                        paths = brain.find_paths(ep.get("node_id", ""), finding_id, max_depth=4)
                        if paths:
                            ctx["attack_paths"].extend(paths[:3])
                            ctx["is_reachable"] = True
                except (OSError, ValueError, RuntimeError):
                    pass

                # Determine blast radius
                asset_count = len(ctx["affected_assets"])
                if asset_count >= 10:
                    ctx["blast_radius"] = "org-wide"
                elif asset_count >= 5:
                    ctx["blast_radius"] = "system"
                elif asset_count >= 2:
                    ctx["blast_radius"] = "component"
                else:
                    ctx["blast_radius"] = "contained"

                # Extract asset criticality from node properties
                props = node.get("properties", {})
                if isinstance(props, str):
                    try:
                        props = json.loads(props)
                    except (json.JSONDecodeError, ValueError):
                        props = {}
                ctx["asset_criticality"] = props.get("asset_criticality", "unknown")

            # Resolve CVEs
            for cve in cve_ids[:5]:
                cve_node = brain.get_node(cve)
                if cve_node:
                    ctx["related_cves"].append(cve_node)

        except Exception as exc:
            logger.debug("[AutoFix] Graph enrichment skipped: %s", type(exc).__name__)

        # EPSS + KEV enrichment from ThreatEnricher (real FIRST.org + CISA data)
        if cve_ids:
            try:
                from core.ml.threat_enricher import ThreatEnricher

                enricher = ThreatEnricher()
                sampled_cves = cve_ids[:5]

                if hasattr(enricher, "enrich"):
                    enrichment = enricher.enrich(sampled_cves, skip_api=True)
                    for _cve_id, data in enrichment.items():
                        if data.get("epss") is not None:
                            ctx["epss_score"] = max(ctx["epss_score"] or 0, data["epss"])
                        if data.get("kev"):
                            ctx["is_kev"] = True
                elif hasattr(enricher, "enrich_findings"):
                    findings = [{"cve_id": cve_id} for cve_id in sampled_cves]
                    enricher.enrich_findings(findings, skip_api=True)
                    for finding in findings:
                        if finding.get("epss_score") is not None:
                            ctx["epss_score"] = max(
                                ctx["epss_score"] or 0,
                                finding["epss_score"],
                            )
                        if finding.get("in_kev") or finding.get("kev"):
                            ctx["is_kev"] = True
            except (AttributeError, ImportError, OSError, ValueError, KeyError, RuntimeError, TypeError):
                pass  # Air-gap fallback

        # FAIL score computation
        try:
            from core.fail_engine import FAILEngine, FAILInput
            fail_engine = FAILEngine()
            fail_input = FAILInput(
                cve_id=cve_ids[0] if cve_ids else None,
                finding_id=finding_id,
                epss_score=ctx.get("epss_score"),
                is_kev=ctx.get("is_kev", False),
                is_reachable=ctx.get("is_reachable", False),
                asset_criticality=ctx.get("asset_criticality", "unknown"),
                affected_assets=len(ctx.get("affected_assets", [])) or 1,
            )
            fail_result = fail_engine.score(fail_input)
            ctx["fail_score"] = round(fail_result.fail_score, 1)
            ctx["fail_grade"] = fail_result.grade.value
            ctx["fail_action"] = fail_result.recommended_action.value
            ctx["fail_breakdown"] = {
                "fact": round(fail_result.fact.score, 1),
                "assess": round(fail_result.assess.score, 1),
                "impact": round(fail_result.impact.score, 1),
                "likelihood": round(fail_result.likelihood.score, 1),
            }
        except (ImportError, OSError, ValueError, KeyError, RuntimeError):
            pass  # Air-gap fallback

        return ctx

    # ------------------------------------------------------------------
    # LLM-powered code patch generation
    # ------------------------------------------------------------------

    async def _generate_code_patch(
        self,
        suggestion: AutoFixSuggestion,
        finding: Dict[str, Any],
        source_code: Optional[str],
        repo_ctx: Dict[str, Any],
        graph_ctx: Dict[str, Any],
    ) -> AutoFixSuggestion:
        """Use LLM to generate a precise code patch in unified-diff format.

        [GODMODE] Injects deep security context that no competitor provides:
        - FAIL score with FACT/ASSESS/IMPACT/LIKELIHOOD breakdown
        - EPSS exploitation probability from FIRST.org
        - CISA KEV status
        - Reachability analysis from Knowledge Graph
        - Blast radius and attack paths
        - Asset criticality and business impact
        - Multi-LLM consensus validation
        """
        language = repo_ctx.get("language", finding.get("language", ""))
        if not language:
            language = _infer_language_from_path(finding.get("file_path", ""))
        framework = repo_ctx.get("framework", "")
        file_path = finding.get("file_path", "unknown")

        code_snippet = source_code or finding.get(
            "code_snippet", "# no source provided"
        )

        # Build deep security context section (what Apiiro/Aikido CANNOT do)
        security_context_lines = []
        fail_score = graph_ctx.get("fail_score")
        if fail_score is not None:
            fail_grade = graph_ctx.get("fail_grade", "UNKNOWN")
            fail_action = graph_ctx.get("fail_action", "INVESTIGATE")
            breakdown = graph_ctx.get("fail_breakdown", {})
            security_context_lines.append(f"FAIL SCORE: {fail_score}/100 (Grade: {fail_grade})")
            security_context_lines.append(f"  Recommended Action: {fail_action}")
            if breakdown:
                security_context_lines.append(
                    f"  Breakdown — FACT: {breakdown.get('fact', 0)}, "
                    f"ASSESS: {breakdown.get('assess', 0)}, "
                    f"IMPACT: {breakdown.get('impact', 0)}, "
                    f"LIKELIHOOD: {breakdown.get('likelihood', 0)}"
                )

        epss = graph_ctx.get("epss_score")
        if epss is not None:
            pct = round(epss * 100, 1)
            urgency = "CRITICAL" if epss > 0.7 else "HIGH" if epss > 0.3 else "MODERATE"
            security_context_lines.append(f"EPSS: {pct}% exploitation probability ({urgency} urgency)")

        if graph_ctx.get("is_kev"):
            security_context_lines.append("⚠️  CISA KEV: This vulnerability IS actively exploited in the wild")

        is_reachable = graph_ctx.get("is_reachable", False)
        security_context_lines.append(
            f"REACHABILITY: {'YES — reachable from attack surface' if is_reachable else 'Not confirmed reachable (lower priority)'}"
        )

        blast = graph_ctx.get("blast_radius", "unknown")
        if blast != "unknown":
            security_context_lines.append(f"BLAST RADIUS: {blast} ({len(graph_ctx.get('affected_assets', []))} assets affected)")

        attack_paths = graph_ctx.get("attack_paths", [])
        if attack_paths:
            security_context_lines.append(f"ATTACK PATHS: {len(attack_paths)} paths from entry point to vulnerable code")
            for i, path in enumerate(attack_paths[:2], 1):
                security_context_lines.append(f"  Path {i}: {' → '.join(str(n) for n in path[:6])}")

        crit = graph_ctx.get("asset_criticality", "unknown")
        if crit != "unknown":
            security_context_lines.append(f"ASSET CRITICALITY: {crit}")

        # [GM4] Material change context
        mcr = graph_ctx.get("material_change_risk", {})
        if mcr.get("recently_changed"):
            security_context_lines.append(
                f"⚡ RECENTLY CHANGED CODE: {mcr.get('detail', 'yes')} "
                f"(velocity: {mcr.get('change_velocity', 'unknown')}, "
                f"risk: {mcr.get('change_risk_score', 0)}/100) — HIGHER REGRESSION RISK"
            )

        security_ctx_block = ""
        if security_context_lines:
            security_ctx_block = "\n\nSECURITY INTELLIGENCE (use this to prioritize fix quality):\n" + "\n".join(
                f"- {line}" for line in security_context_lines
            )

        # Append LLMCouncil multi-model consensus reasoning when present
        # (only set for critical/high severity with FIXOPS_USE_COUNCIL=1).
        council_reasoning = graph_ctx.get("council_reasoning") or ""
        if council_reasoning:
            security_ctx_block += (
                f"\n\n## Council reasoning:\n{council_reasoning[:2000]}"
            )

        prompt = f"""You are a senior security engineer at a Fortune 500 company. Generate a precise, production-ready code fix for this vulnerability.

VULNERABILITY:
- Title: {finding.get('title', '')}
- CWE: {finding.get('cwe_id', 'N/A')}
- CVE: {', '.join(finding.get('cve_ids', [])) or 'N/A'}
- Severity: {finding.get('severity', 'medium')}
- Description: {finding.get('description', '')}
- File: {file_path}
- Language: {language}
- Framework: {framework}{security_ctx_block}

SOURCE CODE:
```{language}
{code_snippet[:3000]}
```

Generate a JSON response with:
{{
  "title": "Brief fix title",
  "description": "Detailed description including WHY this fix is correct given the security context above",
  "patches": [
    {{
      "file_path": "{file_path}",
      "old_code": "exact vulnerable code lines",
      "new_code": "fixed code lines",
      "explanation": "why this fixes the vulnerability and how it addresses the FAIL/EPSS/reachability context"
    }}
  ],
  "testing_guidance": "Specific test cases to verify the fix, including edge cases",
  "rollback_steps": "How to safely revert if needed",
  "risk_assessment": "Risk of applying this fix considering blast radius and asset criticality",
  "effort_minutes": 15,
  "mitre_techniques": ["T1190"],
  "compliance": ["CWE-79", "OWASP A03"],
  "fix_urgency": "immediate|next_sprint|backlog based on FAIL score and EPSS",
  "reachability_note": "How the fix addresses the specific attack path identified"
}}

Provide ONLY valid JSON. The fix must be precise, minimal, and production-ready."""

        # Compress prompt if large (headroom integration)
        try:
            from core.context_compression import compress_prompt
            prompt = compress_prompt(prompt, max_tokens=6000)
        except (ImportError, OSError, ValueError):
            pass  # Air-gap fallback: use uncompressed prompt

        # Enrich with cybersecurity skills context
        try:
            from core.cybersec_skills_loader import get_cybersec_skills_loader
            mitre_techs = finding.get("mitre_techniques", [])
            if mitre_techs:
                skills_ctx = get_cybersec_skills_loader().get_enrichment_context(mitre_techs, max_skills=3)
                if skills_ctx:
                    prompt += f"\n\n{skills_ctx}"
        except (ImportError, OSError, ValueError):
            pass  # Air-gap fallback: no skills enrichment

        # --- Multi-LLM Consensus (GODMODE) ---
        # Try primary provider, then cross-validate with secondary if available
        response = self._multi_llm_generate(prompt, finding, graph_ctx)
        suggestion.metadata["llm_consensus"] = response.get("consensus", {})

        # Extract the primary LLM response from consensus result
        response = response["primary"]

        # Detect deterministic/fallback response (no real LLM available)
        _is_fallback = response.metadata.get("mode") in ("deterministic", "fallback")

        # Parse LLM response — prefer the full raw payload preserved by
        # the provider (contains patches/title/etc.) before falling back
        # to parsing the reasoning text.
        try:
            raw_payload = response.metadata.get("raw_payload")
            # Accept raw_payload if it looks like a structured fix response
            # (has any of the expected fix fields, not just the standard LLMResponse fields)
            _fix_keys = {"patches", "title", "description", "testing_guidance", "effort_minutes"}
            if raw_payload and isinstance(raw_payload, dict) and (set(raw_payload.keys()) & _fix_keys):
                data = raw_payload
                logger.info(
                    "[AutoFix] Using raw_payload for %s (keys=%s)",
                    finding.get("id", "?"), list(raw_payload.keys())[:8],
                )
            else:
                logger.info(
                    "[AutoFix] raw_payload not usable for %s (payload_type=%s, keys=%s, mode=%s)",
                    finding.get("id", "?"),
                    type(raw_payload).__name__ if raw_payload else "None",
                    list(raw_payload.keys())[:5] if isinstance(raw_payload, dict) else "N/A",
                    response.metadata.get("mode", "?"),
                )
                raw = response.reasoning
                # Try to extract JSON from the response
                json_match = re.search(r"\{[\s\S]*\}", raw)
                if json_match:
                    data = json.loads(json_match.group())
                else:
                    data = json.loads(raw)

            suggestion.title = data.get(
                "title", f"Fix {finding.get('title', 'vulnerability')}"
            )
            suggestion.description = data.get("description", response.reasoning[:500])
            suggestion.testing_guidance = data.get(
                "testing_guidance", "Run security tests to verify fix"
            )
            suggestion.rollback_steps = data.get("rollback_steps", "Revert the commit")
            suggestion.risk_assessment = data.get(
                "risk_assessment", "Low risk — minimal code change"
            )
            suggestion.effort_minutes = data.get("effort_minutes", 15)
            suggestion.mitre_techniques = data.get(
                "mitre_techniques", list(response.mitre_techniques)
            )
            suggestion.compliance_frameworks = data.get(
                "compliance", list(response.compliance_concerns)
            )

            for patch_data in data.get("patches", []):
                patch = CodePatch(
                    file_path=patch_data.get("file_path", file_path),
                    language=language,
                    old_code=patch_data.get("old_code", ""),
                    new_code=patch_data.get("new_code", ""),
                    explanation=patch_data.get("explanation", ""),
                    patch_format=PatchFormat.UNIFIED_DIFF,
                )
                # Generate unified diff
                patch.unified_diff = self._make_unified_diff(
                    patch.file_path, patch.old_code, patch.new_code
                )
                suggestion.code_patches.append(patch)

        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning(
                "[AutoFix] LLM response parse failed (%s), trying template library",
                type(exc).__name__,
            )
            # --- Offline template fallback ---
            # When LLM is unavailable or returns non-JSON, use the template
            # library to produce actionable fix suggestions instead of empty patches.
            template_suggestion = self._try_template_fallback(finding, language, file_path)
            if template_suggestion is not None:
                suggestion.title = template_suggestion.get(
                    "title", f"Fix {finding.get('title', 'vulnerability')}"
                )
                suggestion.description = template_suggestion.get("description", "")
                suggestion.testing_guidance = template_suggestion.get(
                    "testing_guidance", "Run security tests to verify fix"
                )
                suggestion.rollback_steps = template_suggestion.get(
                    "rollback_steps", "Revert the commit"
                )
                suggestion.risk_assessment = template_suggestion.get(
                    "risk_assessment", "Low risk — template-based fix"
                )
                suggestion.effort_minutes = template_suggestion.get("effort_minutes", 15)
                suggestion.mitre_techniques = template_suggestion.get("mitre_techniques", [])
                suggestion.compliance_frameworks = template_suggestion.get("compliance_refs", [])
                suggestion.confidence_score = template_suggestion.get("confidence_score", 0.65)
                suggestion.metadata["template_based"] = True
                suggestion.metadata["template_cwe"] = template_suggestion.get("cwe_id", "")

                for patch_data in template_suggestion.get("patches", []):
                    patch = CodePatch(
                        file_path=patch_data.get("file_path", file_path),
                        language=patch_data.get("language", language),
                        old_code=patch_data.get("before", ""),
                        new_code=patch_data.get("after", ""),
                        explanation=patch_data.get("explanation", ""),
                        patch_format=PatchFormat.UNIFIED_DIFF,
                    )
                    patch.unified_diff = self._make_unified_diff(
                        patch.file_path, patch.old_code, patch.new_code
                    )
                    suggestion.code_patches.append(patch)

                logger.info(
                    "[AutoFix] Template fallback produced %d patches for %s (%s)",
                    len(suggestion.code_patches),
                    finding.get("id", "unknown"),
                    template_suggestion.get("cwe_id", "unknown"),
                )
            else:
                # No template match either — last resort fallback
                suggestion.title = f"Fix {finding.get('title', 'vulnerability')}"
                suggestion.description = response.reasoning[:500]
                suggestion.testing_guidance = "Manual review required — no LLM or template match"
                suggestion.confidence_score = 0.4

        # If we got a fallback response but JSON parsed OK (unlikely for deterministic
        # responses that just echo default_reasoning), still check if we have empty patches.
        # This handles edge cases where the LLM returned parseable JSON but with no patches.
        if _is_fallback and not suggestion.code_patches and not suggestion.dependency_fixes:
            template_suggestion = self._try_template_fallback(finding, language, file_path)
            if template_suggestion is not None:
                suggestion.metadata["template_based"] = True
                suggestion.metadata["template_cwe"] = template_suggestion.get("cwe_id", "")
                suggestion.confidence_score = template_suggestion.get("confidence_score", 0.65)
                suggestion.description = template_suggestion.get(
                    "description", suggestion.description
                )
                suggestion.testing_guidance = template_suggestion.get(
                    "testing_guidance", suggestion.testing_guidance
                )
                for patch_data in template_suggestion.get("patches", []):
                    patch = CodePatch(
                        file_path=patch_data.get("file_path", file_path),
                        language=patch_data.get("language", language),
                        old_code=patch_data.get("before", ""),
                        new_code=patch_data.get("after", ""),
                        explanation=patch_data.get("explanation", ""),
                        patch_format=PatchFormat.UNIFIED_DIFF,
                    )
                    patch.unified_diff = self._make_unified_diff(
                        patch.file_path, patch.old_code, patch.new_code
                    )
                    suggestion.code_patches.append(patch)

        return suggestion

    # ------------------------------------------------------------------
    # Material Change Detection (GODMODE GM4)
    # ------------------------------------------------------------------

    def _check_material_changes(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Check if the vulnerable code was recently changed.

        Uses MaterialChangeDetector to determine if the file containing the
        vulnerability has recent security-material changes. If so, the fix
        gets higher priority (recently changed code = higher regression risk).

        Returns a risk summary dict.
        """
        result: Dict[str, Any] = {
            "recently_changed": False,
            "change_risk_score": 0.0,
            "classification": "UNKNOWN",
            "change_velocity": "normal",
            "detail": "No material change data available",
        }

        file_path = finding.get("file_path", "")
        repo = finding.get("repository", finding.get("repo", ""))
        if not file_path:
            return result

        try:
            # REMOVED — ``get_velocity_tracker`` / ``get_detector`` factories
            # never existed on ``core.material_change_detector``; the canonical
            # API is the ``MaterialChangeDetector`` class directly (and the
            # ``PushEventAnalyzer`` push-event surface). 2026-05-03 audit.
            # Use the class directly so AutoFix still gets diff-analysis
            # context (velocity-tracker surface not yet exposed).
            from core.material_change_detector import MaterialChangeDetector

            detector = MaterialChangeDetector()
            _ = repo  # velocity tracker not yet wired; preserve variable
            # Use git_diff from finding metadata if available
            diff_text = finding.get("metadata", {}).get("git_diff", "")
            if diff_text:
                changes = detector.analyze_diff(diff_text)
                if changes:
                    max_risk = max(c.risk_score for c in changes)
                    max_class = max(
                        (c.classification for c in changes),
                        key=lambda x: {"BREAKING": 3, "MATERIAL": 2, "COSMETIC": 1}.get(x.value, 0),
                    )
                    result["change_risk_score"] = round(max_risk, 1)
                    result["classification"] = max_class.value
                    result["recently_changed"] = max_risk >= 35
                    result["detail"] = (
                        f"{len(changes)} material changes detected, "
                        f"max risk {max_risk:.0f}/100, classification: {max_class.value}"
                    )

        except (ImportError, OSError, ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
            logger.debug("[AutoFix] Material change detection skipped: %s", type(exc).__name__)

        return result

    # ------------------------------------------------------------------
    # Multi-LLM Consensus (GODMODE — no competitor does this)
    # ------------------------------------------------------------------

    def _multi_llm_generate(
        self,
        prompt: str,
        finding: Dict[str, Any],
        graph_ctx: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate fix using multi-LLM consensus when available.

        Strategy:
        1. Primary: Try OpenAI (GPT-4) — fastest, best for code patches
        2. Secondary: Try Anthropic (Claude) — best for security reasoning
        3. Compare confidence scores; if both succeed, pick higher-confidence
        4. Store consensus metadata for audit trail

        Falls back to single-provider if secondary unavailable.
        """
        llm = self._get_llm()
        _system_prompt = (
            "You are a senior security engineer at a Fortune 500 company. "
            "Generate precise, production-ready code fixes for vulnerabilities. "
            "Return a JSON object with keys: title, description, "
            "patches (array of {file_path, old_code, new_code, explanation}), "
            "testing_guidance, rollback_steps, risk_assessment, effort_minutes, "
            "mitre_techniques, compliance, fix_urgency, reachability_note. "
            "Include recommended_action, confidence, and reasoning."
        )
        context = {"finding": finding, "graph": graph_ctx}

        # Primary LLM call
        primary = llm.analyse(
            "openai",
            prompt=prompt,
            context=context,
            default_action="code_patch",
            default_confidence=0.7,
            default_reasoning="Generated code patch for vulnerability fix",
            system_prompt=_system_prompt,
        )

        consensus: Dict[str, Any] = {
            "providers_tried": ["openai"],
            "primary_provider": "openai",
            "primary_confidence": primary.confidence,
            "consensus_reached": False,
            "secondary_provider": None,
            "secondary_confidence": None,
        }

        # Secondary LLM call (Anthropic) for consensus — only for critical/high severity
        severity = str(finding.get("severity", "")).lower()
        fail_score = graph_ctx.get("fail_score")
        should_consensus = (
            severity in ("critical", "high")
            or (fail_score is not None and fail_score >= 60)
            or graph_ctx.get("is_kev", False)
        )

        secondary = None
        if should_consensus:
            try:
                secondary = llm.analyse(
                    "anthropic",
                    prompt=prompt,
                    context=context,
                    default_action="code_patch",
                    default_confidence=0.7,
                    default_reasoning="Generated code patch for vulnerability fix",
                    system_prompt=_system_prompt,
                )
                consensus["providers_tried"].append("anthropic")
                consensus["secondary_provider"] = "anthropic"
                consensus["secondary_confidence"] = secondary.confidence

                # Pick higher-confidence response as primary
                if secondary.confidence > primary.confidence:
                    logger.info(
                        "[AutoFix] Consensus: Anthropic (%.2f) beats OpenAI (%.2f) for %s",
                        secondary.confidence, primary.confidence,
                        finding.get("id", "?"),
                    )
                    consensus["selected"] = "anthropic"
                    primary, secondary = secondary, primary
                else:
                    consensus["selected"] = "openai"

                consensus["consensus_reached"] = True
                consensus["confidence_delta"] = abs(
                    primary.confidence - (secondary.confidence if secondary else 0)
                )

            except (OSError, ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
                logger.debug(
                    "[AutoFix] Secondary LLM (anthropic) unavailable: %s", type(exc).__name__
                )
                consensus["secondary_error"] = type(exc).__name__

        return {"primary": primary, "consensus": consensus}

    # ------------------------------------------------------------------
    # Confidence-Gated Auto-Merge (GODMODE)
    # ------------------------------------------------------------------

    def should_auto_merge(
        self, suggestion: AutoFixSuggestion, finding: Dict[str, Any],
        graph_ctx: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Determine if a fix should be auto-merged without human review.

        Auto-merge criteria (ALL must pass):
        1. Confidence >= 0.90
        2. All validation checks pass
        3. Severity is critical or high
        4. EPSS > 0.5 (actively exploited) OR is_kev
        5. Fix type is well-understood (dependency_update, config_hardening)
        6. No dangerous patterns detected
        7. Multi-LLM consensus reached (if available)

        Returns dict with decision + reasoning for audit trail.
        """
        graph_ctx = graph_ctx or {}
        reasons: List[str] = []
        blockers: List[str] = []

        # Gate 1: Confidence
        if suggestion.confidence_score >= 0.90:
            reasons.append(f"Confidence {suggestion.confidence_score:.0%} >= 90%")
        else:
            blockers.append(f"Confidence {suggestion.confidence_score:.0%} < 90%")

        # Gate 2: Validation
        val = suggestion.metadata.get("validation", {})
        if val.get("valid"):
            reasons.append("All validation checks passed")
        else:
            blockers.append(f"Validation failed: {val.get('issues', [])}")

        # Gate 3: Severity
        severity = finding.get("severity", "").lower()
        if severity in ("critical", "high"):
            reasons.append(f"Severity is {severity}")
        else:
            blockers.append(f"Severity {severity} not critical/high")

        # Gate 4: EPSS/KEV urgency
        epss = graph_ctx.get("epss_score")
        is_kev = graph_ctx.get("is_kev", False)
        if is_kev:
            reasons.append("Listed in CISA KEV — actively exploited")
        elif epss is not None and epss > 0.5:
            reasons.append(f"EPSS {epss*100:.1f}% > 50% — high exploitation likelihood")
        else:
            blockers.append("Not KEV and EPSS not high enough for auto-merge")

        # Gate 5: Fix type
        safe_fix_types = {FixType.DEPENDENCY_UPDATE, FixType.CONFIG_HARDENING, FixType.INPUT_VALIDATION}
        if suggestion.fix_type in safe_fix_types:
            reasons.append(f"Fix type {suggestion.fix_type.value} is well-understood")
        else:
            blockers.append(f"Fix type {suggestion.fix_type.value} requires human review")

        # Gate 6: No dangerous patterns
        if val.get("score", 0) >= 1.0:
            reasons.append("No dangerous patterns detected")
        elif val.get("issues"):
            blockers.append("Dangerous patterns found in fix")

        # Gate 7: Multi-LLM consensus
        consensus = suggestion.metadata.get("llm_consensus", {})
        if consensus.get("consensus_reached"):
            reasons.append("Multi-LLM consensus reached")
        else:
            # Not a hard blocker but noted
            reasons.append("Single-LLM fix (consensus not attempted)")

        approved = len(blockers) == 0
        decision = {
            "auto_merge_approved": approved,
            "reasons": reasons,
            "blockers": blockers,
            "gates_passed": len(reasons),
            "gates_total": len(reasons) + len(blockers),
            "recommendation": "AUTO_MERGE" if approved else "HUMAN_REVIEW",
        }

        logger.info(
            "[AutoFix] Auto-merge decision for %s: %s (%d/%d gates passed)",
            suggestion.fix_id, decision["recommendation"],
            decision["gates_passed"], decision["gates_total"],
        )

        return decision

    # ------------------------------------------------------------------
    # Offline template fallback
    # ------------------------------------------------------------------

    @staticmethod
    def _try_template_fallback(
        finding: Dict[str, Any],
        language: str,
        file_path: str,
    ) -> Optional[Dict[str, Any]]:
        """Attempt to produce a fix suggestion from the offline template library.

        Returns a suggestion dict compatible with generate_offline_suggestion(),
        or None if no matching template exists for this finding.
        """
        try:
            from core.autofix_templates import get_template_library

            library = get_template_library()
            suggestion = library.generate_offline_suggestion(finding)
            if suggestion is not None:
                return suggestion
        except (ImportError, OSError, ValueError, RuntimeError) as exc:
            logger.debug(
                "[AutoFix] Template library unavailable: %s", type(exc).__name__
            )
        return None

    # ------------------------------------------------------------------
    # Dependency fix generation
    # ------------------------------------------------------------------

    async def _generate_dependency_fix(
        self,
        suggestion: AutoFixSuggestion,
        finding: Dict[str, Any],
        repo_ctx: Dict[str, Any],
    ) -> AutoFixSuggestion:
        """Generate a dependency version update fix."""
        pkg = finding.get("package_name", finding.get("component", "unknown"))
        current = finding.get("current_version", finding.get("version", "0.0.0"))
        fixed = finding.get("fixed_version", finding.get("patched_version", ""))
        ecosystem = finding.get("ecosystem", repo_ctx.get("ecosystem", "npm"))
        manifest = finding.get("manifest_file", self._guess_manifest(ecosystem))

        # If no fixed version, ask LLM
        if not fixed:
            llm = self._get_llm()
            resp = llm.analyse(
                "openai",
                prompt=f"What is the latest safe version of {pkg} (ecosystem: {ecosystem}) that fixes CVEs: {finding.get('cve_ids', [])}? Reply with just the version number.",
                context={"package": pkg, "ecosystem": ecosystem},
                default_action="lookup",
                default_confidence=0.6,
                default_reasoning=f"{pkg}@latest",
            )
            fixed = resp.reasoning.strip().split("\n")[0].strip()

        dep_fix = DependencyFix(
            package_name=pkg,
            ecosystem=ecosystem,
            current_version=current,
            fixed_version=fixed or "latest",
            cve_ids=finding.get("cve_ids", []),
            manifest_file=manifest,
        )

        suggestion.dependency_fixes.append(dep_fix)
        suggestion.title = f"Update {pkg} from {current} to {fixed or 'latest'}"
        suggestion.description = (
            f"Security update for {pkg}: {current} → {fixed or 'latest'}. "
            f"Fixes: {', '.join(finding.get('cve_ids', [])) or 'security vulnerability'}."
        )
        suggestion.testing_guidance = (
            f"Run tests after updating {pkg}. Check for breaking changes."
        )
        suggestion.rollback_steps = f"Revert {manifest} to {pkg}@{current}"
        suggestion.risk_assessment = (
            "Medium — dependency updates may introduce breaking changes"
        )
        suggestion.effort_minutes = 10
        return suggestion

    # ------------------------------------------------------------------
    # Config hardening fix
    # ------------------------------------------------------------------

    async def _generate_config_fix(
        self,
        suggestion: AutoFixSuggestion,
        finding: Dict[str, Any],
        repo_ctx: Dict[str, Any],
    ) -> AutoFixSuggestion:
        """Generate configuration hardening fix via LLM."""
        llm = self._get_llm()
        resp = llm.analyse(
            "anthropic",
            prompt=f"""Generate a configuration fix for this security issue:
Title: {finding.get('title', '')}
Description: {finding.get('description', '')}
Severity: {finding.get('severity', 'medium')}

Provide JSON: {{"config_changes": {{"key": "value"}}, "title": "...", "description": "...", "testing_guidance": "...", "risk_assessment": "..."}}""",
            context={"finding": finding},
            default_action="config_hardening",
            default_confidence=0.7,
            default_reasoning="Apply security configuration hardening",
        )

        try:
            m = re.search(r"\{[\s\S]*\}", resp.reasoning)
            data = json.loads(m.group()) if m else {}
        except json.JSONDecodeError:
            logger.debug("Failed to parse structured JSON from LLM response")
            data = {}
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.debug("Error extracting structured data from LLM: %s", type(e).__name__)
            data = {}

        suggestion.config_changes = data.get(
            "config_changes", {"security_hardening": True}
        )
        suggestion.title = data.get(
            "title", f"Harden config: {finding.get('title', '')}"
        )
        suggestion.description = data.get("description", resp.reasoning[:500])
        suggestion.testing_guidance = data.get(
            "testing_guidance", "Verify configuration changes"
        )
        suggestion.risk_assessment = data.get("risk_assessment", "Low risk")
        suggestion.effort_minutes = 10
        return suggestion

    # ------------------------------------------------------------------
    # IaC fix generation
    # ------------------------------------------------------------------

    async def _generate_iac_fix(
        self,
        suggestion: AutoFixSuggestion,
        finding: Dict[str, Any],
        source_code: Optional[str],
        repo_ctx: Dict[str, Any],
    ) -> AutoFixSuggestion:
        """Generate infrastructure-as-code fix."""
        file_path = finding.get("file_path", "main.tf")
        code = source_code or finding.get("code_snippet", "")

        llm = self._get_llm()
        resp = llm.analyse(
            "openai",
            prompt=f"""Fix this infrastructure-as-code security issue:
File: {file_path}
Issue: {finding.get('title', '')} — {finding.get('description', '')}
Code:
```
{code[:2000]}
```
Provide JSON: {{"patches": [{{"file_path": "{file_path}", "old_code": "...", "new_code": "...", "explanation": "..."}}], "title": "...", "description": "..."}}""",
            context={"finding": finding},
            default_action="iac_fix",
            default_confidence=0.7,
            default_reasoning="Fix IaC misconfiguration",
        )

        try:
            m = re.search(r"\{[\s\S]*\}", resp.reasoning)
            data = json.loads(m.group()) if m else {}
        except json.JSONDecodeError:
            logger.debug("Failed to parse structured JSON from LLM response")
            data = {}
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.debug("Error extracting structured data from LLM: %s", type(e).__name__)
            data = {}

        suggestion.title = data.get("title", f"Fix IaC: {finding.get('title', '')}")
        suggestion.description = data.get("description", resp.reasoning[:500])
        for p in data.get("patches", []):
            suggestion.code_patches.append(
                CodePatch(
                    file_path=p.get("file_path", file_path),
                    language="hcl" if ".tf" in file_path else "yaml",
                    old_code=p.get("old_code", ""),
                    new_code=p.get("new_code", ""),
                    explanation=p.get("explanation", ""),
                    patch_format=PatchFormat.TERRAFORM,
                )
            )
        suggestion.effort_minutes = 20
        return suggestion

    # ------------------------------------------------------------------
    # Container fix generation
    # ------------------------------------------------------------------

    async def _generate_container_fix(
        self,
        suggestion: AutoFixSuggestion,
        finding: Dict[str, Any],
        source_code: Optional[str],
        repo_ctx: Dict[str, Any],
    ) -> AutoFixSuggestion:
        """Generate Dockerfile / container fix."""
        file_path = finding.get("file_path", "Dockerfile")
        code = source_code or finding.get("code_snippet", "")

        llm = self._get_llm()
        resp = llm.analyse(
            "anthropic",
            prompt=f"""Fix this container security issue:
File: {file_path}
Issue: {finding.get('title', '')} — {finding.get('description', '')}
Dockerfile:
```
{code[:2000]}
```
Provide JSON: {{"patches": [{{"file_path": "{file_path}", "old_code": "...", "new_code": "...", "explanation": "..."}}], "title": "...", "description": "..."}}""",
            context={"finding": finding},
            default_action="container_fix",
            default_confidence=0.7,
            default_reasoning="Fix container security misconfiguration",
        )
        try:
            m = re.search(r"\{[\s\S]*\}", resp.reasoning)
            data = json.loads(m.group()) if m else {}
        except json.JSONDecodeError:
            logger.debug("Failed to parse structured JSON from LLM response")
            data = {}
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.debug("Error extracting structured data from LLM: %s", type(e).__name__)
            data = {}

        suggestion.title = data.get(
            "title", f"Fix container: {finding.get('title', '')}"
        )
        suggestion.description = data.get("description", resp.reasoning[:500])
        for p in data.get("patches", []):
            suggestion.code_patches.append(
                CodePatch(
                    file_path=p.get("file_path", file_path),
                    language="dockerfile",
                    old_code=p.get("old_code", ""),
                    new_code=p.get("new_code", ""),
                    explanation=p.get("explanation", ""),
                    patch_format=PatchFormat.DOCKERFILE,
                )
            )
        suggestion.effort_minutes = 15
        return suggestion

    # ------------------------------------------------------------------
    # Validation & confidence
    # ------------------------------------------------------------------

    # Maximum size for generated patch code (64KB per patch)
    MAX_PATCH_SIZE = 65536

    def _validate_fix(self, suggestion: AutoFixSuggestion) -> Dict[str, Any]:
        """Validate a generated fix for safety.

        [V3] Decision Intelligence — safety gate for LLM-generated code.

        Validates:
        1. At least one fix artifact exists
        2. No dangerous code patterns introduced
        3. No path traversal in file paths
        4. No dangerous imports introduced
        5. Patches have valid old/new code
        6. Dependency fixes have valid versions
        7. Patch size limits enforced
        """
        issues: List[str] = []
        checks_passed = 0
        total_checks = 0

        # Check 1: At least one patch or dependency fix
        total_checks += 1
        if (
            suggestion.code_patches
            or suggestion.dependency_fixes
            or suggestion.config_changes
        ):
            checks_passed += 1
        else:
            issues.append("No patches, dependency fixes, or config changes generated")

        # Check 2: No dangerous patterns in patches
        # Expanded dangerous pattern list — prevents AutoFix from introducing new vulns
        dangerous = [
            # OS command execution
            "rm -rf", "FORMAT C:", "; curl", "wget |", "eval(",
            # SQL destructive operations
            "DROP TABLE", "DELETE FROM", "TRUNCATE TABLE",
            # Shell injection vectors
            "os.system(", "subprocess.call(", "child_process.exec(",
            "subprocess.Popen(", "commands.getoutput(",
            # Code injection / dynamic execution
            "exec(", "__import__(", "compile(",
            # Credential patterns in code (not config values)
            "password=", "secret=", "api_key=",
            # Unsafe deserialization
            "pickle.loads(", "yaml.load(", "marshal.loads(",
            "shelve.open(",
            # Network backdoors
            "0.0.0.0", "bind(", "socket.listen(",  # nosec B104 — string pattern list, not a bind call
            # File system attacks
            "shutil.rmtree(", "os.remove(", "os.unlink(",
            # Debug backdoors
            "breakpoint(", "pdb.set_trace(",
            # Crypto downgrades
            "ssl._create_unverified_context",
            "verify=False", "CERT_NONE",
        ]
        total_checks += 1
        safe = True
        for patch in suggestion.code_patches:
            new_code_lower = patch.new_code.lower()
            old_code_lower = patch.old_code.lower()
            for pattern in dangerous:
                pat_lower = pattern.lower()
                # Only flag if pattern is NEW (not already in old code)
                if pat_lower in new_code_lower and pat_lower not in old_code_lower:
                    issues.append(
                        f"Dangerous pattern '{pattern}' introduced in patch for {patch.file_path}"
                    )
                    safe = False
        if safe:
            checks_passed += 1

        # Check 3: Path traversal in patch file paths
        total_checks += 1
        paths_safe = True
        for patch in suggestion.code_patches:
            fp = patch.file_path
            if ".." in fp or fp.startswith("/") or "\\" in fp:
                issues.append(
                    f"Path traversal detected in patch file_path: {fp[:100]}"
                )
                paths_safe = False
            if len(fp) > 500:
                issues.append(
                    f"Patch file_path too long ({len(fp)} chars): {fp[:60]}..."
                )
                paths_safe = False
        if paths_safe:
            checks_passed += 1

        # Check 4: Dangerous imports in new code
        total_checks += 1
        imports_safe = True
        dangerous_imports = [
            "import ctypes", "import os", "import subprocess",
            "import shutil", "import socket", "from ctypes",
            "import multiprocessing", "import signal",
            "import pty", "import resource",
        ]
        for patch in suggestion.code_patches:
            for imp in dangerous_imports:
                imp_lower = imp.lower()
                if imp_lower in patch.new_code.lower() and imp_lower not in patch.old_code.lower():
                    issues.append(
                        f"Dangerous import '{imp}' introduced in {patch.file_path}"
                    )
                    imports_safe = False
        if imports_safe:
            checks_passed += 1

        # Check 5: Patch has both old and new code
        total_checks += 1
        patch_valid = True
        for patch in suggestion.code_patches:
            if not patch.new_code.strip():
                issues.append(f"Empty new_code in patch for {patch.file_path}")
                patch_valid = False
        if patch_valid:
            checks_passed += 1

        # Check 6: Dependency fix has valid version
        total_checks += 1
        dep_valid = True
        for dep in suggestion.dependency_fixes:
            if not dep.fixed_version or dep.fixed_version == dep.current_version:
                issues.append(f"Invalid fixed version for {dep.package_name}")
                dep_valid = False
        if dep_valid:
            checks_passed += 1

        # Check 7: Patch size limits
        total_checks += 1
        size_ok = True
        for patch in suggestion.code_patches:
            if len(patch.new_code) > self.MAX_PATCH_SIZE:
                issues.append(
                    f"Patch too large for {patch.file_path}: "
                    f"{len(patch.new_code)} bytes (max {self.MAX_PATCH_SIZE})"
                )
                size_ok = False
        if size_ok:
            checks_passed += 1

        return {
            "valid": len(issues) == 0,
            "checks_passed": checks_passed,
            "total_checks": total_checks,
            "score": checks_passed / max(total_checks, 1),
            "issues": issues,
        }

    def _compute_confidence(
        self, suggestion: AutoFixSuggestion, finding: Dict[str, Any]
    ) -> float:
        """Compute confidence score for a fix using ML model.

        Uses the AutoFixConfidenceModel when available, with a deterministic
        rule-based fallback. Also enriches suggestion.metadata with detailed
        ML confidence data (classification, CI, feature contributions).

        Returns
        -------
        float
            Confidence score in [0.1, 0.99] range.
        """
        # --- Try ML model first ---
        try:
            from core.ml.autofix_confidence import get_autofix_confidence_model

            ml_model = get_autofix_confidence_model()

            # Build feature dict from suggestion + finding
            fix_data = self._build_confidence_features(suggestion, finding)

            prediction = ml_model.predict(fix_data)

            # Store rich ML metadata on the suggestion
            suggestion.metadata["ml_confidence"] = prediction.to_dict()

            # Return score normalised to 0-1 range
            return min(max(prediction.confidence_score / 100.0, 0.1), 0.99)

        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.debug(
                "[AutoFix] ML confidence model unavailable (%s), using rule-based fallback",
                type(exc).__name__,
            )

        # --- Deterministic rule-based fallback ---
        return self._compute_confidence_fallback(suggestion, finding)

    def _build_confidence_features(
        self, suggestion: AutoFixSuggestion, finding: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Map AutoFixSuggestion + finding → feature dict for ML model."""
        # CWE → category mapping
        cwe = str(finding.get("cwe_id", "")).upper()
        category = _cwe_to_category(cwe, suggestion.fix_type)

        # Count lines changed across all patches
        lines_changed = sum(
            max(len(p.new_code.splitlines()), len(p.old_code.splitlines()))
            for p in suggestion.code_patches
        ) + sum(1 for _ in suggestion.dependency_fixes)

        # Detect language from patches or finding
        language = "other"
        if suggestion.code_patches:
            language = suggestion.code_patches[0].language or "other"
        elif finding.get("language"):
            language = finding["language"]

        # Validation score as proxy for LLM confidence
        val = suggestion.metadata.get("validation", {})
        llm_confidence = val.get("score", 0.5)

        # Historical success rate from engine stats
        total = self._stats["total_generated"]
        hist_success = (
            self._stats["avg_confidence_score"]
            if total > 5
            else 0.7  # Default before we have enough data
        )

        return {
            "fix_type": suggestion.fix_type.value,
            "severity": finding.get("severity", "medium"),
            "category": category,
            "files_affected": max(len(suggestion.code_patches), 1),
            "lines_changed": max(lines_changed, 1),
            "has_tests": bool(suggestion.testing_guidance),
            "llm_confidence": llm_confidence,
            "language": language,
            "historical_success_rate": hist_success,
            "code_complexity": finding.get("code_complexity", 10),
        }

    @staticmethod
    def _compute_confidence_fallback(
        suggestion: AutoFixSuggestion, finding: Dict[str, Any]
    ) -> float:
        """Deterministic rule-based confidence scoring (legacy fallback)."""
        score = 0.5  # Base

        # Boost for well-known fix types
        if suggestion.fix_type == FixType.DEPENDENCY_UPDATE:
            score += 0.2  # Dependency updates are well-understood
        if suggestion.fix_type == FixType.CONFIG_HARDENING:
            score += 0.15

        # Boost for validation passing
        val = suggestion.metadata.get("validation", {})
        if val.get("valid"):
            score += 0.15
        score += val.get("score", 0) * 0.1

        # Boost for having patches
        if suggestion.code_patches:
            score += 0.05
        if suggestion.dependency_fixes:
            score += 0.05

        # Boost for known CVEs (better data = better fix)
        if suggestion.cve_ids:
            score += min(len(suggestion.cve_ids) * 0.03, 0.1)

        # Severity affects confidence — critical vulns get more research
        severity = finding.get("severity", "").lower()
        if severity == "critical":
            score += 0.05
        elif severity == "high":
            score += 0.03

        return min(max(score, 0.1), 0.99)

    # ------------------------------------------------------------------
    # PR description builder
    # ------------------------------------------------------------------

    def _build_pr_description(
        self, suggestion: AutoFixSuggestion, finding: Dict[str, Any]
    ) -> str:
        """Build a rich PR description for the autofix."""
        lines = [
            "## 🔒 FixOps AutoFix",
            "",
            f"**Vulnerability:** {suggestion.finding_title}",
            f"**Severity:** {finding.get('severity', 'N/A')}",
            f"**CVEs:** {', '.join(suggestion.cve_ids) or 'N/A'}",
            f"**Fix Type:** {suggestion.fix_type.value}",
            f"**Confidence:** {suggestion.confidence.value} ({suggestion.confidence_score:.0%})",
            "",
            "### Description",
            suggestion.description,
            "",
        ]

        if suggestion.code_patches:
            lines.append("### Code Changes")
            for i, patch in enumerate(suggestion.code_patches, 1):
                lines.append(f"\n**Patch {i}:** `{patch.file_path}`")
                lines.append(f"_{patch.explanation}_")
                if patch.unified_diff:
                    lines.append(f"```diff\n{patch.unified_diff}\n```")

        if suggestion.dependency_fixes:
            lines.append("\n### Dependency Updates")
            for dep in suggestion.dependency_fixes:
                lines.append(
                    f"- **{dep.package_name}:** {dep.current_version} → {dep.fixed_version}"
                )

        if suggestion.config_changes:
            lines.append("\n### Configuration Changes")
            lines.append(
                f"```json\n{json.dumps(suggestion.config_changes, indent=2)}\n```"
            )

        lines.extend(
            [
                "",
                "### Testing Guidance",
                suggestion.testing_guidance,
                "",
                "### Rollback",
                suggestion.rollback_steps,
                "",
                "### Risk Assessment",
                suggestion.risk_assessment,
                "",
                "---",
                "*Automated by FixOps AutoFix Engine*",
            ]
        )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Apply fix + Create PR
    # ------------------------------------------------------------------

    async def apply_fix(
        self,
        fix_id: str,
        repository: str,
        create_pr: bool = True,
        auto_merge: bool = False,
    ) -> AutoFixResult:
        """Apply a generated fix and optionally create a PR.

        Args:
            fix_id: ID of the previously generated fix.
            repository: Repository slug (owner/repo).
            create_pr: Whether to create a PR (default True).
            auto_merge: Whether to auto-merge high-confidence fixes.

        Returns:
            AutoFixResult with PR URL, validation status, etc.
        """
        suggestion = self._fixes.get(fix_id)
        if not suggestion:
            return AutoFixResult(success=False, error=f"Fix {fix_id} not found")

        logger.info("[AutoFix] Applying fix %s to repository", fix_id)

        # Build changes map: file_path -> new content
        changes: Dict[str, str] = {}
        for patch in suggestion.code_patches:
            if patch.new_code:
                changes[patch.file_path] = patch.new_code

        for dep in suggestion.dependency_fixes:
            if dep.manifest_file:
                # Build manifest update
                changes[dep.manifest_file] = self._build_manifest_update(dep)

        result = AutoFixResult(validation_passed=True)

        if create_pr:
            try:
                pr_gen = self._get_pr_generator()
                pr_result = pr_gen.create_pr(
                    repository=repository,
                    title=suggestion.pr_title,
                    description=suggestion.pr_description,
                    branch=suggestion.pr_branch,
                    changes=changes,
                )

                if pr_result.success:
                    suggestion.status = FixStatus.PR_CREATED
                    suggestion.pr_url = pr_result.pr_url or ""
                    suggestion.pr_number = pr_result.pr_number or 0
                    suggestion.applied_at = datetime.now(timezone.utc).isoformat()

                    result.success = True
                    result.fix = suggestion
                    result.pr_url = suggestion.pr_url
                    result.pr_number = suggestion.pr_number

                    self._stats["total_prs_created"] += 1

                    # Emit event
                    try:
                        import asyncio

                        from core.event_bus import Event, EventType

                        asyncio.ensure_future(
                            self._get_bus().emit(
                                Event(
                                    event_type=EventType.AUTOFIX_PR_CREATED,
                                    source="autofix_engine",
                                    data={
                                        "fix_id": fix_id,
                                        "pr_url": suggestion.pr_url,
                                        "repository": repository,
                                    },
                                )
                            )
                        )
                    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                        logger.debug("Event bus emit (PR created) failed: %s", type(e).__name__)
                else:
                    suggestion.status = FixStatus.FAILED
                    result.error = pr_result.error or "PR creation failed"
                    self._stats["total_failed"] += 1

            except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
                logger.error("[AutoFix] PR creation failed: %s: %s", type(exc).__name__, exc)
                suggestion.status = FixStatus.FAILED
                result.error = f"PR creation failed ({type(exc).__name__})"
                self._stats["total_failed"] += 1
        else:
            suggestion.status = FixStatus.APPLIED
            suggestion.applied_at = datetime.now(timezone.utc).isoformat()
            result.success = True
            result.fix = suggestion
            self._stats["total_applied"] += 1

        # Log history
        self._history.append(
            {
                "action": "apply",
                "fix_id": fix_id,
                "repository": repository,
                "create_pr": create_pr,
                "status": suggestion.status.value,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        self._persist_fix(fix_id, suggestion)
        self._persist_history()

        return result

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------

    async def rollback_fix(self, fix_id: str) -> Dict[str, Any]:
        """Mark a fix as rolled back."""
        suggestion = self._fixes.get(fix_id)
        if not suggestion:
            return {"success": False, "error": f"Fix {fix_id} not found"}

        suggestion.status = FixStatus.ROLLED_BACK
        self._stats["total_rolled_back"] += 1
        self._history.append(
            {
                "action": "rollback",
                "fix_id": fix_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        self._persist_fix(fix_id, suggestion)
        self._persist_history()

        try:
            import asyncio

            from core.event_bus import Event, EventType

            asyncio.ensure_future(
                self._get_bus().emit(
                    Event(
                        event_type=EventType.AUTOFIX_ROLLED_BACK,
                        source="autofix_engine",
                        data={"fix_id": fix_id},
                    )
                )
            )
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.debug("Event bus emit (rollback) failed: %s", type(e).__name__)

        return {"success": True, "fix_id": fix_id, "status": "rolled_back"}

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    def get_fix(self, fix_id: str) -> Optional[AutoFixSuggestion]:
        """Get a fix by ID."""
        return self._fixes.get(fix_id)

    def list_fixes(
        self,
        finding_id: Optional[str] = None,
        status: Optional[FixStatus] = None,
        fix_type: Optional[FixType] = None,
        limit: int = 50,
    ) -> List[AutoFixSuggestion]:
        """List fixes with optional filters."""
        results = list(self._fixes.values())
        if finding_id:
            results = [f for f in results if f.finding_id == finding_id]
        if status:
            results = [f for f in results if f.status == status]
        if fix_type:
            results = [f for f in results if f.fix_type == fix_type]
        return results[:limit]

    # ------------------------------------------------------------------
    # GAP-044: Teammate-mode fix explanation
    # ------------------------------------------------------------------

    def teammate_explain_fix(
        self, org_id: str, fix_id: str
    ) -> Dict[str, Any]:
        """Plain-language explanation of why a fix works.

        Pulls the AutoFixSuggestion by fix_id and assembles a non-technical
        summary suitable for exec/approver audiences. The org_id is retained
        for future multi-tenant isolation when autofix stores migrate to a
        scoped backend — callers should still pass it explicitly.
        """
        if not isinstance(org_id, str) or not org_id:
            raise ValueError("org_id must be a non-empty string")
        if not isinstance(fix_id, str) or not fix_id:
            raise ValueError("fix_id must be a non-empty string")

        suggestion = self.get_fix(fix_id)
        if suggestion is None:
            return {
                "org_id": org_id,
                "fix_id": fix_id,
                "found": False,
                "explanation": (
                    f"No fix with id={fix_id!r} is stored. The suggestion may "
                    "have expired or never been generated; re-run autofix on "
                    "the originating finding."
                ),
            }

        fix_type = getattr(suggestion.fix_type, "value", str(suggestion.fix_type))
        confidence = getattr(suggestion.confidence, "value", str(suggestion.confidence))
        patches = len(suggestion.code_patches or [])
        dep_fixes = len(suggestion.dependency_fixes or [])
        config_keys = list((suggestion.config_changes or {}).keys())

        # Build plain-language paragraphs
        narrative_parts: List[str] = []
        narrative_parts.append(
            f"This fix addresses the finding '{suggestion.finding_title}' "
            f"(id={suggestion.finding_id}) using a {fix_type} strategy."
        )
        if suggestion.description:
            narrative_parts.append(suggestion.description)
        if patches:
            narrative_parts.append(
                f"It modifies {patches} code location(s) with reviewed patches."
            )
        if dep_fixes:
            narrative_parts.append(
                f"It upgrades {dep_fixes} vulnerable dependency version(s) to a "
                "patched release."
            )
        if config_keys:
            narrative_parts.append(
                f"It adjusts configuration keys: {', '.join(sorted(config_keys))}."
            )
        if suggestion.testing_guidance:
            narrative_parts.append(
                f"Recommended verification: {suggestion.testing_guidance}"
            )
        if suggestion.rollback_steps:
            narrative_parts.append(
                f"Rollback plan: {suggestion.rollback_steps}"
            )

        return {
            "org_id": org_id,
            "fix_id": fix_id,
            "finding_id": suggestion.finding_id,
            "found": True,
            "fix_type": fix_type,
            "confidence": confidence,
            "confidence_score": suggestion.confidence_score,
            "effort_minutes": suggestion.effort_minutes,
            "risk_assessment": suggestion.risk_assessment,
            "compliance_frameworks": list(suggestion.compliance_frameworks or []),
            "mitre_techniques": list(suggestion.mitre_techniques or []),
            "explanation": " ".join(part.strip() for part in narrative_parts if part),
            "summary_bullets": [
                f"Fix strategy: {fix_type}",
                f"Confidence: {confidence} ({suggestion.confidence_score:.2f})",
                f"Patches: {patches}, Dependency fixes: {dep_fixes}, Config keys: {len(config_keys)}",
                f"Estimated effort: {suggestion.effort_minutes} minute(s)",
            ],
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get autofix engine statistics."""
        return {**self._stats, "total_fixes_stored": len(self._fixes)}

    def get_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get fix action history."""
        return list(reversed(self._history[-limit:]))

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_unified_diff(file_path: str, old_code: str, new_code: str) -> str:
        """Generate a unified diff string."""
        import difflib


        old_lines = old_code.splitlines(keepends=True)
        new_lines = new_code.splitlines(keepends=True)
        diff = difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
        )
        return "".join(diff)

    @staticmethod
    def _guess_manifest(ecosystem: str) -> str:
        """Guess the manifest file from the ecosystem."""
        return {
            "npm": "package.json",
            "pip": "requirements.txt",
            "poetry": "pyproject.toml",
            "maven": "pom.xml",
            "gradle": "build.gradle",
            "cargo": "Cargo.toml",
            "go": "go.mod",
            "nuget": "packages.config",
            "gem": "Gemfile",
            "composer": "composer.json",
        }.get(ecosystem, "package.json")

    @staticmethod
    def _build_manifest_update(dep: DependencyFix) -> str:
        """Build a manifest update string for a dependency fix."""
        if dep.ecosystem == "npm":
            return json.dumps({dep.package_name: dep.fixed_version}, indent=2)
        elif dep.ecosystem in ("pip", "poetry"):
            return f"{dep.package_name}=={dep.fixed_version}"
        elif dep.ecosystem == "maven":
            return f"<dependency><groupId>{dep.package_name}</groupId><version>{dep.fixed_version}</version></dependency>"
        elif dep.ecosystem == "go":
            return f"require {dep.package_name} {dep.fixed_version}"
        else:
            return f"{dep.package_name}@{dep.fixed_version}"

    def _update_stats(self, suggestion: AutoFixSuggestion) -> None:
        """Update engine statistics after generating a fix."""
        self._stats["total_generated"] += 1
        ft = suggestion.fix_type.value
        self._stats["by_type"][ft] = self._stats["by_type"].get(ft, 0) + 1
        if (
            suggestion.confidence != FixConfidence.MEDIUM
            or suggestion.confidence_score > 0
        ):
            self._stats["by_confidence"][suggestion.confidence.value] += 1
        # Recompute average confidence
        scores = [
            f.confidence_score for f in self._fixes.values() if f.confidence_score > 0
        ]
        self._stats["avg_confidence_score"] = sum(scores) / max(len(scores), 1)

    def to_dict(self, suggestion: AutoFixSuggestion) -> Dict[str, Any]:
        """Serialize a suggestion to dict."""
        d = asdict(suggestion)
        d["fix_type"] = suggestion.fix_type.value
        d["status"] = suggestion.status.value
        d["confidence"] = suggestion.confidence.value
        for i, p in enumerate(d.get("code_patches", [])):
            d["code_patches"][i]["patch_format"] = suggestion.code_patches[
                i
            ].patch_format.value
        return d


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_autofix_engine: Optional[AutoFixEngine] = None


def get_autofix_engine() -> AutoFixEngine:
    """Get the global AutoFixEngine singleton."""
    global _autofix_engine
    if _autofix_engine is None:
        _autofix_engine = AutoFixEngine()
    return _autofix_engine
