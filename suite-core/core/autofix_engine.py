"""
FixOps AutoFix Engine — AI-powered vulnerability remediation.

Generates precise code patches, dependency updates, configuration hardening,
and IaC fixes using LLM analysis. Integrates with PRGenerator for automated
pull request creation and with the Knowledge Graph for context enrichment.

Competitive parity with Aikido AutoFix and Snyk Fix.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)


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
    HIGH = "high"        # >85% — safe to auto-apply
    MEDIUM = "medium"    # 60-85% — needs review
    LOW = "low"          # <60% — manual review required


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
    ecosystem: str = ""          # npm, pip, maven, gradle, cargo, go
    current_version: str = ""
    fixed_version: str = ""
    cve_ids: List[str] = field(default_factory=list)
    breaking_changes: List[str] = field(default_factory=list)
    manifest_file: str = ""      # package.json, requirements.txt, etc.


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

    def __init__(self) -> None:
        self._fixes: Dict[str, AutoFixSuggestion] = {}
        self._history: List[Dict[str, Any]] = []
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
        finding_title = finding.get("title", finding.get("name", "Unknown Vulnerability"))
        cwe_id = finding.get("cwe_id", "")
        severity = finding.get("severity", "medium").lower()
        cve_ids = finding.get("cve_ids", [])

        # Determine fix type from the finding
        fix_type = self._infer_fix_type(finding)
        fix_id = self._make_fix_id(finding_id, fix_type)

        logger.info(f"[AutoFix] Generating {fix_type.value} fix for {finding_id} ({finding_title})")

        # Enrich context from Knowledge Graph
        graph_context = self._enrich_from_graph(finding_id, cve_ids)

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
                suggestion = await self._generate_dependency_fix(suggestion, finding, repo_context or {})
            elif fix_type == FixType.CONFIG_HARDENING:
                suggestion = await self._generate_config_fix(suggestion, finding, repo_context or {})
            elif fix_type == FixType.IAC_FIX:
                suggestion = await self._generate_iac_fix(suggestion, finding, source_code, repo_context or {})
            elif fix_type == FixType.CONTAINER_FIX:
                suggestion = await self._generate_container_fix(suggestion, finding, source_code, repo_context or {})
            else:
                suggestion = await self._generate_code_patch(
                    suggestion, finding, source_code, repo_context or {}, graph_context
                )

            # Validate the generated fix
            validation = self._validate_fix(suggestion)
            suggestion.metadata["validation"] = validation

            # Assign confidence
            suggestion.confidence_score = self._compute_confidence(suggestion, finding)
            if suggestion.confidence_score >= 0.85:
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

        except Exception as exc:
            logger.error(f"[AutoFix] Generation failed for {finding_id}: {exc}")
            suggestion.status = FixStatus.FAILED
            suggestion.metadata["error"] = str(exc)

        # Store and track
        self._fixes[fix_id] = suggestion
        self._update_stats(suggestion)
        self._history.append({
            "action": "generate", "fix_id": fix_id,
            "finding_id": finding_id, "fix_type": fix_type.value,
            "status": suggestion.status.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Emit event
        try:
            from core.event_bus import EventType, Event
            import asyncio
            asyncio.ensure_future(self._get_bus().emit(Event(
                event_type=EventType.AUTOFIX_GENERATED,
                source="autofix_engine",
                data={"fix_id": fix_id, "finding_id": finding_id, "fix_type": fix_type.value},
            )))
        except Exception:
            pass

        return suggestion

    # ------------------------------------------------------------------
    # Fix type inference
    # ------------------------------------------------------------------

    @staticmethod
    def _infer_fix_type(finding: Dict[str, Any]) -> FixType:
        """Infer the best fix type from the finding metadata."""
        title = (finding.get("title", "") + " " + finding.get("description", "")).lower()
        category = finding.get("category", "").lower()
        file_path = finding.get("file_path", "").lower()

        # Dependency-related
        if any(kw in title for kw in ("outdated", "dependency", "package", "library", "component")):
            return FixType.DEPENDENCY_UPDATE
        if finding.get("cve_ids") and "dependency" in category:
            return FixType.DEPENDENCY_UPDATE

        # IaC
        if any(kw in file_path for kw in (".tf", "terraform", "cloudformation", ".yaml", "helm")):
            if any(kw in title for kw in ("misconfigur", "iac", "infrastructure", "cloud")):
                return FixType.IAC_FIX

        # Container
        if any(kw in file_path for kw in ("dockerfile", "docker-compose", "containerfile")):
            return FixType.CONTAINER_FIX
        if "container" in title or "docker" in title:
            return FixType.CONTAINER_FIX

        # Configuration
        if any(kw in title for kw in ("config", "header", "cors", "tls", "ssl", "hsts", "csp")):
            return FixType.CONFIG_HARDENING

        # Secret
        if any(kw in title for kw in ("secret", "credential", "api key", "password", "token leak")):
            return FixType.SECRET_ROTATION

        # Permission
        if any(kw in title for kw in ("permission", "privilege", "authorization", "rbac", "iam")):
            return FixType.PERMISSION_FIX

        # Input validation
        if any(kw in title for kw in ("injection", "sqli", "xss", "command injection", "input")):
            return FixType.INPUT_VALIDATION

        # Output encoding
        if any(kw in title for kw in ("xss", "cross-site scripting", "output encoding", "html inject")):
            return FixType.OUTPUT_ENCODING

        # WAF
        if "waf" in title or "firewall" in title:
            return FixType.WAF_RULE

        return FixType.CODE_PATCH

    # ------------------------------------------------------------------
    # Knowledge Graph enrichment
    # ------------------------------------------------------------------

    def _enrich_from_graph(self, finding_id: str, cve_ids: List[str]) -> Dict[str, Any]:
        """Pull extra context from the Knowledge Graph."""
        ctx: Dict[str, Any] = {"related_cves": [], "affected_assets": [], "prior_fixes": []}
        try:
            brain = self._get_brain()
            # Get finding node and neighbors
            node = brain.get_node(finding_id)
            if node:
                neighbors = brain.get_neighbors(finding_id, depth=2)
                ctx["neighbors"] = [n.get("id", "") for n in neighbors.nodes[:20]]

            # Resolve CVEs
            for cve in cve_ids[:5]:
                cve_node = brain.get_node(cve)
                if cve_node:
                    ctx["related_cves"].append(cve_node)
        except Exception as exc:
            logger.debug(f"[AutoFix] Graph enrichment skipped: {exc}")
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
        """Use LLM to generate a precise code patch in unified-diff format."""
        language = repo_ctx.get("language", finding.get("language", "python"))
        framework = repo_ctx.get("framework", "")
        file_path = finding.get("file_path", "unknown")

        code_snippet = source_code or finding.get("code_snippet", "# no source provided")

        prompt = f"""You are a senior security engineer. Generate a precise code fix for this vulnerability.

VULNERABILITY:
- Title: {finding.get('title', '')}
- CWE: {finding.get('cwe_id', 'N/A')}
- CVE: {', '.join(finding.get('cve_ids', [])) or 'N/A'}
- Severity: {finding.get('severity', 'medium')}
- Description: {finding.get('description', '')}
- File: {file_path}
- Language: {language}
- Framework: {framework}

SOURCE CODE:
```{language}
{code_snippet[:3000]}
```

Generate a JSON response with:
{{
  "title": "Brief fix title",
  "description": "Detailed description of what the fix does",
  "patches": [
    {{
      "file_path": "{file_path}",
      "old_code": "exact vulnerable code lines",
      "new_code": "fixed code lines",
      "explanation": "why this fixes the vulnerability"
    }}
  ],
  "testing_guidance": "How to verify the fix works",
  "rollback_steps": "How to revert if needed",
  "risk_assessment": "Risk of applying this fix",
  "effort_minutes": 15,
  "mitre_techniques": ["T1190"],
  "compliance": ["CWE-79", "OWASP A03"]
}}

Provide ONLY valid JSON. The fix must be precise, minimal, and production-ready."""

        llm = self._get_llm()
        response = llm.analyse(
            "openai",
            prompt=prompt,
            context={"finding": finding, "graph": graph_ctx},
            default_action="code_patch",
            default_confidence=0.7,
            default_reasoning="Generated code patch for vulnerability fix",
        )

        # Parse LLM response
        try:
            raw = response.reasoning
            # Try to extract JSON from the response
            json_match = re.search(r'\{[\s\S]*\}', raw)
            if json_match:
                data = json.loads(json_match.group())
            else:
                data = json.loads(raw)

            suggestion.title = data.get("title", f"Fix {finding.get('title', 'vulnerability')}")
            suggestion.description = data.get("description", response.reasoning[:500])
            suggestion.testing_guidance = data.get("testing_guidance", "Run security tests to verify fix")
            suggestion.rollback_steps = data.get("rollback_steps", "Revert the commit")
            suggestion.risk_assessment = data.get("risk_assessment", "Low risk — minimal code change")
            suggestion.effort_minutes = data.get("effort_minutes", 15)
            suggestion.mitre_techniques = data.get("mitre_techniques", list(response.mitre_techniques))
            suggestion.compliance_frameworks = data.get("compliance", list(response.compliance_concerns))

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
            logger.warning(f"[AutoFix] LLM response parse failed, using fallback: {exc}")
            suggestion.title = f"Fix {finding.get('title', 'vulnerability')}"
            suggestion.description = response.reasoning[:500]
            suggestion.testing_guidance = "Manual review required — LLM parse failed"
            suggestion.confidence_score = 0.4

        return suggestion

    # ------------------------------------------------------------------
    # Dependency fix generation
    # ------------------------------------------------------------------

    async def _generate_dependency_fix(
        self, suggestion: AutoFixSuggestion, finding: Dict[str, Any], repo_ctx: Dict[str, Any],
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
        suggestion.testing_guidance = f"Run tests after updating {pkg}. Check for breaking changes."
        suggestion.rollback_steps = f"Revert {manifest} to {pkg}@{current}"
        suggestion.risk_assessment = "Medium — dependency updates may introduce breaking changes"
        suggestion.effort_minutes = 10
        return suggestion

    # ------------------------------------------------------------------
    # Config hardening fix
    # ------------------------------------------------------------------

    async def _generate_config_fix(
        self, suggestion: AutoFixSuggestion, finding: Dict[str, Any], repo_ctx: Dict[str, Any],
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
            m = re.search(r'\{[\s\S]*\}', resp.reasoning)
            data = json.loads(m.group()) if m else {}
        except Exception:
            data = {}

        suggestion.config_changes = data.get("config_changes", {"security_hardening": True})
        suggestion.title = data.get("title", f"Harden config: {finding.get('title', '')}")
        suggestion.description = data.get("description", resp.reasoning[:500])
        suggestion.testing_guidance = data.get("testing_guidance", "Verify configuration changes")
        suggestion.risk_assessment = data.get("risk_assessment", "Low risk")
        suggestion.effort_minutes = 10
        return suggestion

    # ------------------------------------------------------------------
    # IaC fix generation
    # ------------------------------------------------------------------

    async def _generate_iac_fix(
        self, suggestion: AutoFixSuggestion, finding: Dict[str, Any],
        source_code: Optional[str], repo_ctx: Dict[str, Any],
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
            m = re.search(r'\{[\s\S]*\}', resp.reasoning)
            data = json.loads(m.group()) if m else {}
        except Exception:
            data = {}

        suggestion.title = data.get("title", f"Fix IaC: {finding.get('title', '')}")
        suggestion.description = data.get("description", resp.reasoning[:500])
        for p in data.get("patches", []):
            suggestion.code_patches.append(CodePatch(
                file_path=p.get("file_path", file_path),
                language="hcl" if ".tf" in file_path else "yaml",
                old_code=p.get("old_code", ""), new_code=p.get("new_code", ""),
                explanation=p.get("explanation", ""), patch_format=PatchFormat.TERRAFORM,
            ))
        suggestion.effort_minutes = 20
        return suggestion

    # ------------------------------------------------------------------
    # Container fix generation
    # ------------------------------------------------------------------

    async def _generate_container_fix(
        self, suggestion: AutoFixSuggestion, finding: Dict[str, Any],
        source_code: Optional[str], repo_ctx: Dict[str, Any],
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
            m = re.search(r'\{[\s\S]*\}', resp.reasoning)
            data = json.loads(m.group()) if m else {}
        except Exception:
            data = {}

        suggestion.title = data.get("title", f"Fix container: {finding.get('title', '')}")
        suggestion.description = data.get("description", resp.reasoning[:500])
        for p in data.get("patches", []):
            suggestion.code_patches.append(CodePatch(
                file_path=p.get("file_path", file_path), language="dockerfile",
                old_code=p.get("old_code", ""), new_code=p.get("new_code", ""),
                explanation=p.get("explanation", ""), patch_format=PatchFormat.DOCKERFILE,
            ))
        suggestion.effort_minutes = 15
        return suggestion

    # ------------------------------------------------------------------
    # Validation & confidence
    # ------------------------------------------------------------------

    def _validate_fix(self, suggestion: AutoFixSuggestion) -> Dict[str, Any]:
        """Validate a generated fix for safety."""
        issues: List[str] = []
        checks_passed = 0
        total_checks = 0

        # Check 1: At least one patch or dependency fix
        total_checks += 1
        if suggestion.code_patches or suggestion.dependency_fixes or suggestion.config_changes:
            checks_passed += 1
        else:
            issues.append("No patches, dependency fixes, or config changes generated")

        # Check 2: No dangerous patterns in patches
        dangerous = ["rm -rf", "DROP TABLE", "DELETE FROM", "FORMAT C:", "; curl", "wget |", "eval("]
        total_checks += 1
        safe = True
        for patch in suggestion.code_patches:
            for pattern in dangerous:
                if pattern.lower() in patch.new_code.lower():
                    issues.append(f"Dangerous pattern '{pattern}' in patch for {patch.file_path}")
                    safe = False
        if safe:
            checks_passed += 1

        # Check 3: Patch has both old and new code
        total_checks += 1
        patch_valid = True
        for patch in suggestion.code_patches:
            if not patch.new_code.strip():
                issues.append(f"Empty new_code in patch for {patch.file_path}")
                patch_valid = False
        if patch_valid:
            checks_passed += 1

        # Check 4: Dependency fix has valid version
        total_checks += 1
        dep_valid = True
        for dep in suggestion.dependency_fixes:
            if not dep.fixed_version or dep.fixed_version == dep.current_version:
                issues.append(f"Invalid fixed version for {dep.package_name}")
                dep_valid = False
        if dep_valid:
            checks_passed += 1

        return {
            "valid": len(issues) == 0,
            "checks_passed": checks_passed,
            "total_checks": total_checks,
            "score": checks_passed / max(total_checks, 1),
            "issues": issues,
        }

    def _compute_confidence(self, suggestion: AutoFixSuggestion, finding: Dict[str, Any]) -> float:
        """Compute confidence score for a fix."""
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

    def _build_pr_description(self, suggestion: AutoFixSuggestion, finding: Dict[str, Any]) -> str:
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
                lines.append(f"- **{dep.package_name}:** {dep.current_version} → {dep.fixed_version}")

        if suggestion.config_changes:
            lines.append("\n### Configuration Changes")
            lines.append(f"```json\n{json.dumps(suggestion.config_changes, indent=2)}\n```")

        lines.extend([
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
        ])
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

        logger.info(f"[AutoFix] Applying fix {fix_id} to {repository}")

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
                        from core.event_bus import EventType, Event
                        import asyncio
                        asyncio.ensure_future(self._get_bus().emit(Event(
                            event_type=EventType.AUTOFIX_PR_CREATED,
                            source="autofix_engine",
                            data={"fix_id": fix_id, "pr_url": suggestion.pr_url, "repository": repository},
                        )))
                    except Exception:
                        pass
                else:
                    suggestion.status = FixStatus.FAILED
                    result.error = pr_result.error or "PR creation failed"
                    self._stats["total_failed"] += 1

            except Exception as exc:
                logger.error(f"[AutoFix] PR creation failed: {exc}")
                suggestion.status = FixStatus.FAILED
                result.error = str(exc)
                self._stats["total_failed"] += 1
        else:
            suggestion.status = FixStatus.APPLIED
            suggestion.applied_at = datetime.now(timezone.utc).isoformat()
            result.success = True
            result.fix = suggestion
            self._stats["total_applied"] += 1

        # Log history
        self._history.append({
            "action": "apply",
            "fix_id": fix_id,
            "repository": repository,
            "create_pr": create_pr,
            "status": suggestion.status.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

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
        self._history.append({
            "action": "rollback", "fix_id": fix_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        try:
            from core.event_bus import EventType, Event
            import asyncio
            asyncio.ensure_future(self._get_bus().emit(Event(
                event_type=EventType.AUTOFIX_ROLLED_BACK,
                source="autofix_engine",
                data={"fix_id": fix_id},
            )))
        except Exception:
            pass

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
            old_lines, new_lines,
            fromfile=f"a/{file_path}", tofile=f"b/{file_path}",
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
        if suggestion.confidence != FixConfidence.MEDIUM or suggestion.confidence_score > 0:
            self._stats["by_confidence"][suggestion.confidence.value] += 1
        # Recompute average confidence
        scores = [f.confidence_score for f in self._fixes.values() if f.confidence_score > 0]
        self._stats["avg_confidence_score"] = sum(scores) / max(len(scores), 1)

    def to_dict(self, suggestion: AutoFixSuggestion) -> Dict[str, Any]:
        """Serialize a suggestion to dict."""
        d = asdict(suggestion)
        d["fix_type"] = suggestion.fix_type.value
        d["status"] = suggestion.status.value
        d["confidence"] = suggestion.confidence.value
        for i, p in enumerate(d.get("code_patches", [])):
            d["code_patches"][i]["patch_format"] = suggestion.code_patches[i].patch_format.value
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