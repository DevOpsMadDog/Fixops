"""Material Change Detector — classify git changes as COSMETIC, MATERIAL, or BREAKING.

Used by the brain pipeline (_enrich_material_change) and the Material Change
Detection API router to assess the risk impact of code changes before, during,
or after deployment.

Usage::

    from core.material_change_detector import MaterialChangeDetector

    detector = MaterialChangeDetector()
    analyses = detector.analyze_diff(diff_text)
    for a in analyses:
        print(a.file_path, a.classification, a.risk_delta)
"""

from __future__ import annotations

import logging
import re
import subprocess  # nosec B404
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:  # pragma: no cover - bus optional
    _get_tg_bus = None

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Enums & Models
# ---------------------------------------------------------------------------


class MaterialClassification(str, Enum):
    """Risk tier for a single file change."""

    COSMETIC = "COSMETIC"
    MATERIAL = "MATERIAL"
    BREAKING = "BREAKING"


class ChangeAnalysis(BaseModel):
    """Analysis result for a single changed file."""

    file_path: str = Field(..., description="Relative path of the changed file")
    classification: MaterialClassification = Field(
        ..., description="Risk tier of the change"
    )
    risk_delta: float = Field(
        ..., ge=0.0, le=1.0, description="Risk multiplier (0.0=none, 1.0=max)"
    )
    blast_radius: List[str] = Field(
        default_factory=list,
        description="Files that import/depend on the changed file",
    )
    reason: str = Field(..., description="Human-readable explanation of classification")


# ---------------------------------------------------------------------------
# Pattern constants
# ---------------------------------------------------------------------------

# File extensions / names that are always COSMETIC
_COSMETIC_EXTENSIONS: set = {
    ".md", ".txt", ".rst", ".csv", ".log",
}
_COSMETIC_NAMES: set = {
    "LICENSE", "LICENCE", "NOTICE", "AUTHORS", "CHANGELOG",
}

# Config/dependency files that are always MATERIAL
_MATERIAL_CONFIG_EXTENSIONS: set = {
    ".env", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg",
}
_MATERIAL_DEPENDENCY_FILES: set = {
    "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
    "package.json", "package-lock.json", "yarn.lock", "Pipfile",
    "Pipfile.lock", "pyproject.toml", "setup.py", "setup.cfg",
}

# Database migration file patterns
_MIGRATION_PATTERNS = [
    re.compile(r"migrations?/.*\.py$", re.IGNORECASE),
    re.compile(r"alembic/.*\.py$", re.IGNORECASE),
    re.compile(r"\d{4}.*migration.*\.py$", re.IGNORECASE),
    re.compile(r".*schema.*\.sql$", re.IGNORECASE),
]

# Lines that are purely cosmetic (comment or docstring opener)
_COMMENT_LINE_RE = re.compile(
    r'^\s*(#|//|/\*|\*|"""|\'\'\'|<!--)'
)

# Function/class definition line
_DEF_LINE_RE = re.compile(r"^(def |class |async def )")

# API route decorator
_ROUTE_DECORATOR_RE = re.compile(
    r"^@(?:app|router)\.(get|post|put|patch|delete|head|options|route)\s*\("
)

# Public name pattern (no leading underscore)
_PUBLIC_DEF_RE = re.compile(r"^(?:async\s+)?(?:def|class)\s+([A-Za-z][A-Za-z0-9_]*)")


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class MaterialChangeDetector:
    """Analyse git diffs and classify the risk tier of each changed file."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_commit(
        self, repo_path: str, commit_sha: str
    ) -> List[ChangeAnalysis]:
        """Return ChangeAnalysis objects for every file touched by *commit_sha*.

        Runs ``git show --unified=5 <sha>`` inside *repo_path*.

        Args:
            repo_path: Absolute path to the git repository root.
            commit_sha: Full or abbreviated commit SHA.

        Returns:
            List of ChangeAnalysis, one per changed file.
        """
        try:
            result = subprocess.run(
                ["git", "show", "--unified=5", commit_sha],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                logger.warning(
                    "git show failed for %s: %s", commit_sha, result.stderr.strip()
                )
                return []
            return self.analyze_diff(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.warning("analyze_commit error for %s: %s", commit_sha, exc)
            return []

    def analyze_diff(self, diff_text: str) -> List[ChangeAnalysis]:
        """Parse a unified diff and return ChangeAnalysis per file.

        Args:
            diff_text: Raw output of ``git diff`` or ``git show``.

        Returns:
            List of ChangeAnalysis, one per changed file.
        """
        if not diff_text or not diff_text.strip():
            return []

        file_diffs = self._split_diff_by_file(diff_text)
        results: List[ChangeAnalysis] = []

        for file_path, hunks in file_diffs:
            classification = self.classify_change(file_path, hunks)
            risk_delta = self.get_risk_multiplier(classification)
            reason = self._build_reason(file_path, hunks, classification)
            results.append(
                ChangeAnalysis(
                    file_path=file_path,
                    classification=classification,
                    risk_delta=risk_delta,
                    blast_radius=[],
                    reason=reason,
                )
            )

        if results:
            self._emit_event(
                "material_change.analyzed",
                {
                    "file_count": len(results),
                    "classifications": {
                        c.value: sum(1 for r in results if r.classification == c)
                        for c in {r.classification for r in results}
                    },
                    "max_risk_delta": max((r.risk_delta for r in results), default=0.0),
                },
            )
        return results

    def compute_blast_radius(
        self, file_path: str, repo_path: str
    ) -> List[str]:
        """Find all files in *repo_path* that import or depend on *file_path*.

        Args:
            file_path: Relative path of the changed file (e.g. ``core/brain.py``).
            repo_path: Absolute path to the repository root.

        Returns:
            Sorted list of relative file paths that import the changed module.
        """
        module_candidates = self._file_path_to_module_names(file_path)
        if not module_candidates:
            return []

        repo = Path(repo_path)
        affected: set = set()

        patterns: List[str] = []
        for mod in module_candidates:
            patterns.append(f"from {mod}")
            patterns.append(f"import {mod}")

        try:
            for py_file in repo.rglob("*.py"):
                try:
                    content = py_file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for pat in patterns:
                    if pat in content:
                        rel = str(py_file.relative_to(repo))
                        if rel != file_path:
                            affected.add(rel)
                        break
        except OSError as exc:
            logger.warning("compute_blast_radius scan error: %s", exc)

        return sorted(affected)

    def classify_change(
        self, file_path: str, diff_hunks: List[str]
    ) -> MaterialClassification:
        """Determine the MaterialClassification for one file's diff hunks.

        Rules are evaluated in priority order: BREAKING > MATERIAL > COSMETIC.

        Args:
            file_path: Relative path of the changed file.
            diff_hunks: List of hunk strings (lines prefixed with + or -).

        Returns:
            The highest applicable MaterialClassification.
        """
        # --- File-level MATERIAL rules (config/deps) — checked before COSMETIC
        # because requirements.txt has .txt extension but is NOT cosmetic.
        if self._is_config_or_dependency_file(file_path):
            return MaterialClassification.MATERIAL

        # --- File-level COSMETIC rules ---
        if self._is_cosmetic_file(file_path):
            return MaterialClassification.COSMETIC

        # --- File-level BREAKING rules (migrations) ---
        if self._is_migration_file(file_path):
            return MaterialClassification.BREAKING

        # --- New file (only additions) ---
        if self._is_new_file(diff_hunks):
            return MaterialClassification.MATERIAL

        # --- Hunk-level analysis ---
        added_lines, removed_lines = self._extract_changed_lines(diff_hunks)

        # BREAKING check (highest priority)
        if self._detect_breaking(file_path, added_lines, removed_lines):
            return MaterialClassification.BREAKING

        # COSMETIC-only check
        if self._all_lines_cosmetic(added_lines, removed_lines):
            return MaterialClassification.COSMETIC

        # Everything else is MATERIAL
        return MaterialClassification.MATERIAL

    def get_risk_multiplier(
        self, classification: MaterialClassification
    ) -> float:
        """Return the risk multiplier for a classification tier.

        Args:
            classification: A MaterialClassification enum value.

        Returns:
            0.0 for COSMETIC, 0.5 for MATERIAL, 1.0 for BREAKING.
        """
        _map: Dict[MaterialClassification, float] = {
            MaterialClassification.COSMETIC: 0.0,
            MaterialClassification.MATERIAL: 0.5,
            MaterialClassification.BREAKING: 1.0,
        }
        return _map.get(classification, 0.0)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _split_diff_by_file(
        self, diff_text: str
    ) -> List[Tuple[str, List[str]]]:
        """Split a unified diff into (file_path, hunk_lines) per file."""
        results: List[Tuple[str, List[str]]] = []
        current_file: Optional[str] = None
        current_hunks: List[str] = []

        for line in diff_text.splitlines():
            if line.startswith("diff --git "):
                if current_file is not None:
                    results.append((current_file, current_hunks))
                current_file = None
                current_hunks = []
            elif line.startswith("+++ b/"):
                current_file = line[6:].strip()
            elif line.startswith("+++ /dev/null"):
                # File deleted — use the --- line name
                pass
            elif line.startswith("--- b/"):
                pass  # ignore old-file header
            elif current_file is not None and (
                line.startswith("+") or line.startswith("-")
            ):
                # Skip the --- / +++ header lines
                if not (line.startswith("---") or line.startswith("+++")):
                    current_hunks.append(line)

        if current_file is not None:
            results.append((current_file, current_hunks))

        return results

    def _extract_changed_lines(
        self, diff_hunks: List[str]
    ) -> Tuple[List[str], List[str]]:
        """Return (added_lines, removed_lines) stripped of the +/- prefix."""
        added = [line[1:] for line in diff_hunks if line.startswith("+")]
        removed = [line[1:] for line in diff_hunks if line.startswith("-")]
        return added, removed

    def _is_cosmetic_file(self, file_path: str) -> bool:
        """True when the file is inherently documentation or plain text."""
        path = Path(file_path)
        return (
            path.suffix.lower() in _COSMETIC_EXTENSIONS
            or path.name.upper() in _COSMETIC_NAMES
        )

    def _is_config_or_dependency_file(self, file_path: str) -> bool:
        """True for config files and known dependency manifests."""
        path = Path(file_path)
        return (
            path.suffix.lower() in _MATERIAL_CONFIG_EXTENSIONS
            or path.name in _MATERIAL_DEPENDENCY_FILES
        )

    def _is_migration_file(self, file_path: str) -> bool:
        """True for database migration scripts."""
        for pattern in _MIGRATION_PATTERNS:
            if pattern.search(file_path):
                return True
        return False

    def _is_new_file(self, diff_hunks: List[str]) -> bool:
        """True when the diff only has additions (brand-new file)."""
        if not diff_hunks:
            return False
        return all(line.startswith("+") for line in diff_hunks)

    def _detect_breaking(
        self,
        file_path: str,
        added_lines: List[str],
        removed_lines: List[str],
    ) -> bool:
        """Return True if the diff contains BREAKING change indicators."""
        added_set = set(line.strip() for line in added_lines)

        # 1. Public function/class definition removed without a matching add
        for line in removed_lines:
            stripped = line.strip()
            m = _PUBLIC_DEF_RE.match(stripped)
            if m:
                name = m.group(1)
                # Check if the same name still appears in added defs
                still_present = any(
                    _PUBLIC_DEF_RE.match(a.strip()) and
                    _PUBLIC_DEF_RE.match(a.strip()).group(1) == name  # type: ignore[union-attr]
                    for a in added_lines
                )
                if not still_present:
                    return True

        # 2. Function signature changed (same name, different signature)
        removed_defs = [
            line.strip() for line in removed_lines
            if _DEF_LINE_RE.match(line.strip())
        ]
        added_defs = [
            line.strip() for line in added_lines
            if _DEF_LINE_RE.match(line.strip())
        ]
        for rdef in removed_defs:
            rname = self._extract_def_name(rdef)
            if rname:
                for adef in added_defs:
                    if self._extract_def_name(adef) == rname and adef != rdef:
                        return True

        # 3. API route decorator removed without a matching add
        removed_routes = [
            line.strip() for line in removed_lines
            if _ROUTE_DECORATOR_RE.match(line.strip())
        ]
        if removed_routes:
            for rr in removed_routes:
                if rr not in added_set:
                    return True

        # 4. __init__.py export removed
        if file_path.endswith("__init__.py"):
            for line in removed_lines:
                stripped = line.strip()
                if stripped.startswith("from ") or stripped.startswith("import "):
                    if stripped not in added_set:
                        return True

        return False

    def _all_lines_cosmetic(
        self,
        added_lines: List[str],
        removed_lines: List[str],
    ) -> bool:
        """True when every changed line is blank, a comment, or a docstring."""
        all_lines = added_lines + removed_lines
        if not all_lines:
            return True
        for line in all_lines:
            stripped = line.strip()
            if not stripped:
                continue
            if _COMMENT_LINE_RE.match(stripped):
                continue
            if stripped.startswith('"""') or stripped.startswith("'''"):
                continue
            return False
        return True

    def _extract_def_name(self, def_line: str) -> Optional[str]:
        """Extract function/class name from a def/class line."""
        m = re.match(r"(?:async\s+)?(?:def|class)\s+(\w+)", def_line)
        return m.group(1) if m else None

    def _file_path_to_module_names(self, file_path: str) -> List[str]:
        """Convert a file path to plausible Python module import strings."""
        path = Path(file_path)
        if path.suffix != ".py":
            return []

        parts = list(path.with_suffix("").parts)
        if not parts:
            return []

        candidates: List[str] = []
        # Full dotted path
        candidates.append(".".join(parts))
        # Sub-paths (drop leading directory components)
        for i in range(1, len(parts)):
            candidates.append(".".join(parts[i:]))

        # Normalise hyphens to underscores
        return [c.replace("-", "_") for c in candidates]

    def _build_reason(
        self,
        file_path: str,
        diff_hunks: List[str],
        classification: MaterialClassification,
    ) -> str:
        """Construct a human-readable reason string for the classification."""
        if classification == MaterialClassification.COSMETIC:
            if self._is_cosmetic_file(file_path):
                suffix = Path(file_path).suffix or Path(file_path).name
                return f"Documentation/text file: {suffix}"
            return "Only whitespace, comments, or docstring changes detected"

        if classification == MaterialClassification.MATERIAL:
            if self._is_config_or_dependency_file(file_path):
                return f"Configuration or dependency file changed: {Path(file_path).name}"
            if self._is_new_file(diff_hunks):
                return "New file added"
            return "Function body or logic changes detected (non-signature)"

        # BREAKING
        if self._is_migration_file(file_path):
            return f"Database migration file: {Path(file_path).name}"
        return (
            "Breaking change: public function/class deleted, "
            "signature changed, API route removed, or __init__.py export removed"
        )

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
# Push-event blast radius (CRITICAL / HIGH / MEDIUM / LOW)
# ---------------------------------------------------------------------------

import hashlib  # noqa: E402 — stdlib, already imported by CPython
import hmac as _hmac  # noqa: E402
import json as _json  # noqa: E402
import os as _os  # noqa: E402
import sqlite3 as _sqlite3  # noqa: E402
import uuid as _uuid  # noqa: E402
from dataclasses import dataclass as _dataclass  # noqa: E402
from dataclasses import field as _field
from datetime import datetime as _datetime  # noqa: E402
from datetime import timezone as _timezone
from enum import Enum as _Enum  # noqa: E402
from typing import Any as _Any  # noqa: E402
from typing import Dict as _Dict
from typing import List as _List
from typing import Optional as _Optional


class BlastRadiusCategory(str, _Enum):
    """Security blast-radius tier for a set of changed files."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# File path patterns → blast radius tier
_BR_CRITICAL = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"auth[_\-/]", r"[_\-/]auth\.", r"authentication", r"authorization",
        r"crypto[_\-/]", r"[_\-/]crypto\.", r"encrypt", r"decrypt",
        r"payment", r"billing", r"stripe",
        r"secret[_\-/]", r"[_\-/]secret\.", r"vault",
        r"key[_\-]manager", r"jwt", r"oauth", r"sso", r"saml", r"password",
    ]
]
_BR_HIGH = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"router\.py$", r"routes\.py$", r"_router\.py$",
        r"api[_\-/]", r"endpoint",
        r"model[_s]\.py$", r"db[_\-/]", r"database", r"migration",
        r"middleware", r"security", r"firewall", r"rbac", r"permission", r"access_matrix",
    ]
]
_BR_LOW = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"test[_\-/]", r"[_\-/]test\.", r"spec[_\-/]",
        r"\.md$", r"\.rst$", r"\.txt$",
        r"\.yml$", r"\.yaml$", r"\.json$", r"\.toml$", r"\.cfg$", r"\.ini$",
        r"Makefile", r"Dockerfile", r"docker-compose",
    ]
]
_BR_SECURITY_CRITICAL = _BR_CRITICAL + [
    re.compile(p, re.IGNORECASE)
    for p in [r"router\.py$", r"routes\.py$", r"_router\.py$", r"middleware", r"security", r"rbac"]
]


@_dataclass
class BlastRadius:
    """Blast radius for a push event's changed files."""

    category: BlastRadiusCategory
    changed_files: _List[str] = _field(default_factory=list)
    critical_files: _List[str] = _field(default_factory=list)
    high_files: _List[str] = _field(default_factory=list)
    medium_files: _List[str] = _field(default_factory=list)
    low_files: _List[str] = _field(default_factory=list)
    security_critical_ratio: float = 0.0

    def to_dict(self) -> _Dict[str, _Any]:
        return {
            "category": self.category.value,
            "changed_files_count": len(self.changed_files),
            "critical_files": self.critical_files,
            "high_files": self.high_files,
            "medium_files": self.medium_files,
            "low_files": self.low_files,
            "security_critical_ratio": round(self.security_critical_ratio, 3),
        }


@_dataclass
class MaterialChangeResult:
    """Full result of analyzing a GitHub push event."""

    id: str = _field(default_factory=lambda: str(_uuid.uuid4()))
    commit_sha: str = ""
    repository: str = ""
    branch: str = ""
    author: str = ""
    changed_files: _List[str] = _field(default_factory=list)
    blast_radius: _Optional[BlastRadius] = None
    sast_findings: _List[_Dict[str, _Any]] = _field(default_factory=list)
    is_material: bool = False
    materiality_reasons: _List[str] = _field(default_factory=list)
    council_verdict: _Optional[_Dict[str, _Any]] = None
    incident_id: _Optional[str] = None
    analyzed_at: str = _field(
        default_factory=lambda: _datetime.now(_timezone.utc).isoformat()
    )

    def to_dict(self) -> _Dict[str, _Any]:
        return {
            "id": self.id,
            "commit_sha": self.commit_sha,
            "repository": self.repository,
            "branch": self.branch,
            "author": self.author,
            "changed_files_count": len(self.changed_files),
            "blast_radius": self.blast_radius.to_dict() if self.blast_radius else None,
            "sast_findings_count": len(self.sast_findings),
            "sast_findings": self.sast_findings,
            "is_material": self.is_material,
            "materiality_reasons": self.materiality_reasons,
            "council_verdict": self.council_verdict,
            "incident_id": self.incident_id,
            "analyzed_at": self.analyzed_at,
        }


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

_MC_DB_PATH = Path(
    _os.environ.get("FIXOPS_DATA_DIR", "/tmp/fixops")  # nosec B108
) / "material_changes.db"


def _mc_get_db() -> _sqlite3.Connection:
    _MC_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = _sqlite3.connect(str(_MC_DB_PATH), check_same_thread=False)
    conn.row_factory = _sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS material_changes (
            id TEXT PRIMARY KEY,
            commit_sha TEXT,
            repository TEXT,
            branch TEXT,
            author TEXT,
            is_material INTEGER DEFAULT 0,
            data TEXT NOT NULL,
            analyzed_at TEXT
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_mc_at ON material_changes(analyzed_at DESC)"
    )
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# Regex SAST rules (tool, severity, title)
# ---------------------------------------------------------------------------

_SAST_RULES: _List[tuple] = [
    (re.compile(r"(password|secret|api_key|token)\s*=\s*['\"][^'\"]{4,}", re.I), "HIGH", "Hardcoded credential"),
    (re.compile(r"\beval\s*\(", re.I), "HIGH", "Use of eval()"),
    (re.compile(r"\bexec\s*\(", re.I), "MEDIUM", "Use of exec()"),
    (re.compile(r"subprocess\.call\(.*shell\s*=\s*True", re.I), "HIGH", "Shell injection risk"),
    (re.compile(r"pickle\.loads?\(", re.I), "HIGH", "Unsafe pickle deserialization"),
    (re.compile(r"yaml\.load\([^)]*\)", re.I), "MEDIUM", "Unsafe yaml.load()"),
    (re.compile(r"hashlib\.(md5|sha1)\(", re.I), "MEDIUM", "Weak hash algorithm"),
    (re.compile(r"(SSL_VERIFY|verify)\s*=\s*False", re.I), "HIGH", "TLS verification disabled"),
    (re.compile(r"\bDEBUG\s*=\s*True", re.I), "LOW", "Debug mode enabled"),
]


# ---------------------------------------------------------------------------
# PushEventAnalyzer — the new webhook-centric detector
# ---------------------------------------------------------------------------


class PushEventAnalyzer:
    """Analyze GitHub push webhook payloads for security-material changes.

    This class is the push-event-centric surface of MaterialChangeDetector.
    It exposes the interface specified by the task:

        analyzer = PushEventAnalyzer()
        result = analyzer.analyze_push_event(payload)

    The existing ``MaterialChangeDetector`` class (diff/commit analysis) is
    preserved unchanged so no existing callers break.
    """

    def __init__(
        self,
        repo_root: _Optional[str] = None,
        webhook_secret: _Optional[str] = None,
    ) -> None:
        self._repo_root = Path(repo_root) if repo_root else Path.cwd()
        self._webhook_secret = webhook_secret or _os.environ.get(
            "GITHUB_WEBHOOK_SECRET", ""
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_push_event(self, payload: dict) -> MaterialChangeResult:
        """Analyze a GitHub push webhook payload end-to-end."""
        result = MaterialChangeResult(
            commit_sha=payload.get("after", ""),
            repository=payload.get("repository", {}).get("full_name", ""),
            branch=payload.get("ref", "").replace("refs/heads/", ""),
            author=(
                payload.get("pusher", {}).get("name", "")
                or (payload.get("head_commit") or {}).get("author", {}).get("name", "")
            ),
        )

        # Collect all changed files across commits
        seen: set = set()
        changed: _List[str] = []
        for commit in payload.get("commits", []):
            for f in (
                commit.get("added", [])
                + commit.get("modified", [])
                + commit.get("removed", [])
            ):
                if f not in seen:
                    seen.add(f)
                    changed.append(f)
        result.changed_files = changed

        if not result.changed_files:
            logger.info(
                "material_change.no_files commit=%s repo=%s",
                result.commit_sha,
                result.repository,
            )
            self._persist(result)
            return result

        result.blast_radius = self._get_blast_radius(result.changed_files)
        result.sast_findings = self._run_sast_on_changes(
            result.changed_files, str(self._repo_root)
        )
        result.is_material, result.materiality_reasons = self._assess_materiality(
            result.sast_findings, result.blast_radius
        )
        result.council_verdict = self._ask_council(result)
        if result.council_verdict and result.council_verdict.get("is_material"):
            if not result.is_material:
                result.is_material = True
                result.materiality_reasons.append("llm_council_override")

        result.incident_id = self._create_incident_if_material(result)
        logger.info(
            "material_change.analyzed commit=%s repo=%s material=%s",
            result.commit_sha,
            result.repository,
            result.is_material,
        )
        self._persist(result)
        return result

    # ------------------------------------------------------------------
    # Blast radius
    # ------------------------------------------------------------------

    def _get_blast_radius(self, changed_files: _List[str]) -> BlastRadius:
        """Categorize changed files and compute overall blast radius."""
        critical: _List[str] = []
        high: _List[str] = []
        medium: _List[str] = []
        low: _List[str] = []
        security_critical: _List[str] = []

        for f in changed_files:
            if any(p.search(f) for p in _BR_CRITICAL):
                critical.append(f)
            elif any(p.search(f) for p in _BR_HIGH):
                high.append(f)
            elif any(p.search(f) for p in _BR_LOW):
                low.append(f)
            else:
                medium.append(f)

            if any(p.search(f) for p in _BR_SECURITY_CRITICAL):
                security_critical.append(f)

        ratio = len(security_critical) / len(changed_files) if changed_files else 0.0

        if critical:
            category = BlastRadiusCategory.CRITICAL
        elif high:
            category = BlastRadiusCategory.HIGH
        elif medium:
            category = BlastRadiusCategory.MEDIUM
        else:
            category = BlastRadiusCategory.LOW

        return BlastRadius(
            category=category,
            changed_files=changed_files,
            critical_files=critical,
            high_files=high,
            medium_files=medium,
            low_files=low,
            security_critical_ratio=ratio,
        )

    # ------------------------------------------------------------------
    # SAST
    # ------------------------------------------------------------------

    def _run_sast_on_changes(
        self, files: _List[str], repo_path: str
    ) -> _List[_Dict[str, _Any]]:
        """Run SAST on changed files: Bandit (if available) + regex heuristics."""
        findings: _List[_Dict[str, _Any]] = []
        py_files = [f for f in files if f.endswith(".py")]
        if py_files:
            findings.extend(self._run_bandit(py_files, repo_path))
        findings.extend(self._run_regex_sast(files, repo_path))
        return findings

    def _run_bandit(
        self, py_files: _List[str], repo_path: str
    ) -> _List[_Dict[str, _Any]]:
        """Run Bandit on Python files; return [] if unavailable."""
        import subprocess  # nosec B404

        abs_files = [
            str(Path(repo_path) / f)
            for f in py_files
            if (Path(repo_path) / f).is_file()
        ]
        if not abs_files:
            return []
        try:
            result = subprocess.run(
                ["bandit", "-f", "json", "-q", "--"] + abs_files,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode not in (0, 1):
                return []
            data = _json.loads(result.stdout or "{}")
            out: _List[_Dict[str, _Any]] = []
            for r in data.get("results", []):
                sev = r.get("issue_severity", "LOW").upper()
                if sev in ("HIGH", "CRITICAL", "MEDIUM"):
                    out.append({
                        "id": str(_uuid.uuid4()),
                        "tool": "bandit",
                        "severity": sev,
                        "title": r.get("issue_text", ""),
                        "file": r.get("filename", ""),
                        "line": r.get("line_number", 0),
                        "cwe": r.get("issue_cwe", {}).get("id", ""),
                    })
            return out
        except Exception as exc:  # noqa: BLE001
            logger.debug("material_change.bandit_unavailable: %s", exc)
            return []

    def _run_regex_sast(
        self, files: _List[str], repo_path: str
    ) -> _List[_Dict[str, _Any]]:
        """Regex SAST heuristics for all file types."""
        findings: _List[_Dict[str, _Any]] = []
        for rel_path in files:
            abs_path = Path(repo_path) / rel_path
            if not abs_path.is_file():
                continue
            try:
                content = abs_path.read_text(errors="replace")
            except OSError:
                continue
            for lineno, line in enumerate(content.splitlines(), start=1):
                for pattern, severity, title in _SAST_RULES:
                    if pattern.search(line):
                        findings.append({
                            "id": str(_uuid.uuid4()),
                            "tool": "regex_sast",
                            "severity": severity,
                            "title": title,
                            "file": rel_path,
                            "line": lineno,
                            "snippet": line.strip()[:120],
                        })
        return findings

    # ------------------------------------------------------------------
    # Materiality assessment
    # ------------------------------------------------------------------

    def _assess_materiality(
        self,
        sast_findings: _List[_Dict],
        blast_radius: BlastRadius,
    ) -> tuple:
        """Return (is_material: bool, reasons: List[str])."""
        reasons: _List[str] = []

        # Rule 1: blast radius tier
        if blast_radius.category in (BlastRadiusCategory.CRITICAL, BlastRadiusCategory.HIGH):
            reasons.append(f"blast_radius_{blast_radius.category.value.lower()}")

        # Rule 2: SAST high/critical findings
        high_crit = [
            f for f in sast_findings
            if f.get("severity", "").upper() in ("HIGH", "CRITICAL")
        ]
        if high_crit:
            reasons.append(f"sast_{len(high_crit)}_high_or_critical_findings")

        # Rule 3: ≥20% security-critical file ratio
        if blast_radius.security_critical_ratio >= 0.20:
            reasons.append(
                f"security_critical_ratio_{blast_radius.security_critical_ratio:.0%}"
            )

        return bool(reasons), reasons

    # ------------------------------------------------------------------
    # LLM Council
    # ------------------------------------------------------------------

    def _ask_council(
        self, result: MaterialChangeResult
    ) -> _Optional[_Dict[str, _Any]]:
        """Ask LLM Council whether this change is material. Returns None if unavailable."""
        try:
            from core.council_pipeline_adapter import (
                create_consensus_engine_replacement,
            )

            adapter = create_consensus_engine_replacement()
            br_cat = result.blast_radius.category.value if result.blast_radius else "UNKNOWN"
            prompt = (
                f"A developer pushed {len(result.changed_files)} files to "
                f"{result.repository} ({result.branch} branch), commit {result.commit_sha}. "
                f"Blast radius: {br_cat}. "
                f"SAST findings: {len(result.sast_findings)} total, "
                f"{sum(1 for f in result.sast_findings if f.get('severity','').upper() in ('HIGH','CRITICAL'))} HIGH/CRITICAL. "
                "Is this change 'material' from a security perspective? "
                'Respond with JSON: {"is_material": true/false, "confidence": 0.0-1.0, "reasoning": "..."}.'
            )
            council_result = adapter.analyse(
                prompt=prompt, context={"source": "material_change_detector"}
            )
            raw = getattr(council_result, "reasoning", "") or str(council_result)
            match = re.search(r'\{[^}]*"is_material"[^}]*\}', raw, re.DOTALL)
            if match:
                return _json.loads(match.group())
            decision = getattr(council_result, "final_decision", "") or ""
            return {
                "is_material": "block" in decision or "remediate" in decision,
                "confidence": getattr(council_result, "confidence", 0.5),
                "reasoning": raw[:500],
            }
        except Exception as exc:  # noqa: BLE001
            logger.debug("material_change.council_unavailable: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Incident creation
    # ------------------------------------------------------------------

    def _create_incident_if_material(
        self, result: MaterialChangeResult
    ) -> _Optional[str]:
        """Open an incident when the change is material. Returns incident ID or None."""
        if not result.is_material:
            return None
        try:
            from core.incident_response import (
                IncidentResponseManager,
                IncidentSeverity,
                IncidentType,
            )

            store = IncidentResponseManager()
            br_cat = result.blast_radius.category if result.blast_radius else BlastRadiusCategory.MEDIUM
            severity_map = {
                BlastRadiusCategory.CRITICAL: IncidentSeverity.SEV1,
                BlastRadiusCategory.HIGH: IncidentSeverity.SEV2,
                BlastRadiusCategory.MEDIUM: IncidentSeverity.SEV3,
                BlastRadiusCategory.LOW: IncidentSeverity.SEV4,
            }
            severity = severity_map.get(br_cat, IncidentSeverity.SEV2)
            title = (
                f"Material change detected: {result.commit_sha[:8]} "
                f"on {result.repository}/{result.branch}"
            )
            incident = store.create_incident(
                title=title,
                type=IncidentType.SUPPLY_CHAIN,
                severity=severity,
                reported_by="material_change_detector",
                org_id="default",
            )
            logger.info(
                "material_change.incident_created id=%s commit=%s",
                incident.id,
                result.commit_sha,
            )
            return incident.id
        except Exception as exc:  # noqa: BLE001
            logger.warning("material_change.incident_creation_failed: %s", exc)
            return None

    # ------------------------------------------------------------------
    # HMAC webhook verification
    # ------------------------------------------------------------------

    def verify_webhook_signature(
        self, payload_bytes: bytes, signature_header: str
    ) -> bool:
        """Verify GitHub HMAC-SHA256 webhook signature.

        Returns True if valid (or no secret configured — dev mode).
        """
        if not self._webhook_secret:
            return True
        if not signature_header.startswith("sha256="):
            return False
        expected = _hmac.new(
            self._webhook_secret.encode(),
            payload_bytes,
            hashlib.sha256,
        ).hexdigest()
        provided = signature_header[len("sha256="):]
        return _hmac.compare_digest(expected, provided)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _persist(self, result: MaterialChangeResult) -> None:
        try:
            conn = _mc_get_db()
            conn.execute(
                """INSERT OR REPLACE INTO material_changes
                       (id, commit_sha, repository, branch, author, is_material, data, analyzed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    result.id,
                    result.commit_sha,
                    result.repository,
                    result.branch,
                    result.author,
                    1 if result.is_material else 0,
                    _json.dumps(result.to_dict()),
                    result.analyzed_at,
                ),
            )
            conn.commit()
            conn.close()
        except Exception as exc:  # noqa: BLE001
            logger.warning("material_change.persist_failed: %s", exc)

    def list_recent(self, limit: int = 50) -> _List[_Dict[str, _Any]]:
        """Return recent analyses, newest first."""
        try:
            conn = _mc_get_db()
            rows = conn.execute(
                "SELECT data FROM material_changes ORDER BY analyzed_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            conn.close()
            return [_json.loads(r["data"]) for r in rows]
        except Exception as exc:  # noqa: BLE001
            logger.warning("material_change.list_failed: %s", exc)
            return []

    def get_by_id(self, change_id: str) -> _Optional[_Dict[str, _Any]]:
        """Fetch a specific analysis by ID."""
        try:
            conn = _mc_get_db()
            row = conn.execute(
                "SELECT data FROM material_changes WHERE id = ?", (change_id,)
            ).fetchone()
            conn.close()
            return _json.loads(row["data"]) if row else None
        except Exception as exc:  # noqa: BLE001
            logger.warning("material_change.get_failed: %s", exc)
            return None
