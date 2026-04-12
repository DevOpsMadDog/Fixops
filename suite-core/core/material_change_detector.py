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
import subprocess
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

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
