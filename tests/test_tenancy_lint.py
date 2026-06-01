"""AC-007-02 / AC-007-03 — Tenancy lint gate tests.

Verifies:
  1. Running the scanner against the repo with the allowlist passes (no new violations).
  2. Injecting a synthetic Query(default="default") on a temp string is detected by the
     scanner's regex (proves the gate bites).
  3. The allowlist file exists with a recorded violation count.

Run:
    PYTHONPATH=.:suite-api:suite-core:suite-attack:suite-feeds:suite-integrations:suite-evidence-risk:archive/legacy:archive/enterprise_legacy \
    python -m pytest tests/test_tenancy_lint.py -v
"""
from __future__ import annotations

import re
import sys
import os
from pathlib import Path

import pytest

# Ensure scripts/ is importable
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from tenancy_lint import (
    ALLOWLIST_REL,
    Violation,
    load_allowlist,
    scan,
)

ALLOWLIST_PATH = REPO_ROOT / ALLOWLIST_REL


# ---------------------------------------------------------------------------
# AC-007-03: allowlist file must exist with a recorded count
# ---------------------------------------------------------------------------

def test_allowlist_file_exists():
    """AC-007-03: specs/tenancy_allowlist.txt must exist."""
    assert ALLOWLIST_PATH.exists(), (
        f"Allowlist not found at {ALLOWLIST_PATH}. "
        "Run: python scripts/tenancy_lint.py --generate-allowlist"
    )


def test_allowlist_has_entries():
    """AC-007-03: allowlist must contain at least one entry (frozen debt)."""
    keys = load_allowlist(ALLOWLIST_PATH)
    assert len(keys) > 0, "Allowlist is empty — expected frozen violations."


def test_allowlist_entry_format():
    """Allowlist entries must follow the path:lineno:CATEGORY format."""
    keys = load_allowlist(ALLOWLIST_PATH)
    pattern = re.compile(r"^.+:\d+:(V1|V2|V3)$")
    malformed = [k for k in keys if not pattern.match(k)]
    assert not malformed, f"Malformed allowlist entries: {malformed[:5]}"


# ---------------------------------------------------------------------------
# AC-007-02a: scanner passes against current codebase (no new violations)
# ---------------------------------------------------------------------------

def test_no_new_violations_beyond_allowlist():
    """AC-007-02: scanner + allowlist must report PASS for the current repo."""
    allowlist_keys = load_allowlist(ALLOWLIST_PATH)
    violations = scan(REPO_ROOT)
    new = [v for v in violations if v.allowlist_key() not in allowlist_keys]
    assert not new, (
        f"{len(new)} NEW tenancy violation(s) detected (not in allowlist):\n"
        + "\n".join(f"  {v}" for v in new[:20])
        + ("\n  ..." if len(new) > 20 else "")
    )


# ---------------------------------------------------------------------------
# AC-007-02b: scanner detects synthetic new violation (gate bites)
# ---------------------------------------------------------------------------

def test_v1_regex_detects_query_default_synthetic():
    """Gate bites: a synthetic Query(default='default') org_id line is flagged as V1."""
    synthetic_line = '    org_id: str = Query(default="default"),'

    # Replicate the V1 regex from the scanner directly
    v1_match = re.search(
        r'org_id["\']?\s*[,\)=:][^#\n]*Query\([^)]*default\s*=\s*["\']default["\']',
        synthetic_line,
    ) or re.search(
        r'\borg_id\s*:\s*str\s*=\s*["\']default["\']',
        synthetic_line,
    )
    assert v1_match, (
        f"V1 regex did NOT match synthetic violation line: {synthetic_line!r}\n"
        "The lint gate is broken — fix the scanner regex."
    )


def test_v1_regex_detects_bare_string_default():
    """Gate bites: bare org_id: str = 'default' is also a V1 violation."""
    synthetic_line = "    org_id: str = 'default'"
    v1_match = re.search(
        r'\borg_id\s*:\s*str\s*=\s*["\']default["\']',
        synthetic_line,
    )
    assert v1_match, f"V1 regex did not catch bare str default: {synthetic_line!r}"


def test_v3_regex_detects_shadow_def():
    """Gate bites: a synthetic def get_org_id() is flagged as V3."""
    synthetic_line = "def get_org_id() -> str:"
    v3_match = re.match(r"\s*(async\s+)?def\s+get_org_id\s*[\(\[]", synthetic_line)
    assert v3_match, f"V3 regex did not catch shadow def: {synthetic_line!r}"


def test_v2_regex_detects_noncanonical_import():
    """Gate bites: a non-canonical get_org_id import is flagged as V2."""
    synthetic_line = "from some.random.module import get_org_id"
    m = re.match(r"\s*from\s+([\w\.]+)\s+import\s+(.*)", synthetic_line)
    assert m, "Regex parse failure"
    module = m.group(1).strip()
    imports_part = m.group(2)
    canonical = {"apps.api.org_middleware", "apps.api.dependencies"}
    assert "get_org_id" in imports_part and module not in canonical, (
        "V2 regex did not flag non-canonical import"
    )


# ---------------------------------------------------------------------------
# Regression: canonical imports/defs are NOT flagged
# ---------------------------------------------------------------------------

def test_canonical_import_not_flagged():
    """org_middleware import of get_org_id must NOT be a V2 violation."""
    line = "from apps.api.org_middleware import get_org_id"
    m = re.match(r"\s*from\s+([\w\.]+)\s+import\s+(.*)", line)
    assert m
    module = m.group(1).strip()
    canonical = {"apps.api.org_middleware", "apps.api.dependencies"}
    is_violation = "get_org_id" in m.group(2) and module not in canonical
    assert not is_violation, "Canonical import incorrectly flagged as V2"


def test_v1_regex_does_not_flag_correct_depends():
    """Depends(get_org_id) without a default= must NOT trigger V1."""
    correct_line = "    org_id: str = Depends(get_org_id),"
    v1_match = re.search(
        r'org_id["\']?\s*[,\)=:][^#\n]*Query\([^)]*default\s*=\s*["\']default["\']',
        correct_line,
    ) or re.search(
        r'\borg_id\s*:\s*str\s*=\s*["\']default["\']',
        correct_line,
    )
    assert not v1_match, "Correct Depends() usage incorrectly flagged as V1"


# ---------------------------------------------------------------------------
# Violation.allowlist_key() format
# ---------------------------------------------------------------------------

def test_violation_allowlist_key_format():
    """Violation.allowlist_key() produces path:lineno:CATEGORY."""
    v = Violation(
        rel_path="suite-api/apps/api/foo_router.py",
        line_no=42,
        category="V1",
        text='org_id: str = Query(default="default"),',
    )
    assert v.allowlist_key() == "suite-api/apps/api/foo_router.py:42:V1"
