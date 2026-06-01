"""SPEC-007 — Tenancy lint scanner.

Scans suite-api/apps/api and suite-core/api for three categories of
tenancy violations:

  V1  org_id parameter using Query(default="default") or bare str = "default"
  V2  `from X import ... get_org_id` where X is NOT a canonical module
  V3  `def get_org_id` defined outside the canonical modules

Allowlist:
    specs/tenancy_allowlist.txt — one "file:line:category" entry per known
    (frozen) violation.  The gate PASSES if the current violation set is a
    SUBSET of the allowlist.  It FAILS if any NEW violation appears (i.e. a
    violation not in the allowlist).  The allowlist may only shrink over time.

Usage:
    python scripts/tenancy_lint.py [--generate-allowlist] [--repo-root PATH]

    --generate-allowlist  Write the current violations to the allowlist file
                          (use once to bootstrap; do not run in CI gate mode).
    --repo-root PATH      Override repo root (default: parent of this script).

Exit codes:
    0  Clean (no new violations beyond allowlist)
    1  New violation(s) detected — CI should fail
    2  Usage / config error
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CANONICAL_MODULES = frozenset({"apps.api.org_middleware", "apps.api.dependencies"})

CANONICAL_FILES = frozenset({"org_middleware.py", "dependencies.py"})

SCAN_DIRS_REL = ["suite-api/apps/api", "suite-core/api"]

ALLOWLIST_REL = "specs/tenancy_allowlist.txt"


# ---------------------------------------------------------------------------
# Violation dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Violation:
    rel_path: str   # relative to repo root
    line_no: int
    category: str   # V1 | V2 | V3
    text: str       # stripped source line

    def allowlist_key(self) -> str:
        """Stable key stored in the allowlist (path:lineno:category)."""
        return f"{self.rel_path}:{self.line_no}:{self.category}"

    def __str__(self) -> str:
        return f"[{self.category}] {self.rel_path}:{self.line_no}: {self.text}"


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def scan(repo_root: Path) -> list[Violation]:
    violations: list[Violation] = []

    for scan_dir_rel in SCAN_DIRS_REL:
        scan_dir = repo_root / scan_dir_rel
        if not scan_dir.exists():
            continue

        for fpath in sorted(scan_dir.rglob("*.py")):
            rel = str(fpath.relative_to(repo_root))
            is_canonical = fpath.name in CANONICAL_FILES

            try:
                lines = fpath.read_text(errors="ignore").splitlines()
            except OSError:
                continue

            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()

                # --- V1: org_id Query(default="default") ---
                if re.search(
                    r'org_id["\']?\s*[,\)=:][^#\n]*Query\([^)]*default\s*=\s*["\']default["\']',
                    line,
                ) or re.search(
                    r'\borg_id\s*:\s*str\s*=\s*["\']default["\']',
                    line,
                ):
                    violations.append(
                        Violation(rel, lineno, "V1", stripped)
                    )

                if not is_canonical:
                    # --- V2: non-canonical get_org_id import ---
                    m = re.match(r"\s*from\s+([\w\.]+)\s+import\s+(.*)", line)
                    if m:
                        module = m.group(1).strip()
                        imports_part = m.group(2)
                        if (
                            "get_org_id" in imports_part
                            and module not in CANONICAL_MODULES
                        ):
                            violations.append(
                                Violation(rel, lineno, "V2", stripped)
                            )

                    # --- V3: shadow def get_org_id ---
                    if re.match(r"\s*(async\s+)?def\s+get_org_id\s*[\(\[]", line):
                        violations.append(
                            Violation(rel, lineno, "V3", stripped)
                        )

    return violations


# ---------------------------------------------------------------------------
# Allowlist helpers
# ---------------------------------------------------------------------------

def load_allowlist(path: Path) -> set[str]:
    if not path.exists():
        return set()
    keys: set[str] = set()
    for raw_line in path.read_text(errors="ignore").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            keys.add(line)
    return keys


def write_allowlist(path: Path, violations: list[Violation]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# SPEC-007 tenancy violation allowlist — frozen debt.",
        "# Format: relative/path/to/file.py:lineno:CATEGORY",
        "# This list may only SHRINK. Never add new entries manually.",
        f"# Generated violations: {len(violations)}",
        "",
    ]
    for v in sorted(violations, key=lambda x: x.allowlist_key()):
        lines.append(v.allowlist_key())
    path.write_text("\n".join(lines) + "\n")
    print(f"Allowlist written: {path} ({len(violations)} entries)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SPEC-007 tenancy lint scanner")
    parser.add_argument(
        "--generate-allowlist",
        action="store_true",
        help="Write current violations to the allowlist (bootstrap mode).",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Path to repo root (default: parent of this script's directory).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-violation output; only print summary.",
    )
    args = parser.parse_args(argv)

    repo_root: Path = args.repo_root or Path(__file__).resolve().parent.parent
    allowlist_path = repo_root / ALLOWLIST_REL

    violations = scan(repo_root)

    counts = {"V1": 0, "V2": 0, "V3": 0}
    for v in violations:
        counts[v.category] += 1

    print(
        f"Tenancy lint — "
        f"V1(query-default)={counts['V1']}  "
        f"V2(import)={counts['V2']}  "
        f"V3(shadow-def)={counts['V3']}  "
        f"total={len(violations)}"
    )

    if args.generate_allowlist:
        write_allowlist(allowlist_path, violations)
        return 0

    # --- Gate mode: compare against allowlist ---
    allowlist_keys = load_allowlist(allowlist_path)

    if not allowlist_keys and violations:
        print(
            "ERROR: allowlist is empty but violations exist. "
            "Run with --generate-allowlist first.",
            file=sys.stderr,
        )
        return 2

    new_violations = [v for v in violations if v.allowlist_key() not in allowlist_keys]

    if new_violations:
        print(f"\nFAIL — {len(new_violations)} NEW violation(s) not in allowlist:")
        for v in new_violations:
            print(f"  {v}")
        print(
            "\nFix these violations or add them to the allowlist "
            "(only shrinking allowed; never grow it)."
        )
        return 1

    removed = allowlist_keys - {v.allowlist_key() for v in violations}
    if removed and not args.quiet:
        print(f"INFO: {len(removed)} allowlisted violation(s) have been fixed.")

    print(f"OK — no new violations (allowlist has {len(allowlist_keys)} frozen entries).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
