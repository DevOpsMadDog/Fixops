#!/usr/bin/env python3
"""
Purge ALL dead @/pages/ references from any .tsx/.ts file under src/.

Handles:
  - const X = lazy(() => import("@/pages/..."))
  - const X = lazy(() => import("@/pages/..."));  (with semicolon)
  - import X from "@/pages/..."
  - import { X } from "@/pages/..."  (named imports — drop whole line)
  - Inline bare imports: import("@/pages/...")  inside object literals / JSX
  - JSX usage: <X /> <X> element={<X} (any line referencing a dead name)
  - TABS-style object entries:  { key: "...", label: "...", component: DeadX }
  - Test file imports referencing dead pages

Usage:
    python tools/purge_all_dead_imports.py suite-ui/aldeci-ui-new/src <pages_dir>
"""

import os
import re
import sys
import glob


def resolve(pages_dir: str, path: str) -> bool:
    base = os.path.join(pages_dir, path)
    return (
        os.path.isfile(base + ".tsx")
        or os.path.isfile(os.path.join(base, "index.tsx"))
        or os.path.isfile(base + ".ts")
    )


# ── patterns to extract import paths ────────────────────────────────────────
# lazy(() => import("@/pages/foo"))
LAZY_RE = re.compile(
    r'^\s*const\s+(\w+)\s*=\s*lazy\(\s*\(\s*\)\s*=>\s*import\("@/pages/([^"]+)"\)\s*\)'
)
# import X from "@/pages/foo"
DEFAULT_IMPORT_RE = re.compile(
    r'^\s*import\s+(\w+)\s+from\s+"@/pages/([^"]+)"'
)
# import { X, Y } from "@/pages/foo"  — named
NAMED_IMPORT_RE = re.compile(
    r'^\s*import\s+\{[^}]+\}\s+from\s+"@/pages/([^"]+)"'
)
# inline: import("@/pages/foo")  — anywhere on a line (dynamic, not const-assigned)
INLINE_IMPORT_RE = re.compile(r'import\("@/pages/([^"]+)"\)')


def collect_dead_names(lines: list[str], pages_dir: str) -> set[str]:
    dead: set[str] = set()
    for line in lines:
        # lazy const
        m = LAZY_RE.match(line)
        if m:
            if not resolve(pages_dir, m.group(2)):
                dead.add(m.group(1))
            continue
        # default import
        m = DEFAULT_IMPORT_RE.match(line)
        if m:
            if not resolve(pages_dir, m.group(2)):
                dead.add(m.group(1))
            continue
        # named import — we can't easily track individual names; drop whole line
        # handled later by path check
    return dead


def collect_dead_paths(lines: list[str], pages_dir: str) -> set[str]:
    """Return set of @/pages/... paths that are missing."""
    dead: set[str] = set()
    for line in lines:
        for m in INLINE_IMPORT_RE.finditer(line):
            path = m.group(1)
            if not resolve(pages_dir, path):
                dead.add(path)
        m = LAZY_RE.match(line)
        if m and not resolve(pages_dir, m.group(2)):
            dead.add(m.group(2))
        m = DEFAULT_IMPORT_RE.match(line)
        if m and not resolve(pages_dir, m.group(2)):
            dead.add(m.group(2))
        m = NAMED_IMPORT_RE.match(line)
        if m and not resolve(pages_dir, m.group(1)):
            dead.add(m.group(1))
    return dead


def build_name_re(dead: set[str]) -> re.Pattern | None:
    if not dead:
        return None
    ds = sorted(dead, key=len, reverse=True)
    return re.compile(r'\b(?:' + '|'.join(re.escape(n) for n in ds) + r')\b')


def build_path_re(dead_paths: set[str]) -> re.Pattern | None:
    if not dead_paths:
        return None
    ds = sorted(dead_paths, key=len, reverse=True)
    return re.compile(
        r'(?:' + '|'.join(re.escape(p) for p in ds) + r')'
    )


def purge_file(fpath: str, pages_dir: str) -> int:
    with open(fpath, "r", encoding="utf-8") as fh:
        lines = fh.readlines()

    dead_names = collect_dead_names(lines, pages_dir)
    dead_paths = collect_dead_paths(lines, pages_dir)

    if not dead_names and not dead_paths:
        return 0

    name_re = build_name_re(dead_names)
    path_re = build_path_re(dead_paths)

    # Regex for lazy/default import declaration lines referencing dead names
    if dead_names:
        ds = sorted(dead_names, key=len, reverse=True)
        decl_re = re.compile(
            r'^\s*(?:const\s+)?(?:' + '|'.join(re.escape(n) for n in ds) + r')\s*='
        )
        import_decl_re = re.compile(
            r'^\s*import\s+(?:' + '|'.join(re.escape(n) for n in ds) + r')\s+from\s+'
        )
    else:
        decl_re = None
        import_decl_re = None

    kept: list[str] = []
    removed = 0

    for line in lines:
        drop = False

        # 1. Drop lazy const declaration for dead name
        if decl_re and decl_re.match(line) and 'lazy(' in line:
            drop = True

        # 2. Drop default import for dead name
        if not drop and import_decl_re and import_decl_re.match(line):
            drop = True

        # 3. Drop any import line referencing a dead path (named, inline, etc.)
        if not drop and path_re and path_re.search(line):
            if 'import' in line:
                drop = True

        # 4. Drop JSX usage of dead component names
        if not drop and name_re:
            if name_re.search(line):
                stripped = line.strip()
                # Drop if it's a JSX element line or a route/element prop line
                if (
                    '<' in line and name_re.search(line)
                    or 'element={' in line
                    or 'component:' in line
                    or (stripped.startswith('{') and stripped.endswith('},'))
                ):
                    drop = True

        if drop:
            removed += 1
        else:
            kept.append(line)

    if removed:
        with open(fpath, "w", encoding="utf-8") as fh:
            fh.writelines(kept)

    return removed


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: purge_all_dead_imports.py <src_dir> <pages_dir>")
        sys.exit(1)

    src_dir = sys.argv[1]
    pages_dir = sys.argv[2]

    tsx_files = glob.glob(os.path.join(src_dir, "**", "*.tsx"), recursive=True)
    tsx_files += glob.glob(os.path.join(src_dir, "**", "*.ts"), recursive=True)

    total = 0
    for fpath in sorted(tsx_files):
        removed = purge_file(fpath, pages_dir)
        if removed:
            rel = os.path.relpath(fpath, src_dir)
            print(f"  {rel}: removed {removed} lines")
            total += removed

    print(f"\nTotal lines removed: {total}")


if __name__ == "__main__":
    main()
