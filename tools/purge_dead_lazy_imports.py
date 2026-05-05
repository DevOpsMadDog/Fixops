#!/usr/bin/env python3
"""
Purge dead lazy() imports and their matching <Route> entries from App.tsx.

Usage:
    python tools/purge_dead_lazy_imports.py suite-ui/aldeci-ui-new/src/App.tsx

The script:
1. Reads App.tsx line by line.
2. For every `const X = lazy(() => import("@/pages/..."))` line, resolves the
   file path relative to the pages directory.
3. If the target file does not exist (.tsx / /index.tsx / .ts), the line is
   marked DEAD and the component name is recorded.
4. Every JSX line that references a dead component name (as a JSX tag or
   element prop) is also removed.
5. Writes the cleaned file back in-place and prints a summary.
"""

import os
import re
import sys

def resolve(pages_dir: str, path: str) -> bool:
    """Return True if the target page file exists on disk."""
    base = os.path.join(pages_dir, path)
    return (
        os.path.isfile(base + ".tsx")
        or os.path.isfile(os.path.join(base, "index.tsx"))
        or os.path.isfile(base + ".ts")
    )


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: purge_dead_lazy_imports.py <path/to/App.tsx>")
        sys.exit(1)

    app_path = sys.argv[1]
    pages_dir = os.path.join(os.path.dirname(app_path), "pages")

    with open(app_path, "r", encoding="utf-8") as fh:
        lines = fh.readlines()

    # ── Pass 1: identify dead component names ────────────────────────────────
    # Pattern: const SomeName = lazy(() => import("@/pages/some/path"))
    lazy_re = re.compile(
        r'^\s*const\s+(\w+)\s*=\s*lazy\(\s*\(\s*\)\s*=>\s*import\("@/pages/([^"]+)"\)\s*\)'
    )

    dead: set[str] = set()
    alive: set[str] = set()

    for line in lines:
        m = lazy_re.match(line)
        if m:
            comp_name = m.group(1)
            page_path = m.group(2)
            if resolve(pages_dir, page_path):
                alive.add(comp_name)
            else:
                dead.add(comp_name)

    print(f"Alive lazy imports : {len(alive)}")
    print(f"Dead  lazy imports : {len(dead)}")

    if not dead:
        print("Nothing to remove.")
        return

    # ── Pass 2: drop dead lines ───────────────────────────────────────────────
    # We drop a line if it matches any of these patterns for a dead name X:
    #   • const X = lazy(...)                        — the import itself
    #   • <Route ... element={<X .../>} ... />       — single-line route
    #   • <Route ... element={<X />} ... />
    #   • element={<X />}  (anywhere)
    #   • <X />  or  <X>   (standalone JSX usage)
    # We use a broad token-based check: if any dead name appears as a JSX
    # component reference on the line, drop the whole line.

    # Build one regex that matches any dead component used as JSX / prop value.
    dead_sorted = sorted(dead, key=len, reverse=True)  # longest first
    dead_pattern = re.compile(
        r'(?:'
        + r'|'.join(re.escape(n) for n in dead_sorted)
        + r')(?:\s*/?>|(?=\s))'
    )
    lazy_name_re = re.compile(
        r'^\s*const\s+(' + '|'.join(re.escape(n) for n in dead_sorted) + r')\s*='
    )

    kept: list[str] = []
    removed_count = 0

    for line in lines:
        # Drop the const X = lazy(...) declaration lines
        if lazy_name_re.match(line):
            removed_count += 1
            continue
        # Drop any line that uses a dead component as JSX element/prop
        if dead_pattern.search(line):
            removed_count += 1
            continue
        kept.append(line)

    print(f"Lines removed      : {removed_count}")
    print(f"Lines remaining    : {len(kept)}")

    # ── Write back ────────────────────────────────────────────────────────────
    backup = app_path + ".bak"
    with open(backup, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    print(f"Backup written to  : {backup}")

    with open(app_path, "w", encoding="utf-8") as fh:
        fh.writelines(kept)
    print(f"Cleaned file written: {app_path}")


if __name__ == "__main__":
    main()
