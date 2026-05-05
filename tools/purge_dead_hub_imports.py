#!/usr/bin/env python3
"""
Purge dead lazy() imports from Hub files under src/pages/*.Hub.tsx.

For each Hub file:
1. Find lines: const X = lazy(() => import("@/pages/..."))
2. If the target file doesn't exist, record X as dead.
3. Remove the const X = lazy(...) declaration line.
4. Remove any JSX line referencing <X /> or element={<X} etc.
5. Also fixes TabsContent / tab value references to dead components.

Usage:
    python tools/purge_dead_hub_imports.py suite-ui/aldeci-ui-new/src/pages
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


def purge_file(fpath: str, pages_dir: str) -> int:
    with open(fpath, "r", encoding="utf-8") as fh:
        lines = fh.readlines()

    lazy_re = re.compile(
        r'^\s*const\s+(\w+)\s*=\s*lazy\(\s*\(\s*\)\s*=>\s*import\("@/pages/([^"]+)"\)\s*\)'
    )

    dead: set[str] = set()
    for line in lines:
        m = lazy_re.match(line)
        if m:
            comp_name, page_path = m.group(1), m.group(2)
            if not resolve(pages_dir, page_path):
                dead.add(comp_name)

    if not dead:
        return 0

    dead_sorted = sorted(dead, key=len, reverse=True)

    # Match dead component used as JSX tag or in element={<X
    dead_jsx_re = re.compile(
        r'<(?:' + '|'.join(re.escape(n) for n in dead_sorted) + r')[\s/>]'
    )
    lazy_name_re = re.compile(
        r'^\s*const\s+(?:' + '|'.join(re.escape(n) for n in dead_sorted) + r')\s*='
    )
    # Also drop TABS array entries that reference dead components
    # e.g.  { key: "foo", label: "Foo", component: DeadComp }
    dead_ref_re = re.compile(
        r'\b(?:' + '|'.join(re.escape(n) for n in dead_sorted) + r')\b'
    )

    kept: list[str] = []
    removed = 0
    for line in lines:
        if lazy_name_re.match(line):
            removed += 1
            continue
        if dead_jsx_re.search(line):
            removed += 1
            continue
        # Drop TABS-style object literals referencing dead components
        # Only drop if the whole line is essentially just the entry
        stripped = line.strip()
        if dead_ref_re.search(line) and stripped.startswith("{") and stripped.endswith("},"):
            removed += 1
            continue
        if dead_ref_re.search(line) and "component:" in line:
            removed += 1
            continue
        kept.append(line)

    with open(fpath, "w", encoding="utf-8") as fh:
        fh.writelines(kept)

    return removed


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: purge_dead_hub_imports.py <src/pages dir>")
        sys.exit(1)

    pages_dir = sys.argv[1]
    hub_files = sorted(glob.glob(os.path.join(pages_dir, "*Hub.tsx")))
    print(f"Found {len(hub_files)} Hub files")

    total_removed = 0
    for fpath in hub_files:
        removed = purge_file(fpath, pages_dir)
        if removed:
            print(f"  {os.path.basename(fpath)}: removed {removed} lines")
            total_removed += removed

    print(f"\nTotal lines removed across all Hub files: {total_removed}")


if __name__ == "__main__":
    main()
