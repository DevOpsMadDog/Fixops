#!/usr/bin/env python3
"""
Fix misplaced setLoading(false) calls and add proper .finally() to useEffect chains.

The first script incorrectly inserted setLoading(false) inside:
  - handleRefresh arrow functions (pattern: setLoading(false);};)
  - .then() bodies (pattern: setLoading(false);})

This script:
1. Removes the misplaced setLoading(false) lines
2. Adds proper .finally(() => setLoading(false)) after the useEffect promise chain
   OR adds setLoading(false) right before the closing }, []); of useEffect
"""

import os
import re
import sys

PAGES_DIR = "/Users/devops.ai/fixops/Fixops/suite-ui/aldeci-ui-new/src/pages"


def find_matching_paren(text: str, start: int) -> int:
    """Given position of '(', return position of matching ')'."""
    depth = 0
    i = start
    while i < len(text):
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def fix_file(filepath: str, dry_run: bool = False) -> tuple[bool, str]:
    """Returns (changed, description)."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # Only fix files that have loading state but misplaced setLoading(false)
    if "loading" not in content:
        return False, "no loading state"
    if "setLoading(false)" not in content:
        return False, "no setLoading call"

    # Check for misplaced patterns
    has_bad1 = "setLoading(false);}" in content  # inside arrow/block
    if not has_bad1:
        return False, "no misplaced setLoading"

    original = content

    # Find the export default function start
    comp_match = re.search(r'^export default function \w+', content, re.MULTILINE)
    if not comp_match:
        return False, "no export default function"
    comp_start = comp_match.start()

    # ── Step 1: Remove all misplaced `\n    setLoading(false);` occurrences ──
    # These are lines that appear as part of another statement (};  or }) on same line)
    # Pattern: \n    setLoading(false); followed immediately by } or }) on same/next chars

    # Remove: `\n    setLoading(false);` when followed by `};` or `})`
    # i.e. the setLoading line is embedded inside a single-line or multi-line arrow
    content = re.sub(
        r'\n    setLoading\(false\);(}[;)])',
        r'\1',
        content
    )
    # Also handle with newline before }
    content = re.sub(
        r'\n    setLoading\(false\);\n(\s*}[;)])',
        r'\n\1',
        content
    )

    # ── Step 2: Check if useEffect now has a proper setLoading(false) ──────────
    # Find the first useEffect in component body
    comp_body = content[comp_start:]
    ue_match = re.search(r'\buseEffect\(\(\)\s*=>\s*\{', comp_body)
    if not ue_match:
        # Try alternate form
        ue_match = re.search(r'\buseEffect\(\(\)\s*=>\s*\{', comp_body)

    if ue_match:
        ue_start_rel = ue_match.start()
        ue_abs = comp_start + ue_start_rel

        # Find the opening { of the callback
        brace_open_rel = ue_match.end() - 1  # position of { in comp_body
        brace_open_abs = comp_start + brace_open_rel

        # Find matching }
        depth = 0
        i = brace_open_abs
        while i < len(content):
            if content[i] == '{':
                depth += 1
            elif content[i] == '}':
                depth -= 1
                if depth == 0:
                    break
            i += 1
        cb_close_abs = i

        callback_body = content[brace_open_abs + 1:cb_close_abs]

        # Check if setLoading(false) is already properly present in useEffect body
        if 'setLoading(false)' in callback_body:
            # Already has it properly
            pass
        else:
            # Add it properly
            if 'Promise.allSettled' in callback_body:
                # Find .then( and add .finally after its matching )
                then_match = re.search(r'\.then\(', callback_body)
                if then_match:
                    paren_start_abs = brace_open_abs + 1 + then_match.end() - 1
                    paren_end_abs = find_matching_paren(content, paren_start_abs)
                    if paren_end_abs != -1:
                        insert_pos = paren_end_abs + 1
                        content = (
                            content[:insert_pos]
                            + "\n      .finally(() => setLoading(false))"
                            + content[insert_pos:]
                        )
            elif 'fetchData' in callback_body:
                # Add setLoading(false) before closing }
                content = content[:cb_close_abs] + "\n    setLoading(false);" + content[cb_close_abs:]
            else:
                # fetch chain: add .finally after last .catch or .then
                chain_matches = list(re.finditer(r'\.(then|catch)\(', callback_body))
                if chain_matches:
                    last_m = chain_matches[-1]
                    paren_start_abs = brace_open_abs + 1 + last_m.end() - 1
                    paren_end_abs = find_matching_paren(content, paren_start_abs)
                    if paren_end_abs != -1:
                        insert_pos = paren_end_abs + 1
                        content = (
                            content[:insert_pos]
                            + "\n      .finally(() => setLoading(false))"
                            + content[insert_pos:]
                        )
                else:
                    content = content[:cb_close_abs] + "\n    setLoading(false);" + content[cb_close_abs:]

    changed = content != original
    if changed and not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

    return changed, "fixed" if changed else "no change"


def main():
    dry_run = "--dry-run" in sys.argv
    target_file = None
    for arg in sys.argv[1:]:
        if arg != "--dry-run" and arg.endswith(".tsx"):
            target_file = arg

    files = sorted([
        os.path.join(PAGES_DIR, f)
        for f in os.listdir(PAGES_DIR)
        if f.endswith(".tsx")
    ])
    if target_file:
        if not target_file.startswith("/"):
            target_file = os.path.join(PAGES_DIR, target_file)
        files = [target_file]

    fixed = []
    skipped = []
    errors = []

    for filepath in files:
        try:
            changed, desc = fix_file(filepath, dry_run=dry_run)
            if changed:
                fixed.append(filepath)
                print(f"  {'[DRY] ' if dry_run else ''}FIXED: {os.path.basename(filepath)}")
            else:
                skipped.append(filepath)
        except Exception as e:
            errors.append((filepath, str(e)))
            print(f"  ERROR: {os.path.basename(filepath)}: {e}")
            import traceback; traceback.print_exc()

    mode = "[DRY RUN] " if dry_run else ""
    print(f"\n{mode}Done: {len(fixed)} fixed, {len(skipped)} skipped, {len(errors)} errors")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
