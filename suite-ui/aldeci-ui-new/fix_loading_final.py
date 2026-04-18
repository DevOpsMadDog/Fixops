#!/usr/bin/env python3
"""
Final comprehensive fix for all misplaced setLoading(false) calls.

Misplaced patterns (inserted by previous buggy script):
  A) `\n    setLoading(false);}`   -- embedded before any closing brace
  B) `\n    setLoading(false);}, []);`  -- at end of useEffect deps
  C) `\n    setLoading(false);})`   -- inside .then() body
  D) ` \n    setLoading(false);}, [` -- with space before newline

A file is "done correctly" if:
  - It has `.finally(() => setLoading(false))` in first useEffect, OR
  - It has standalone `setLoading(false);` on its own indented line in useEffect body

Strategy for each file:
  1. Remove ALL `\n    setLoading(false);` occurrences that precede `}` (misplaced)
  2. After removal, check if useEffect still has setLoading — if not, add .finally properly
"""

import os
import re
import sys

PAGES_DIR = "/Users/devops.ai/fixops/Fixops/suite-ui/aldeci-ui-new/src/pages"


def find_matching_paren(text: str, start: int) -> int:
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


def find_matching_brace(text: str, start: int) -> int:
    depth = 0
    i = start
    while i < len(text):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def remove_all_misplaced(content: str) -> str:
    """Remove every \n    setLoading(false); that is followed by } (misplaced)."""
    # The pattern: optional spaces, then \n    setLoading(false); then optional spaces then }
    # This covers all variants: };  })  }, []);  } trend=...
    result = re.sub(
        r' ?\n    setLoading\(false\);(?=\s*})',
        '',
        content
    )
    return result


def useeffect_has_setloading(content: str, comp_start: int) -> bool:
    """Check if first useEffect properly contains setLoading(false) as standalone or .finally."""
    comp_body = content[comp_start:]
    ue_match = re.search(r'\buseEffect\(', comp_body)
    if not ue_match:
        return False

    outer_open = comp_start + ue_match.end() - 1
    outer_close = find_matching_paren(content, outer_open)
    if outer_close == -1:
        return False

    ue_block = content[comp_start + ue_match.start():outer_close + 1]

    # Check for .finally version
    if '.finally(() => setLoading(false))' in ue_block:
        return True
    # Check for standalone setLoading(false); on its own line (4-space indent)
    if re.search(r'\n    setLoading\(false\);\n', ue_block):
        return True
    return False


def add_finally_to_useeffect(content: str, comp_start: int) -> str:
    """Add .finally(() => setLoading(false)) to first useEffect."""
    comp_body = content[comp_start:]
    ue_match = re.search(r'\buseEffect\(', comp_body)
    if not ue_match:
        return content

    outer_open_abs = comp_start + ue_match.end() - 1
    outer_close_abs = find_matching_paren(content, outer_open_abs)
    if outer_close_abs == -1:
        return content

    # Find callback opening brace (first { after useEffect()
    cb_open_abs = content.find('{', outer_open_abs + 1)
    if cb_open_abs == -1 or cb_open_abs >= outer_close_abs:
        return content
    cb_close_abs = find_matching_brace(content, cb_open_abs)
    if cb_close_abs == -1:
        return content

    callback_body = content[cb_open_abs + 1:cb_close_abs]

    if 'Promise.allSettled' in callback_body:
        then_match = re.search(r'\.then\(', callback_body)
        if then_match:
            paren_open_abs = cb_open_abs + 1 + then_match.end() - 1
            paren_close_abs = find_matching_paren(content, paren_open_abs)
            if paren_close_abs != -1:
                ins = paren_close_abs + 1
                return content[:ins] + "\n      .finally(() => setLoading(false))" + content[ins:]

    if 'fetchData()' in callback_body:
        return content[:cb_close_abs] + "\n    setLoading(false);" + content[cb_close_abs:]

    # fetch/apiFetch chain: add .finally after last .catch or .then
    chain_matches = list(re.finditer(r'\.(then|catch)\(', callback_body))
    if chain_matches:
        last_m = chain_matches[-1]
        paren_open_abs = cb_open_abs + 1 + last_m.end() - 1
        paren_close_abs = find_matching_paren(content, paren_open_abs)
        if paren_close_abs != -1:
            ins = paren_close_abs + 1
            return content[:ins] + "\n      .finally(() => setLoading(false))" + content[ins:]

    # Generic: add before closing brace
    return content[:cb_close_abs] + "\n    setLoading(false);" + content[cb_close_abs:]


def fix_file(filepath: str, dry_run: bool = False) -> tuple[bool, str]:
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    if "setLoading" not in content:
        return False, "no setLoading"

    original = content
    comp_match = re.search(r'^export default function \w+', content, re.MULTILINE)
    if not comp_match:
        return False, "no export default function"
    comp_start = comp_match.start()

    # Step 1: Always remove all misplaced setLoading(false) occurrences
    content = remove_all_misplaced(content)

    # Step 2: If useEffect no longer has setLoading, add it properly
    if not useeffect_has_setloading(content, comp_start):
        content = add_finally_to_useeffect(content, comp_start)

    changed = content != original
    if changed and not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
    return changed, "fixed" if changed else "no change"


def main():
    dry_run = "--dry-run" in sys.argv
    target_files = [a for a in sys.argv[1:] if a != "--dry-run" and a.endswith(".tsx")]

    if target_files:
        files = [
            f if f.startswith("/") else os.path.join(PAGES_DIR, f)
            for f in target_files
        ]
    else:
        files = sorted([
            os.path.join(PAGES_DIR, f)
            for f in os.listdir(PAGES_DIR)
            if f.endswith(".tsx")
        ])

    fixed, skipped, errors = [], [], []

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
    if errors:
        for f, e in errors:
            print(f"  ERROR in {os.path.basename(f)}: {e}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
