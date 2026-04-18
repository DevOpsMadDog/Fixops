#!/usr/bin/env python3
"""
Add loading skeleton states to all TSX pages that have useEffect but no lowercase 'loading'.

Strategy per file:
1. Add `const [loading, setLoading] = useState(true);` after the last existing useState
2. Add `.finally(() => setLoading(false))` to the useEffect promise chain,
   OR set loading(false) before }, []); close
3. Insert skeleton early-return before the main `  return (` of the component
"""

import os
import re
import sys

PAGES_DIR = "/Users/devops.ai/fixops/Fixops/suite-ui/aldeci-ui-new/src/pages"

SKELETON = """\
  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

"""

def needs_fix(content: str) -> bool:
    return "useEffect" in content and "loading" not in content


def find_matching_brace(text: str, start: int) -> int:
    """Given position of '{', return position of matching '}'."""
    depth = 0
    i = start
    while i < len(text):
        c = text[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def find_matching_paren(text: str, start: int) -> int:
    """Given position of '(', return position of matching ')'."""
    depth = 0
    i = start
    while i < len(text):
        c = text[i]
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def find_use_effect_bounds(content: str, comp_start: int) -> tuple[int, int, int] | None:
    """
    Find the first useEffect in the component body.
    Returns (ue_start, callback_open_brace, callback_close_brace) or None.
    """
    comp_body = content[comp_start:]
    ue_match = re.search(r'\buseEffect\(', comp_body)
    if not ue_match:
        return None

    ue_abs = comp_start + ue_match.start()
    # useEffect( ... ) — find the outer paren
    outer_paren_start = comp_start + ue_match.end() - 1  # position of '('
    # Actually ue_match.end() is just after 'useEffect(' — so outer open paren is at ue_match.end()-1 relative to comp_body
    outer_open = comp_start + ue_match.end() - 1

    # Find the callback: () => { or function() {
    # Scan for the first '{' inside the outer paren
    search_start = outer_open + 1
    brace_pos = content.find('{', search_start)
    if brace_pos == -1:
        return None

    close_brace = find_matching_brace(content, brace_pos)
    if close_brace == -1:
        return None

    return (ue_abs, brace_pos, close_brace)


def add_finally_to_content(content: str, comp_start: int) -> str:
    """Add .finally(() => setLoading(false)) to first useEffect in component."""
    bounds = find_use_effect_bounds(content, comp_start)
    if not bounds:
        return content

    ue_abs, cb_open, cb_close = bounds
    callback_body = content[cb_open + 1:cb_close]

    if 'Promise.allSettled' in callback_body:
        # Find .then( in callback and add .finally after its matching )
        then_match = re.search(r'\.then\(', callback_body)
        if then_match:
            # Find the '(' of .then(
            paren_start_rel = then_match.end() - 1  # relative to callback_body
            paren_start_abs = cb_open + 1 + paren_start_rel
            paren_end_abs = find_matching_paren(content, paren_start_abs)
            if paren_end_abs != -1:
                insert_pos = paren_end_abs + 1
                return content[:insert_pos] + "\n      .finally(() => setLoading(false))" + content[insert_pos:]

    if 'fetchData' in callback_body:
        # useEffect(() => { fetchData(); }, []);
        # Add setLoading(false) before the closing } of callback
        return content[:cb_close] + "\n    setLoading(false);" + content[cb_close:]

    # fetch(...).then(...).catch(...) chains
    if 'apiFetch' in callback_body or 'fetch(' in callback_body:
        # Find last .catch( or .then( in callback body, add .finally after its )
        chain_matches = list(re.finditer(r'\.(then|catch)\(', callback_body))
        if chain_matches:
            last_m = chain_matches[-1]
            paren_start_rel = cb_open + 1 + last_m.end() - 1
            paren_end_abs = find_matching_paren(content, paren_start_rel)
            if paren_end_abs != -1:
                insert_pos = paren_end_abs + 1
                return content[:insert_pos] + "\n      .finally(() => setLoading(false))" + content[insert_pos:]

    # Generic fallback: add setLoading(false) before closing brace
    return content[:cb_close] + "\n    setLoading(false);" + content[cb_close:]


def fix_file(filepath: str, dry_run: bool = False) -> str | None:
    """Returns error string or None on success."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    if not needs_fix(content):
        return "SKIP:already_has_loading"

    original = content

    # ── Find component start ───────────────────────────────────────────────────
    comp_match = re.search(r'^export default function \w+', content, re.MULTILINE)
    if not comp_match:
        return "SKIP:no_export_default_function"

    comp_start = comp_match.start()

    # ── Step 1: Add loading state after last useState in component ─────────────
    comp_body_text = content[comp_start:]
    use_state_pattern = re.compile(r'^ {2}const \[[^\]]+\] = useState[^\n]+\n', re.MULTILINE)
    matches = list(use_state_pattern.finditer(comp_body_text))

    loading_decl = "  const [loading, setLoading] = useState(true);\n"

    if matches:
        last = matches[-1]
        abs_pos = comp_start + last.end()
        content = content[:abs_pos] + loading_decl + content[abs_pos:]
        comp_start_adjusted = comp_start  # comp_start unchanged (insertion is after it)
    else:
        # Insert after opening { of function
        brace_pos = content.find('{', comp_start)
        if brace_pos == -1:
            return "SKIP:no_opening_brace"
        abs_pos = brace_pos + 1
        content = content[:abs_pos] + "\n" + loading_decl + content[abs_pos:]

    # Re-find comp_start after insertion (comp_start unchanged since we inserted after it)
    # But the content grew, so positions after insertion point shifted.
    # comp_start itself didn't move.

    # ── Step 2: Add .finally to first useEffect ────────────────────────────────
    content = add_finally_to_content(content, comp_start)

    # ── Step 3: Insert skeleton before main `  return (` ──────────────────────
    comp_after = content[comp_start:]
    main_return = re.search(r'^  return \(', comp_after, re.MULTILINE)
    if main_return:
        abs_return = comp_start + main_return.start()
        content = content[:abs_return] + SKELETON + content[abs_return:]
    else:
        main_return2 = re.search(r'^  return\(', comp_after, re.MULTILINE)
        if main_return2:
            abs_return2 = comp_start + main_return2.start()
            content = content[:abs_return2] + SKELETON + content[abs_return2:]

    if content == original:
        return "SKIP:no_change_made"

    if not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
    return None


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
        # Single file mode
        if not target_file.startswith("/"):
            target_file = os.path.join(PAGES_DIR, target_file)
        files = [target_file]

    fixed = []
    skipped = []
    errors = []

    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            if not needs_fix(content):
                skipped.append(filepath)
                continue
            result = fix_file(filepath, dry_run=dry_run)
            if result and result.startswith("SKIP"):
                skipped.append(filepath)
                print(f"  SKIP [{result}]: {os.path.basename(filepath)}")
            elif result:
                errors.append((filepath, result))
                print(f"  ERROR: {os.path.basename(filepath)}: {result}")
            else:
                fixed.append(filepath)
                if not dry_run:
                    print(f"  FIXED: {os.path.basename(filepath)}")
        except Exception as e:
            errors.append((filepath, str(e)))
            print(f"  ERROR: {os.path.basename(filepath)}: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()

    mode = "[DRY RUN] " if dry_run else ""
    print(f"\n{mode}Done: {len(fixed)} fixed, {len(skipped)} skipped, {len(errors)} errors")
    if errors:
        for f, e in errors:
            print(f"  ERROR in {os.path.basename(f)}: {e}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
