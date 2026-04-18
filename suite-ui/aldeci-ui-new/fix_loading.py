#!/usr/bin/env python3
"""
Add loading skeleton states to all TSX pages that have useEffect but no lowercase 'loading'.

Strategy per file:
1. Add `const [loading, setLoading] = useState(true);` after the last existing useState
2. Add `.finally(() => setLoading(false))` to the first useEffect in the main component
3. Insert skeleton early-return before the main `return (` of the component
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

def fix_file(filepath: str, dry_run: bool = False) -> str | None:
    """Returns error string or None on success."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    if not needs_fix(content):
        return "SKIP:already_has_loading"

    original = content

    # ── Step 1: Add `const [loading, setLoading] = useState(true);` ──────────
    # Find the export default function body (the main component)
    # Insert after the last useState() call in the component body

    # Find where export default function starts
    comp_start = re.search(r'^export default function \w+', content, re.MULTILINE)
    if not comp_start:
        return "SKIP:no_export_default_function"

    comp_body_start = comp_start.start()
    comp_body = content[comp_body_start:]

    # Find all useState declarations in component body
    use_state_pattern = re.compile(r'^ {2}const \[[^\]]+\] = useState[^\n]+\n', re.MULTILINE)
    matches = list(use_state_pattern.finditer(comp_body))

    loading_decl = "  const [loading, setLoading] = useState(true);\n"

    if matches:
        # Insert after the last useState in the component
        last = matches[-1]
        abs_pos = comp_body_start + last.end()
        content = content[:abs_pos] + loading_decl + content[abs_pos:]
        # Adjust comp_body_start offset for subsequent operations
        offset_added = len(loading_decl)
    else:
        # No useState found — insert after the opening { of the function
        brace_match = re.search(r'\{', comp_body)
        if not brace_match:
            return "SKIP:no_opening_brace"
        abs_pos = comp_body_start + brace_match.end()
        content = content[:abs_pos] + "\n" + loading_decl + content[abs_pos:]
        offset_added = len("\n" + loading_decl)

    # ── Step 2: Add .finally(() => setLoading(false)) to first useEffect ──────
    # Find the first useEffect in the component body (after comp_body_start)
    # We need to find the matching closing `}, [...]` of the useEffect

    # Re-locate comp_body_start (unchanged, just content grew)
    comp_after = content[comp_body_start:]

    # Find first useEffect
    ue_match = re.search(r'\buseEffect\(', comp_after)
    if not ue_match:
        # Shouldn't happen since we checked useEffect exists
        pass
    else:
        ue_abs = comp_body_start + ue_match.start()
        # Find the body of useEffect: useEffect(() => { ... }, [...]);
        # Walk chars to find balanced braces
        pos = ue_abs + ue_match.end()
        # Skip past `() => {` or `function() {`
        # Find the opening { of the callback
        arrow_end = content.find('{', pos)
        if arrow_end != -1:
            # Count braces to find the end of the callback body
            depth = 1
            i = arrow_end + 1
            while i < len(content) and depth > 0:
                if content[i] == '{':
                    depth += 1
                elif content[i] == '}':
                    depth -= 1
                i += 1
            # i now points to char after the closing } of callback
            callback_end = i - 1  # position of closing }

            # The pattern after callback_end should be `}, [...])`
            # Check if .finally already present (shouldn't be since 'loading' not in file)
            # Find what's between callback_end and the end of useEffect statement
            after_callback = content[callback_end:callback_end + 200]

            # Pattern: look for the fetch/Promise chain inside the useEffect body
            callback_body = content[arrow_end + 1:callback_end]

            # Add .finally based on what's inside
            if 'Promise.allSettled' in callback_body:
                # Pattern: Promise.allSettled([...]).then(...)
                # Add .finally after the .then(...) block
                # Find the .then( call and its matching closing paren
                then_match = re.search(r'\.then\(', callback_body)
                if then_match:
                    then_start = then_match.end()
                    # Find matching ) for .then(
                    depth2 = 1
                    j = then_start
                    while j < len(callback_body) and depth2 > 0:
                        if callback_body[j] == '(':
                            depth2 += 1
                        elif callback_body[j] == ')':
                            depth2 -= 1
                        j += 1
                    then_end = arrow_end + 1 + j  # absolute pos after closing ) of .then(...)

                    # Insert .finally(() => setLoading(false)) after .then(...)
                    final_insert = "\n      .finally(() => setLoading(false))"
                    content = content[:then_end] + final_insert + content[then_end:]

            elif 'fetchData' in callback_body:
                # Pattern: useEffect(() => { fetchData(); }, []);
                # Add setLoading(true) before fetchData() and setLoading(false) in fetchData or via finally
                # Simplest: wrap fetchData with setLoading
                # Actually just add setLoading(false) after fetchData() call
                # Find fetchData() call in callback body
                fd_match = re.search(r'fetchData\(\);?', callback_body)
                if fd_match:
                    fd_abs = arrow_end + 1 + fd_match.end()
                    content = content[:fd_abs] + "\n    setLoading(false);" + content[fd_abs:]

            elif 'apiFetch' in callback_body or 'fetch(' in callback_body:
                # Raw fetch chain — add .finally to the chain
                # Find .catch( or .then( at top level and add .finally after it
                # Find the last .catch or .then in the chain
                chain_match = list(re.finditer(r'\.(then|catch)\(', callback_body))
                if chain_match:
                    last_chain = chain_match[-1]
                    lc_start = last_chain.end()
                    # Find matching )
                    depth3 = 1
                    k = lc_start
                    while k < len(callback_body) and depth3 > 0:
                        if callback_body[k] == '(':
                            depth3 += 1
                        elif callback_body[k] == ')':
                            depth3 -= 1
                        k += 1
                    chain_end_abs = arrow_end + 1 + k
                    content = content[:chain_end_abs] + "\n      .finally(() => setLoading(false))" + content[chain_end_abs:]
                else:
                    # Just add setLoading(false) at end of callback body
                    content = content[:callback_end] + "\n    setLoading(false);" + content[callback_end:]
            else:
                # Generic: add setLoading(false) at end of callback body
                content = content[:callback_end] + "\n    setLoading(false);" + content[callback_end:]

    # ── Step 3: Insert skeleton before the main `  return (` ─────────────────
    # Find the first `  return (` that's at 2-space indent in the component body
    # (This is the main render return, not sub-component returns)

    comp_after2 = content[comp_body_start:]
    main_return = re.search(r'^  return \(', comp_after2, re.MULTILINE)
    if main_return:
        abs_return = comp_body_start + main_return.start()
        content = content[:abs_return] + SKELETON + content[abs_return:]
    else:
        # Try without space
        main_return2 = re.search(r'^  return\(', comp_after2, re.MULTILINE)
        if main_return2:
            abs_return2 = comp_body_start + main_return2.start()
            content = content[:abs_return2] + SKELETON + content[abs_return2:]

    if content == original:
        return "SKIP:no_change_made"

    if not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
    return None


def main():
    dry_run = "--dry-run" in sys.argv

    files = sorted([
        os.path.join(PAGES_DIR, f)
        for f in os.listdir(PAGES_DIR)
        if f.endswith(".tsx")
    ])

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
                if dry_run:
                    print(f"  [DRY] WOULD FIX: {os.path.basename(filepath)}")
                else:
                    print(f"  FIXED: {os.path.basename(filepath)}")
        except Exception as e:
            errors.append((filepath, str(e)))
            print(f"  ERROR: {os.path.basename(filepath)}: {e}")

    print(f"\n{'[DRY RUN] ' if dry_run else ''}Done: {len(fixed)} fixed, {len(skipped)} skipped, {len(errors)} errors")
    if errors:
        for f, e in errors:
            print(f"  ERROR in {os.path.basename(f)}: {e}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
