#!/usr/bin/env python3
"""
Add loading skeleton states to all TSX pages that have useEffect but no loading state.
"""

import os
import re
import sys

PAGES_DIR = "/Users/devops.ai/fixops/Fixops/suite-ui/aldeci-ui-new/src/pages"

SKELETON_RETURN = """  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

"""

def needs_fix(content: str) -> bool:
    return "useEffect" in content and "loading" not in content

def fix_file(filepath: str) -> bool:
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    if not needs_fix(content):
        return False

    original = content

    # ── 1. Add loading to useState import (or add useState import) ──────────

    # Already imports useState
    if "useState" in content:
        # Add loading state after the first useState declaration in the component
        # We'll inject it as the first new useState line after the component function opens
        pass
    else:
        # Need to add useState to imports
        content = content.replace(
            'import { useEffect }',
            'import { useState, useEffect }'
        )
        content = content.replace(
            'import {useEffect}',
            'import { useState, useEffect }'
        )

    # ── 2. Insert `const [loading, setLoading] = useState(true);` ──────────
    # Find the export default function or const component declaration
    # and inject after the opening brace + any existing useState/const lines

    # Pattern: find first useState or the first line after the opening { of the component
    # Strategy: insert after the last existing useState line in the component,
    # or after the opening brace if no useState exists.

    # Find the component function body start
    # Match: export default function Foo() { OR export default function Foo(props...) {
    comp_func_pattern = re.compile(
        r'(export default function \w+[^{]*\{)',
        re.MULTILINE
    )
    # Also handle arrow function components
    comp_arrow_pattern = re.compile(
        r'(export default function \w+[^{]*\{|const \w+ = \([^)]*\) =>\s*\{)',
        re.MULTILINE
    )

    # Find where to insert loading state
    # Look for existing useState declarations to insert after the last one
    use_state_decl_pattern = re.compile(
        r'^( {2}|\t)const \[[^\]]+\] = useState[^;]+;',
        re.MULTILINE
    )

    matches = list(use_state_decl_pattern.finditer(content))

    loading_decl = "  const [loading, setLoading] = useState(true);\n"

    if matches:
        # Insert after the last useState declaration
        last_match = matches[-1]
        insert_pos = last_match.end()
        content = content[:insert_pos] + "\n" + loading_decl + content[insert_pos:]
    else:
        # Insert after the opening { of the export default function
        func_match = comp_func_pattern.search(content)
        if func_match:
            insert_pos = func_match.end()
            content = content[:insert_pos] + "\n" + loading_decl + content[insert_pos:]
        else:
            # Can't find insertion point, skip
            return False

    # ── 3. Add .finally(() => setLoading(false)) to useEffect ──────────────
    # Find useEffect calls and add finally to the promise chain or at the end

    # Pattern A: Promise.allSettled(...).then(...) — add .finally
    content = re.sub(
        r'(Promise\.allSettled\([^)]+\)\.then\([^}]+\})\s*\)',
        lambda m: m.group(0).rstrip(')') + '\n      .finally(() => setLoading(false))',
        content,
        count=0,
        flags=re.DOTALL
    )

    # Pattern B: apiFetch(...).then(...).catch(...) — add .finally before ;
    # Pattern C: fetch(...).then(...) — add .finally

    # Generic approach: find useEffect(() => { ... }, []); blocks
    # and add setLoading(false) call at end if not present
    # We'll use a simpler targeted approach:

    # Find useEffect blocks and inject setLoading(false) before the closing }, []);
    # Strategy: find `}, []);` or `}, [refreshKey]);` etc. at end of useEffect
    # and insert setLoading(false) before it

    # Actually the cleanest approach: find Promise.allSettled chains and add .finally,
    # or find the useEffect body and add setLoading(false) call

    # Approach: look for useEffect(() => { ... and find the fetch/apiFetch calls
    # Add .finally(() => setLoading(false)) to each top-level promise in useEffect

    # Simpler: after the .then( block closes, add .finally
    # Let's handle common patterns:

    # Pattern: apiFetch(...)\n      .then(...)\n    ); — add .finally
    def add_finally_to_apifetch(m):
        s = m.group(0)
        if 'finally' in s:
            return s
        # Add .finally before the trailing );
        s = re.sub(r'\)\s*;(\s*\n\s*\})', r').finally(() => setLoading(false));\n\1', s, count=1)
        return s

    # Handle Promise.allSettled with .then that doesn't already have .finally
    def add_finally_to_promise(m):
        s = m.group(0)
        if 'finally' in s:
            return s
        # Find the end of .then(...) and add .finally
        # The pattern ends with );
        s = re.sub(r'(\}\s*\)\s*);(\s*\n)', r'\1\n      .finally(() => setLoading(false));\2', s, count=1)
        return s

    # Find useEffect blocks
    use_effect_pattern = re.compile(
        r'useEffect\(\(\)\s*=>\s*\{(.+?)\},\s*\[[^\]]*\]\s*\);',
        re.DOTALL
    )

    def process_use_effect(m):
        body = m.group(1)
        if 'setLoading' in body or 'finally' in body:
            return m.group(0)

        # Add setLoading(false) to common patterns
        # Pattern 1: Promise.allSettled(...).then(...)
        if 'Promise.allSettled' in body:
            body = re.sub(
                r'(\.then\((?:[^}]|\{[^}]*\})*?\})\s*\)',
                lambda mm: mm.group(0) + '\n      .finally(() => setLoading(false))',
                body,
                count=1,
                flags=re.DOTALL
            )
        # Pattern 2: apiFetch or fetch call with .then
        elif re.search(r'apiFetch|fetch\(', body):
            # Add setLoading(false) before the closing of useEffect body
            body = body.rstrip()
            if not body.endswith('setLoading(false);'):
                body += '\n    setLoading(false);'
        else:
            # Just add setLoading(false) at end
            body = body.rstrip()
            body += '\n    setLoading(false);'

        return f'useEffect(() => {{{body}\n  }}, {m.group(0)[m.group(0).rfind("},"):]}'

    content = use_effect_pattern.sub(process_use_effect, content)

    # ── 4. Inject skeleton return before the main return statement ──────────
    # Find "return (" or "return(" that's the component's main return
    # It should be indented with 2 spaces (top-level in function body)

    # We need to inject the loading check before the first `  return (` in the component
    # Find the export default function body

    # Pattern: `  return (` at 2-space indent (the component's render return)
    main_return_pattern = re.compile(r'^  return \(', re.MULTILINE)
    return_match = main_return_pattern.search(content)

    if return_match:
        insert_pos = return_match.start()
        content = content[:insert_pos] + SKELETON_RETURN + content[insert_pos:]
    else:
        # Try `  return(` without space
        main_return_pattern2 = re.compile(r'^  return\(', re.MULTILINE)
        return_match2 = main_return_pattern2.search(content)
        if return_match2:
            insert_pos = return_match2.start()
            content = content[:insert_pos] + SKELETON_RETURN + content[insert_pos:]

    if content == original:
        return False

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return True


def main():
    files = [
        os.path.join(PAGES_DIR, f)
        for f in os.listdir(PAGES_DIR)
        if f.endswith(".tsx")
    ]

    fixed = []
    skipped = []
    errors = []

    for filepath in sorted(files):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            if not needs_fix(content):
                skipped.append(filepath)
                continue
            result = fix_file(filepath)
            if result:
                fixed.append(filepath)
                print(f"  FIXED: {os.path.basename(filepath)}")
            else:
                skipped.append(filepath)
        except Exception as e:
            errors.append((filepath, str(e)))
            print(f"  ERROR: {os.path.basename(filepath)}: {e}")

    print(f"\nDone: {len(fixed)} fixed, {len(skipped)} skipped, {len(errors)} errors")
    if errors:
        for f, e in errors:
            print(f"  ERROR in {f}: {e}")

if __name__ == "__main__":
    main()
