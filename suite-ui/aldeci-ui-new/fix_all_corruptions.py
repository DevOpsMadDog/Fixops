#!/usr/bin/env python3
"""
Fix all corruption types introduced by previous loading-state scripts.

Corruption types:
  A) const [loading] inserted inside useState<...>({ object literal
     BEFORE: useState<T>({
               const [loading, setLoading] = useState(true);
                 stats: null, ...
     AFTER:  useState<T>({
               stats: null, ...
             and insert const [loading...] properly before the next useState or component open

  B) setLoading(false); embedded inside JSX attribute value
     BEFORE: value={stats.total_endpoints\n    setLoading(false);}
     AFTER:  value={stats.total_endpoints}

  D) setLoading(false); inside useEffect close: fetchData();\n    setLoading(false);}, [
     BEFORE: fetchData();\n    setLoading(false);}, []);
     AFTER:  fetchData();}, []);
     (already handled by fix_loading_final, but some remain)

  E) const [loading] inserted inside generic type argument }>({
     Same as A but slightly different regex

All fixes preserve the loading state declaration — just move it to the right place.
"""

import os
import re
import sys

PAGES_DIR = "/Users/devops.ai/fixops/Fixops/suite-ui/aldeci-ui-new/src/pages"


def fix_type_b(content: str) -> str:
    """Remove setLoading(false); embedded inside JSX attribute values."""
    # Pattern: someAttr={expr\n    setLoading(false);}  rest_of_line
    # The setLoading was inserted before the } closing a JSX expression
    # Remove: \n    setLoading(false); when followed by } and more JSX
    result = re.sub(
        r'\n\s+setLoading\(false\);(\})',
        r'\1',
        content
    )
    return result


def fix_type_d(content: str) -> str:
    """Remove setLoading(false); from useEffect close: }, []) patterns."""
    result = re.sub(
        r' ?\n    setLoading\(false\);(?=\s*})',
        '',
        content
    )
    return result


def fix_type_a_e(content: str) -> str:
    """
    Remove const [loading, setLoading] = useState(true); from inside
    useState<...>({ ... }) object literals, and ensure it's placed correctly.

    Pattern:
      useState<T>({
        const [loading, setLoading] = useState(true);   ← WRONG: inside object
          prop: val,
      })

    Fix: remove it from inside the object. The loading state should already
    exist elsewhere if it was inserted twice, or needs to be added before
    the first useState properly.
    """
    # Remove const [loading...] that appears inside an object literal
    # (indented with 2 spaces inside a useState({ call)
    # Pattern: after `useState<...>({` or `useState({`, line starting with `  const [loading`
    result = re.sub(
        r'(useState[^(]*\(\{)\n  const \[loading, setLoading\] = useState\(true\);\n',
        r'\1\n',
        content
    )
    # Also fix when inserted right before object properties with extra indent
    result = re.sub(
        r'(useState[^(]*\(\{)\n  const \[loading, setLoading\] = useState\(true\);\n    ',
        r'\1\n    ',
        result
    )
    return result


def ensure_loading_state_exists(content: str, comp_start: int) -> str:
    """
    If const [loading, setLoading] = useState(true) doesn't exist in component,
    add it after the last useState declaration.
    """
    comp_body = content[comp_start:]

    if 'const [loading, setLoading] = useState(true)' in comp_body:
        return content  # already there

    loading_decl = "  const [loading, setLoading] = useState(true);\n"

    # Find last useState in component body
    use_state_pattern = re.compile(r'^ {2}const \[[^\]]+\] = useState[^\n]+\n', re.MULTILINE)
    matches = list(use_state_pattern.finditer(comp_body))

    if matches:
        last = matches[-1]
        abs_pos = comp_start + last.end()
        return content[:abs_pos] + loading_decl + content[abs_pos:]
    else:
        # Insert after opening { of function
        brace_pos = content.find('{', comp_start)
        if brace_pos != -1:
            return content[:brace_pos + 1] + "\n" + loading_decl + content[brace_pos + 1:]

    return content


def ensure_skeleton_exists(content: str, comp_start: int) -> str:
    """Ensure the skeleton return block exists before the main return."""
    comp_body = content[comp_start:]

    if 'animate-pulse' in comp_body:
        return content  # already has skeleton

    skeleton = """\
  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

"""
    main_return = re.search(r'^  return \(', comp_body, re.MULTILINE)
    if main_return:
        abs_pos = comp_start + main_return.start()
        return content[:abs_pos] + skeleton + content[abs_pos:]

    return content


def ensure_finally_in_useeffect(content: str, comp_start: int) -> str:
    """Ensure the first useEffect has setLoading(false) in some form."""
    comp_body = content[comp_start:]

    if '.finally(() => setLoading(false))' in comp_body:
        return content

    # Check if standalone setLoading(false) is in a useEffect
    ue_match = re.search(r'\buseEffect\(', comp_body)
    if not ue_match:
        return content

    # Find useEffect outer parens
    outer_open = comp_start + ue_match.end() - 1
    depth = 0
    i = outer_open
    while i < len(content):
        if content[i] == '(':
            depth += 1
        elif content[i] == ')':
            depth -= 1
            if depth == 0:
                break
        i += 1
    outer_close = i
    ue_block = content[comp_start + ue_match.start():outer_close + 1]

    if 'setLoading(false)' in ue_block:
        return content  # has it

    # Find callback brace
    cb_open = content.find('{', outer_open + 1)
    if cb_open == -1 or cb_open >= outer_close:
        return content

    depth = 0
    i = cb_open
    while i < len(content):
        if content[i] == '{':
            depth += 1
        elif content[i] == '}':
            depth -= 1
            if depth == 0:
                break
        i += 1
    cb_close = i
    callback_body = content[cb_open + 1:cb_close]

    def find_paren_end(text, start):
        d = 0
        i = start
        while i < len(text):
            if text[i] == '(':
                d += 1
            elif text[i] == ')':
                d -= 1
                if d == 0:
                    return i
            i += 1
        return -1

    if 'Promise.allSettled' in callback_body:
        m = re.search(r'\.then\(', callback_body)
        if m:
            p_open = cb_open + 1 + m.end() - 1
            p_close = find_paren_end(content, p_open)
            if p_close != -1:
                return content[:p_close + 1] + "\n      .finally(() => setLoading(false))" + content[p_close + 1:]

    if 'fetchData()' in callback_body or 'loadData()' in callback_body:
        # Add to the fetch function itself
        fn_name = 'fetchData' if 'fetchData()' in callback_body else 'loadData'
        fn_match = re.search(rf'const {fn_name}\s*=\s*\(\)\s*=>\s*\{{', comp_body)
        if fn_match:
            fn_brace = comp_start + fn_match.end() - 1
            depth = 0
            i = fn_brace
            while i < len(content):
                if content[i] == '{':
                    depth += 1
                elif content[i] == '}':
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            fn_close = i
            fn_body = content[fn_brace + 1:fn_close]

            # Add .finally to last .then/.catch/.finally in fn_body
            chain = list(re.finditer(r'\.(then|catch|finally)\(', fn_body))
            if chain:
                last_c = chain[-1]
                p_open = fn_brace + 1 + last_c.end() - 1
                p_close = find_paren_end(content, p_open)
                if p_close != -1:
                    return content[:p_close + 1] + "\n      .finally(() => setLoading(false))" + content[p_close + 1:]

        # Fallback: add setLoading before cb_close
        return content[:cb_close] + "\n    setLoading(false);" + content[cb_close:]

    chain = list(re.finditer(r'\.(then|catch)\(', callback_body))
    if chain:
        last_c = chain[-1]
        p_open = cb_open + 1 + last_c.end() - 1
        p_close = find_paren_end(content, p_open)
        if p_close != -1:
            return content[:p_close + 1] + "\n      .finally(() => setLoading(false))" + content[p_close + 1:]

    return content[:cb_close] + "\n    setLoading(false);" + content[cb_close:]


def fix_file(filepath: str, dry_run: bool = False) -> tuple[bool, str]:
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    original = content

    comp_match = re.search(r'^export default function \w+', content, re.MULTILINE)
    if not comp_match:
        return False, "no export default function"
    comp_start = comp_match.start()

    # Fix Type A/E: loading decl inside useState object
    content = fix_type_a_e(content)

    # Fix Type B: setLoading inside JSX attribute
    content = fix_type_b(content)

    # Fix Type D: setLoading before useEffect closing brace
    content = fix_type_d(content)

    # Now ensure loading state, skeleton, and finally all exist correctly
    # Re-find comp_start (it didn't move)
    if 'setLoading' in content[comp_start:]:  # only for files that have setLoading
        content = ensure_loading_state_exists(content, comp_start)
        content = ensure_skeleton_exists(content, comp_start)
        content = ensure_finally_in_useeffect(content, comp_start)

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
