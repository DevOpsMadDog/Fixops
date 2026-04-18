#!/usr/bin/env python3
"""
Fix remaining issues:
1. Duplicate const [loading, setLoading] declarations (remove the extra useState(true))
2. Remaining Type D: setLoading(false) before useEffect close }, [])
3. Ensure .finally(() => setLoading(false)) exists in useEffect
"""
import os, re, sys

PAGES_DIR = "/Users/devops.ai/fixops/Fixops/suite-ui/aldeci-ui-new/src/pages"

def find_matching_paren(text, start):
    d = 0
    i = start
    while i < len(text):
        if text[i] == '(': d += 1
        elif text[i] == ')':
            d -= 1
            if d == 0: return i
        i += 1
    return -1

def find_matching_brace(text, start):
    d = 0
    i = start
    while i < len(text):
        if text[i] == '{': d += 1
        elif text[i] == '}':
            d -= 1
            if d == 0: return i
        i += 1
    return -1

def fix_file(filepath, dry_run=False):
    with open(filepath) as f:
        content = f.read()
    original = content

    comp_match = re.search(r'^export default function \w+', content, re.MULTILINE)
    if not comp_match:
        return False, "no component"
    comp_start = comp_match.start()

    # Fix 1: Remove duplicate const [loading, setLoading] = useState(true)
    # when useState(false) already exists for loading in the same component
    comp_body = content[comp_start:]
    false_matches = list(re.finditer(r'const \[loading, setLoading\] = useState\(false\)', comp_body))
    true_matches = list(re.finditer(r'const \[loading, setLoading\] = useState\(true\)', comp_body))

    if false_matches and true_matches:
        # Remove the useState(true) line - it's the duplicate added by our script
        # Find the full line including newline
        for m in reversed(true_matches):
            abs_start = comp_start + m.start()
            # Find start of line
            line_start = content.rfind('\n', 0, abs_start) + 1
            # Find end of line
            line_end = content.find('\n', abs_start) + 1
            content = content[:line_start] + content[line_end:]

    # Fix 2: Remove Type D - setLoading(false); before useEffect }, [
    # Pattern: \n  \n    setLoading(false);}, [  OR  \n    setLoading(false);}, [
    content = re.sub(r'\n\s*\n    setLoading\(false\);(})', r'\n  \1', content)
    content = re.sub(r' ?\n    setLoading\(false\);(?=\s*})', '', content)

    # Fix 3: Ensure useEffect has .finally or setLoading(false) properly
    # Re-find comp_start (unchanged)
    comp_body2 = content[comp_start:]
    has_correct = (
        '.finally(() => setLoading(false))' in comp_body2 or
        re.search(r'\n    setLoading\(false\);\n', comp_body2) or
        re.search(r'setLoading\(false\)', comp_body2)  # any form in component
    )

    if 'setLoading' in comp_body2 and not has_correct:
        # Add .finally to first useEffect
        ue_match = re.search(r'\buseEffect\(', comp_body2)
        if ue_match:
            outer_open = comp_start + ue_match.end() - 1
            outer_close = find_matching_paren(content, outer_open)
            if outer_close != -1:
                cb_open = content.find('{', outer_open + 1)
                if cb_open != -1 and cb_open < outer_close:
                    cb_close = find_matching_brace(content, cb_open)
                    if cb_close != -1:
                        callback_body = content[cb_open + 1:cb_close]

                        if 'Promise.allSettled' in callback_body:
                            m = re.search(r'\.then\(', callback_body)
                            if m:
                                p_open = cb_open + 1 + m.end() - 1
                                p_close = find_matching_paren(content, p_open)
                                if p_close != -1:
                                    content = content[:p_close+1] + "\n      .finally(() => setLoading(false))" + content[p_close+1:]
                        elif re.search(r'(?:fetchData|loadData)\(\)', callback_body):
                            fn_name = re.search(r'(fetchData|loadData)\(\)', callback_body).group(1)
                            fn_match = re.search(rf'const {fn_name}\s*=\s*\(\)\s*=>\s*\{{', comp_body2)
                            if fn_match:
                                fn_brace = comp_start + fn_match.end() - 1
                                fn_close = find_matching_brace(content, fn_brace)
                                if fn_close != -1:
                                    fn_body = content[fn_brace+1:fn_close]
                                    chain = list(re.finditer(r'\.(then|catch|finally)\(', fn_body))
                                    if chain:
                                        last_c = chain[-1]
                                        p_open = fn_brace + 1 + last_c.end() - 1
                                        p_close = find_matching_paren(content, p_open)
                                        if p_close != -1:
                                            content = content[:p_close+1] + "\n      .finally(() => setLoading(false))" + content[p_close+1:]
                                    else:
                                        content = content[:fn_close] + "\n    setLoading(false);" + content[fn_close:]
                            else:
                                content = content[:cb_close] + "\n    setLoading(false);" + content[cb_close:]
                        else:
                            chain = list(re.finditer(r'\.(then|catch)\(', callback_body))
                            if chain:
                                last_c = chain[-1]
                                p_open = cb_open + 1 + last_c.end() - 1
                                p_close = find_matching_paren(content, p_open)
                                if p_close != -1:
                                    content = content[:p_close+1] + "\n      .finally(() => setLoading(false))" + content[p_close+1:]
                            else:
                                content = content[:cb_close] + "\n    setLoading(false);" + content[cb_close:]

    changed = content != original
    if changed and not dry_run:
        with open(filepath, 'w') as f:
            f.write(content)
    return changed, "fixed" if changed else "no change"

def main():
    dry_run = "--dry-run" in sys.argv
    target_files = [a for a in sys.argv[1:] if a != "--dry-run" and a.endswith(".tsx")]

    files = (
        [f if f.startswith("/") else os.path.join(PAGES_DIR, f) for f in target_files]
        if target_files else
        sorted(os.path.join(PAGES_DIR, f) for f in os.listdir(PAGES_DIR) if f.endswith(".tsx"))
    )

    fixed, skipped, errors = [], [], []
    for filepath in files:
        try:
            changed, desc = fix_file(filepath, dry_run)
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
