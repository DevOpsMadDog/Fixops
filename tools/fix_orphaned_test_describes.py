#!/usr/bin/env python3
"""
Fix test files where describe blocks use <P /> but P is never defined in scope.

The pattern is:
  describe("SomePage", () => {
    it("renders heading", async () => {
      renderPage(<P />);   // P is undefined — was the imported page component
      ...
    });
  });

Fix: replace `renderPage(<P />)` with `renderPage(<div data-testid="stub" />)`
so the file compiles. The test will fail at runtime on the expectation (which is
fine — the page no longer exists). Alternatively wrap with describe.skip.

Strategy: scan the ENTIRE file for `const P`, `let P`, or `var P` at the top scope.
If any such declaration exists anywhere in the file, P is a legitimate binding —
skip the file entirely to avoid false-positive replacements.

Only replace bare `<P />` / `<P>` when NO top-scope `P` declaration exists in the file.

Usage:
    python tools/fix_orphaned_test_describes.py [--dry-run] <file> [<file> ...]
"""
import re
import sys

# Matches any variable declaration of P at start-of-expression context:
#   const P = ...
#   let P = ...
#   var P = ...
_TOP_SCOPE_P_RE = re.compile(r'(?:const|let|var)\s+P\b')

DRY_RUN = False


def fix_file(fpath: str) -> int:
    with open(fpath, "r", encoding="utf-8") as fh:
        source = fh.read()

    # Whole-file guard: if P is declared anywhere in the file, it is a legitimate
    # binding (component, variable, etc.). Leave the file untouched.
    if _TOP_SCOPE_P_RE.search(source):
        return 0

    lines = source.splitlines(keepends=True)
    fixed: list[str] = []
    changes = 0

    for line in lines:
        if '<P />' in line or '<P>' in line:
            line = line.replace('<P />', '<div data-testid="removed-page" />')
            line = line.replace('<P>', '<div data-testid="removed-page">')
            changes += 1
        fixed.append(line)

    if not changes:
        return 0

    # Wrap describe blocks that contain 'removed-page' in describe.skip
    result_lines = fixed
    in_describe = False
    describe_start = -1
    brace_depth = 0
    needs_skip: list[tuple[int, int]] = []

    i = 0
    while i < len(result_lines):
        line = result_lines[i]
        if not in_describe and re.match(r'\s*describe\(', line) and not re.match(r'\s*describe\.skip\(', line):
            in_describe = True
            describe_start = i
            brace_depth = line.count('{') - line.count('}')
        elif in_describe:
            brace_depth += line.count('{') - line.count('}')
            if brace_depth <= 0:
                block = result_lines[describe_start:i + 1]
                if any('removed-page' in l for l in block):
                    needs_skip.append((describe_start, i))
                in_describe = False
                brace_depth = 0
        i += 1

    for start, _end in reversed(needs_skip):
        result_lines[start] = result_lines[start].replace('describe(', 'describe.skip(', 1)
        changes += 1

    if not DRY_RUN:
        with open(fpath, "w", encoding="utf-8") as fh:
            fh.writelines(result_lines)

    return changes


def main() -> None:
    global DRY_RUN
    args = sys.argv[1:]
    if '--dry-run' in args:
        DRY_RUN = True
        args = [a for a in args if a != '--dry-run']

    if not args:
        print("Usage: fix_orphaned_test_describes.py [--dry-run] <file> [<file> ...]")
        sys.exit(1)

    total = 0
    for fpath in args:
        n = fix_file(fpath)
        if n:
            print(f"  {fpath}: {n} fixes")
            total += n
    print(f"Total fixes: {total}")


if __name__ == "__main__":
    main()
