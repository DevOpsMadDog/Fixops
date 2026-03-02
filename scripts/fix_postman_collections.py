#!/usr/bin/env python3
"""
Fix ALdeci Postman collection issues:
  1. Normalize URL variable names to {{apiBase}}:
       {{baseurl}} (lowercase u) — task-reported issue in collections 4/5
       {{baseUrl}} (capital U)   — found in collections 1/2
       {{base_url}}              — found in collection 7
  2. Fix truncated test scripts (missing closing braces / parens)
       Pattern A: function() { ... }  — missing closing }); at end
       Pattern B: () => ...           — arrow function missing closing )
"""

import json
import os
import sys

COLLECTION_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "suite-integrations", "postman", "enterprise"
)

COLLECTIONS = [
    "ALdeci-1-MissionControl.postman_collection.json",
    "ALdeci-2-Discover.postman_collection.json",
    "ALdeci-3-Validate.postman_collection.json",
    "ALdeci-4-Remediate.postman_collection.json",
    "ALdeci-5-Comply.postman_collection.json",
    "ALdeci-6-PersonaWorkflows.postman_collection.json",
    "ALdeci-7-Scanners-OSS-AutoFix.postman_collection.json",
]

# Which URL variable patterns to replace → target
URL_VAR_REPLACEMENTS = [
    ("{{baseurl}}", "{{apiBase}}"),   # lowercase u — reported in task
    ("{{baseUrl}}", "{{apiBase}}"),   # capital U — found in collections 1/2
    ("{{base_url}}", "{{apiBase}}"),  # underscore — found in collection 7
]

fix_log = []


# ---------------------------------------------------------------------------
# URL variable fix — string-level replacement in the raw JSON text
# ---------------------------------------------------------------------------

def fix_url_variables(raw_text, filename):
    """Replace non-standard URL variables with {{apiBase}} in the raw JSON."""
    total_replacements = 0
    for old, new in URL_VAR_REPLACEMENTS:
        count = raw_text.count(old)
        if count:
            raw_text = raw_text.replace(old, new)
            total_replacements += count
            fix_log.append(
                f"[URL-VAR] {filename}: replaced {count}x '{old}' → '{new}'"
            )
    return raw_text, total_replacements


# ---------------------------------------------------------------------------
# Test-script fix — operates on the parsed JSON structure
# ---------------------------------------------------------------------------

def fix_exec_lines(exec_lines, request_name):
    """
    Detect and fix truncated JavaScript test scripts.

    Two truncation patterns found in the collections:

    Pattern A — traditional function syntax:
        pm.test('...', function() { pm.expect(...);
        (missing closing  });  )

    Pattern B — arrow function syntax (collection 7):
        pm.test('...', () => pm.expect(...);
        (missing closing  );  — the outer pm.test call is never closed)

    Pattern C — multi-line where the FIRST pm.test is left open:
        pm.test('...', function() { pm.expect(...);    ← no closing })
        pm.test('...', function() {
            ...
        });

    For Pattern C the first test call needs  });  inserted before the second
    pm.test line.
    """
    if not exec_lines:
        return exec_lines, False

    js = "\n".join(exec_lines)

    brace_diff = js.count("{") - js.count("}")
    paren_diff = js.count("(") - js.count(")")

    if brace_diff == 0 and paren_diff == 0:
        return exec_lines, False  # nothing to fix

    new_lines = list(exec_lines)

    # ---- Pattern B: arrow function, only paren imbalance (no brace imbalance)
    # e.g.  pm.test('...', () => pm.expect(...);
    # Needs:  });  appended
    if brace_diff == 0 and paren_diff > 0:
        last = new_lines[-1]
        # The last line ends with );  but is missing the outer  )
        # Convert  ...);  →  ...));
        if last.rstrip().endswith(");"):
            new_lines[-1] = last.rstrip()[:-1] + ");"
            fix_log.append(
                f"[SCRIPT-B] '{request_name}': appended extra ')' to last line"
            )
            # Re-check after fix
            js2 = "\n".join(new_lines)
            if js2.count("(") == js2.count(")"):
                return new_lines, True

    # ---- Pattern A / C: brace imbalance (function() { ... missing });)
    if brace_diff > 0:
        # Check if the last line of new_lines (after possible Pattern B fix)
        # ends the last pm.test properly
        last = new_lines[-1].rstrip()

        # Sub-pattern C: there is a later, properly-closed pm.test but an
        # earlier pm.test was left open.  We need to insert  });  just before
        # the SECOND pm.test line.
        #
        # Heuristic: if the final line of the script IS  });  then the last
        # pm.test is properly closed, meaning the open brace is from an earlier
        # call.  Find the second pm.test and insert  });  before it.
        if last == "});":
            # Find the line index of the second occurrence of pm.test(
            pm_test_indices = [
                i for i, ln in enumerate(new_lines)
                if ln.lstrip().startswith("pm.test(")
            ]
            if len(pm_test_indices) >= 2:
                insert_before = pm_test_indices[1]
                new_lines.insert(insert_before, "});")
                fix_log.append(
                    f"[SCRIPT-C] '{request_name}': inserted '}}); ' before "
                    f"line {insert_before} to close first pm.test"
                )
                return new_lines, True

        # Sub-pattern A: the entire script is ONE pm.test call on one line,
        # or the last line doesn't close it.  Append  });
        closing = "});" if brace_diff == 1 else ("});" * brace_diff)
        new_lines.append(closing)
        fix_log.append(
            f"[SCRIPT-A] '{request_name}': appended '{closing}' "
            f"(brace_diff={brace_diff})"
        )
        return new_lines, True

    return new_lines, False


def walk_and_fix_scripts(node, fixes_count):
    """Recursively walk the collection JSON and fix test scripts in-place."""
    if isinstance(node, dict):
        if "event" in node:
            request_name = node.get("name", "unknown")
            for ev in node["event"]:
                if (
                    isinstance(ev, dict)
                    and ev.get("listen") == "test"
                    and "script" in ev
                ):
                    script = ev["script"]
                    exec_lines = script.get("exec", [])
                    fixed_lines, changed = fix_exec_lines(exec_lines, request_name)
                    if changed:
                        script["exec"] = fixed_lines
                        fixes_count[0] += 1

        for k, v in node.items():
            if k != "event":
                walk_and_fix_scripts(v, fixes_count)

    elif isinstance(node, list):
        for item in node:
            walk_and_fix_scripts(item, fixes_count)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def process_collection(filepath):
    filename = os.path.basename(filepath)
    print(f"\n{'='*60}")
    print(f"Processing: {filename}")
    print(f"{'='*60}")

    with open(filepath, "r", encoding="utf-8") as fh:
        raw = fh.read()

    # Step 1 — fix URL variables (string-level)
    raw_fixed, url_fix_count = fix_url_variables(raw, filename)

    # Step 2 — parse and fix test scripts (structure-level)
    data = json.loads(raw_fixed)
    script_fixes = [0]
    walk_and_fix_scripts(data, script_fixes)

    total_fixes = url_fix_count + script_fixes[0]

    if total_fixes == 0:
        print("  No changes needed.")
        return 0

    # Write back with consistent formatting
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    print(f"  URL-var fixes: {url_fix_count}")
    print(f"  Script fixes:  {script_fixes[0]}")
    print(f"  Total fixes:   {total_fixes}")
    return total_fixes


def verify_collection(filepath):
    """Verify the fixed collection has no remaining issues."""
    filename = os.path.basename(filepath)
    with open(filepath, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    raw = open(filepath).read()

    issues = []

    # Check residual non-standard URL vars
    for old, _ in URL_VAR_REPLACEMENTS:
        count = raw.count(old)
        if count:
            issues.append(f"  RESIDUAL URL-VAR: {count}x '{old}' still present")

    # Check script balance
    broken_scripts = []

    def check_scripts(node):
        if isinstance(node, dict):
            if "event" in node:
                name = node.get("name", "?")
                for ev in node["event"]:
                    if isinstance(ev, dict) and ev.get("listen") == "test":
                        lines = ev.get("script", {}).get("exec", [])
                        js = "\n".join(lines)
                        bd = js.count("{") - js.count("}")
                        pd = js.count("(") - js.count(")")
                        if bd != 0 or pd != 0:
                            broken_scripts.append(
                                f"{name} (brace_diff={bd}, paren_diff={pd})"
                            )
            for k, v in node.items():
                if k != "event":
                    check_scripts(v)
        elif isinstance(node, list):
            for item in node:
                check_scripts(item)

    check_scripts(data)

    if broken_scripts:
        for s in broken_scripts:
            issues.append(f"  STILL-BROKEN script: {s}")

    if issues:
        print(f"\nVERIFY FAIL — {filename}:")
        for i in issues:
            print(i)
        return False
    else:
        print(f"  VERIFY OK — {filename}")
        return True


def main():
    grand_total = 0
    all_ok = True

    for name in COLLECTIONS:
        filepath = os.path.join(COLLECTION_DIR, name)
        if not os.path.exists(filepath):
            print(f"WARNING: file not found: {filepath}")
            continue
        fixes = process_collection(filepath)
        grand_total += fixes

    print(f"\n{'='*60}")
    print("VERIFICATION PASS")
    print(f"{'='*60}")
    for name in COLLECTIONS:
        filepath = os.path.join(COLLECTION_DIR, name)
        if not os.path.exists(filepath):
            continue
        ok = verify_collection(filepath)
        if not ok:
            all_ok = False

    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"Total fixes applied: {grand_total}")
    print()
    for entry in fix_log:
        print(f"  {entry}")

    if all_ok:
        print("\nAll collections pass verification.")
        return 0
    else:
        print("\nSome collections still have issues — see above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
