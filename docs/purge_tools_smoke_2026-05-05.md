---
date: 2026-05-05
author: qa-engineer
branch: features/intermediate-stage
commit-under-test: 3eb988a0
---

# Purge Tools Idempotency Smoke Test

Run against `suite-ui/aldeci-ui-new/src` after the App.tsx cleanup wave.

| Script | Result | Lines changed | Recommendation |
|--------|--------|---------------|----------------|
| `purge_dead_lazy_imports.py` | IDEMPOTENT | 0 | KEEP |
| `purge_dead_hub_imports.py` | IDEMPOTENT | 0 | KEEP |
| `purge_all_dead_imports.py` | IDEMPOTENT | 0 | KEEP |
| `purge_empty_lazy_blocks.py` | IDEMPOTENT | 0 | KEEP |
| `fix_orphaned_test_describes.py` | **VIOLATION** | 24 | **FIX** |

## Violation detail — fix_orphaned_test_describes.py

Files mutated on second run (auto-reverted):
- `src/__tests__/settings-auth.test.tsx` — 14 replacements
- `src/__tests__/ai.test.tsx` — 10 replacements

Root cause: the script's "context window" check looks only 5 lines back for
`const P =`. Both files declare `const P = (() => null) as any` at top-of-file
scope (lines 21 and 16 respectively), far above the `renderPage(<P />)` call
sites. Individual `it()` blocks also reassign `const P` via dynamic import
inside async scope. The 5-line window misses both, producing false positives on
every subsequent run — the script will keep replacing `<P />` indefinitely.

## Action required

`fix_orphaned_test_describes.py` must be fixed before re-use: extend the
context search to the full file scope (check for any `const P` anywhere in the
file, not just the 5 preceding lines). Mark as **DO NOT RUN** until patched.
Scripts 1-4 are safe to re-run at any time.
