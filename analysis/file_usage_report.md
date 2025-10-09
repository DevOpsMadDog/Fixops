# Repository File Usage Inventory

This report is generated automatically by ``scripts/generate_file_usage_inventory.py``.

## Totals by status

| Status | Files | Lines |
| --- | ---: | ---: |
| needed | 297 | 55728 |
| supporting | 191 | 47073 |
| not_needed | 36 | 1543 |

Statuses marked **not_needed** are safe to exclude from the production-critical deployment
because they either represent generated artefacts or demo fixtures. Supporting files are kept
to maintain documentation and analysis quality but can be reviewed if footprint reductions
are required.

Detailed entries live in ``analysis/file_usage_summary.csv`` with columns for the rule
source and rationale behind each classification. Adjust ``analysis/file_usage_overrides.json``
to enforce custom decisions.
