# Dependabot Status Snapshot — 2026-05-04 night

**Audited at**: HEAD `2bd8b399` on `features/intermediate-stage`
**Audited by**: security-analyst agent, 2026-05-05

---

## TL;DR

| Layer | CVE count | Severity breakdown | Fix available |
|-------|-----------|-------------------|---------------|
| Python backend (`requirements.txt`) | **0** | — | N/A |
| Active frontend (`suite-ui/aldeci-ui-new/`) | **0** | — | N/A |
| Frozen legacy UI (`suite-ui/aldeci/`) | **DELETED** | directory does not exist on this branch | N/A — gone |

**Net live CVEs on `features/intermediate-stage`: 0 Python + 0 npm.**

---

## Scan Commands & Raw Output

```
pip-audit --requirement requirements.txt --format json
→ "No known vulnerabilities found"
→ PYTHON CVE COUNT: 0

cd suite-ui/aldeci-ui-new && npm audit --json
→ NPM CVE COUNT: 0
→ vulnerabilities: {total: 0}

ls suite-ui/aldeci
→ ls: No such file or directory  (confirmed deleted)
```

---

## Categorization

### Production code paths

| Path | Tool | Result |
|------|------|--------|
| `suite-api/`, `suite-core/`, `suite-attack/` (Python) | pip-audit | 0 CVEs |
| `suite-ui/aldeci-ui-new/` (React 19 + Vite 6) | npm audit | 0 CVEs |

### Dev-only / test-only
No separate dev-requirements file with known vulns. `pip-audit` scans the full `requirements.txt`; 0 findings regardless of prod/dev split.

### Frozen legacy UI
`suite-ui/aldeci/` does not exist on `features/intermediate-stage`. It was deleted in commit `5f415a1d` (113 files removed). The **125 Dependabot alerts** on `main` (2 critical / 47 high / 52 moderate / 24 low) are entirely attributable to this deleted directory's transitive `node_modules`. They will auto-close when this branch merges into `main`.

---

## Delta vs Prior Baseline (dependabot_triage_2026-05-05.md)

No change. Branch was already clean at `14929e98`; HEAD `2bd8b399` adds backend/route commits only — no new dependencies introduced.

---

## Action Required

None on `features/intermediate-stage`. The single unblock is:

> **Merge `features/intermediate-stage` → `main`** to close all 125 Dependabot alerts in one shot.

No individual CVE patching needed. No dependency upgrades needed on this branch.
