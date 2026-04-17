# PRD — Community 805: Bash Plural-Expression Header (plural-exp.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Declare the plural-expression evaluator (plural_eval, extract_plural_expression) for bash-5.1's ngettext() support, enabling grammatically-correct pluralisation in localised ALDECI shell error messages.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/lib/intl/plural-exp.h`
- Graph community: 805 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[plural-exp.h] -->|declares| B[plural_eval / extract_plural_expression]
    B --> C[bash-5.1 ngettext implementation]
    C --> D[Grammatically-correct plural messages in ALDECI locales]
```

---

## Source Files

- `bash-5.1/lib/intl/plural-exp.h`

**Graph node label (truncated):** `plural-exp.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/lib/intl/plural-exp.h – plural expression evaluator declarations

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 805 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/lib/intl/plural-exp.c`

---

## Acceptance Criteria

- [ ] ngettext('file','files',1) and ngettext('file','files',2) both correct

---

## Effort Estimate

**XS – vendor file; no modification required**

| Task | Points |
|------|--------|
| Understand file purpose | 1 |
| Verify vendored build compiles cleanly | 2 |
| CI build matrix validation | 2 |

---

## Status

**Stable**

> Vendored file. No ALDECI-side changes required. Only action: ensure bash-5.1 builds cleanly in CI and GPLv3 license headers are preserved.
