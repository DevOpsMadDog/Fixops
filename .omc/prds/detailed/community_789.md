# PRD — Community 789: Bash Multibyte-String Utilities Include (shmbutil.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Define multibyte-string utilities (IS_MBCHAR, MB_NEXTCHAR, etc.) for bash-5.1's Unicode-aware lexer, enabling ALDECI operators to use UTF-8 variable names and string values in automation scripts.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/include/shmbutil.h`
- Graph community: 789 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[shmbutil.h] -->|defines| B[IS_MBCHAR / MB_NEXTCHAR / MB_INVALIDCH]
    B --> C[bash-5.1 subst.c / bashline.c]
    C --> D[UTF-8 variable names and strings in ALDECI scripts]
```

---

## Source Files

- `bash-5.1/include/shmbutil.h`

**Graph node label (truncated):** `shmbutil.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/include/shmbutil.h – multibyte-string utility macros

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 789 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/subst.h`

---

## Acceptance Criteria

- [ ] UTF-8 variable names (e.g. résumé=test) handled without corruption

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
