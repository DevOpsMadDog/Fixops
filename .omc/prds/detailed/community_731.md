# PRD — Community 731: Bash Syntax Classification Header (syntax.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Define character-class macros (shellmeta, shellblank, shellquote, etc.) and syntax-table arrays used by the bash-5.1 lexer, enabling correct tokenisation of shell scripts executed by ALDECI's automation layer.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/syntax.h`
- Graph community: 731 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[syntax.h] -->|defines| B[syntax class macros]
    B --> C[bash-5.1 syntax.c / y.tab.c lexer]
    C --> D[Shell tokenisation in ALDECI script-runner]
```

---

## Source Files

- `bash-5.1/syntax.h`

**Graph node label (truncated):** `syntax.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/syntax.h:L1 – 'Syntax definitions for the shell'; Defines for use by mksyntax.c

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 731 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/syntax.c`
- `bash-5.1/support/mksyntax.c`

---

## Acceptance Criteria

- [ ] bash-5.1 lexer compiles cleanly; GPLv3 preserved

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
