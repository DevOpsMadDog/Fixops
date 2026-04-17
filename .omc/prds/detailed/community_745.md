# PRD — Community 745: Bash Word-Substitution Header (subst.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Declare the externally visible substitution functions (word_split, command_substitute, parameter_brace_expand) from bash-5.1's subst.c, enabling $(), ${}, and $[] expansions in ALDECI automation scripts.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/subst.h`
- Graph community: 745 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[subst.h] -->|includes| B[stdc.h]
    A -->|declares| C[word substitution functions]
    C --> D[bash-5.1 subst.c]
    D --> E[Parameter / command substitution in ALDECI scripts]
```

---

## Source Files

- `bash-5.1/subst.h`

**Graph node label (truncated):** `subst.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/subst.h:L1 – 'Names of externally visible functions in subst.c'; includes stdc.h

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 745 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/subst.c`

---

## Acceptance Criteria

- [ ] $(cmd), ${var:-default}, $((expr)) all expand correctly

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
