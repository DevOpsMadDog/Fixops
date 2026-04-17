# PRD — Community 739: Bash Programmable-Completion Header (pcomplete.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Define COMPSPEC struct and programmable-completion API for bash-5.1, enabling tab-completion in interactive ALDECI shell sessions when operators use the embedded bash runtime.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/pcomplete.h`
- Graph community: 739 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[pcomplete.h] -->|includes| B[stdc.h]
    A -->|defines| C[COMPSPEC struct]
    A -->|declares| D[programmable completion functions]
    D --> E[bash-5.1 pcomplete.c]
    E --> F[Tab-completion in interactive ALDECI shell]
```

---

## Source Files

- `bash-5.1/pcomplete.h`

**Graph node label (truncated):** `pcomplete.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/pcomplete.h:L1 – 'structure definitions and other stuff for programmable completion'; includes stdc.h

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 739 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/pcomplete.c`

---

## Acceptance Criteria

- [ ] complete -F works in interactive mode; GPLv3 preserved

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
