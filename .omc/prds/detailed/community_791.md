# PRD — Community 791: Bash Memory-Allocation Include (memalloc.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Define the low-level memory-allocation interface (ALLOC_BUFFER, RESIZE_BUFFER) for bash-5.1's word-expansion buffer management, preventing realloc-induced crashes in ALDECI's large-document word expansions.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/include/memalloc.h`
- Graph community: 791 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[memalloc.h] -->|defines| B[ALLOC_BUFFER / RESIZE_BUFFER]
    B --> C[bash-5.1 subst.c word-expansion buffers]
    C --> D[Safe buffer management for large expansions in ALDECI]
```

---

## Source Files

- `bash-5.1/include/memalloc.h`

**Graph node label (truncated):** `memalloc.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/include/memalloc.h – buffer allocation macros

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 791 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/xmalloc.h`

---

## Acceptance Criteria

- [ ] Word expansion of 64KB strings completes without heap corruption

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
