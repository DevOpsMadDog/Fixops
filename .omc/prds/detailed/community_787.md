# PRD — Community 787: Bash Object-Cache Include (ocache.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Define bash-5.1's object-cache macros (DECLARE_CACHE, CREATE_CACHE_ELEMENT) for allocation-pool reuse of frequently-created WORD_DESC and REDIRECT objects, reducing heap fragmentation in long-running ALDECI shell sessions.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/include/ocache.h`
- Graph community: 787 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[ocache.h] -->|defines| B[DECLARE_CACHE / CREATE_CACHE_ELEMENT macros]
    B --> C[bash-5.1 make_cmd.c / subst.c]
    C --> D[Reduced heap fragmentation in long ALDECI sessions]
```

---

## Source Files

- `bash-5.1/include/ocache.h`

**Graph node label (truncated):** `ocache.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/include/ocache.h – object-cache macro definitions

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 787 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/make_cmd.h`
- `bash-5.1/subst.h`

---

## Acceptance Criteria

- [ ] Memory usage stable over 10k command iterations in stress test

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
