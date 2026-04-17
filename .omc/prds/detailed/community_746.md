# PRD — Community 746: Bash Associative-Array Header (assoc.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Define the associative-array interface (HASH_TABLE reuse, assoc_create/copy/dispose/insert/reference) for bash-5.1's declare -A support, used in ALDECI automation scripts that map keys to values.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/assoc.h`
- Graph community: 746 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[assoc.h] -->|includes| B[stdc.h]
    A -->|declares| C[assoc_create / assoc_insert / assoc_reference]
    C --> D[bash-5.1 assoc.c]
    D --> E[declare -A in ALDECI scripts]
```

---

## Source Files

- `bash-5.1/assoc.h`

**Graph node label (truncated):** `assoc.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/assoc.h:L1 – 'definitions for the interface exported by assoc.c'; includes stdc.h

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 746 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/assoc.c`

---

## Acceptance Criteria

- [ ] declare -A map; map[key]=val; echo ${map[key]} works

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
