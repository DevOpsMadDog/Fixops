# PRD — Community 761: Bash Command-Hash-Table Header (hashcmd.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Declare the command-hashing table functions (remember_in_command_table, find_hashed_filename) for bash-5.1, providing O(1) PATH lookup caching for frequently-invoked security tools in ALDECI scripts.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/hashcmd.h`
- Graph community: 761 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[hashcmd.h] -->|declares| B[remember_in_command_table / find_hashed_filename]
    B --> C[bash-5.1 hashcmd.c]
    C --> D[O(1) command-lookup cache in ALDECI script-runner]
```

---

## Source Files

- `bash-5.1/hashcmd.h`

**Graph node label (truncated):** `hashcmd.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/hashcmd.h – command hash table declarations

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 761 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/hashcmd.c`
- `bash-5.1/hashlib.h`

---

## Acceptance Criteria

- [ ] Repeated invocations of same binary skip PATH rescan

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
