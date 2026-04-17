# PRD — Community 782: Bash Union-Wait Include (unionwait.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Provide the union wait type for BSD-style waitpid() compatibility in bash-5.1, ensuring ALDECI's script-runner correctly handles child exit status on legacy UNIX platforms in the CI matrix.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/include/unionwait.h`
- Graph community: 782 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[unionwait.h] -->|union wait| B[BSD-style wait status]
    B --> C[bash-5.1 jobs.c on BSD targets]
    C --> D[Correct exit-status handling in ALDECI CI]
```

---

## Source Files

- `bash-5.1/include/unionwait.h`

**Graph node label (truncated):** `unionwait.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/include/unionwait.h – union wait BSD compatibility

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 782 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/posixwait.h`

---

## Acceptance Criteria

- [ ] Exit status correctly decoded on FreeBSD and macOS CI runners

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
