# PRD — Community 774: Bash POSIX Wait Include (posixwait.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Provide portable waitpid() / WIFEXITED / WEXITSTATUS definitions for bash-5.1's job-control layer, ensuring ALDECI's script-runner correctly reaps child processes spawned by security tool invocations.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/include/posixwait.h`
- Graph community: 774 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[posixwait.h] -->|portable| B[waitpid / WIFEXITED / WEXITSTATUS]
    B --> C[bash-5.1 jobs.c / execute_cmd.c]
    C --> D[Child-process reaping in ALDECI script-runner]
```

---

## Source Files

- `bash-5.1/include/posixwait.h`

**Graph node label (truncated):** `posixwait.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/include/posixwait.h – POSIX wait portability

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 774 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/jobs.h`

---

## Acceptance Criteria

- [ ] No zombie processes after security tool sub-commands complete

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
