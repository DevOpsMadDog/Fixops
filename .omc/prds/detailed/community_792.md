# PRD — Community 792: Bash Builtin Pipe-Size Header (pipesize.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Define PIPESIZE constant for bash-5.1's ulimit builtin, allowing ALDECI operators to query and set pipe-buffer limits when tuning throughput of security-tool pipeline chains.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/builtins/pipesize.h`
- Graph community: 792 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[pipesize.h] -->|PIPESIZE| B[bash-5.1 builtins/ulimit.def]
    B --> C[ulimit -p output in ALDECI scripts]
```

---

## Source Files

- `bash-5.1/builtins/pipesize.h`

**Graph node label (truncated):** `pipesize.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/builtins/pipesize.h – PIPESIZE constant for ulimit builtin

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 792 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/builtins/ulimit.def`

---

## Acceptance Criteria

- [ ] ulimit -p returns correct pipe buffer size in ALDECI containers

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
