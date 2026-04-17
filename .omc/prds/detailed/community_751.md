# PRD — Community 751: Bash Command-Copy Implementation (copy_cmd.c)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Implement copy_command() that deep-copies COMMAND tree nodes for bash-5.1 function definitions, preventing use-after-free bugs in ALDECI's long-running embedded shell sessions.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/copy_cmd.c`
- Graph community: 751 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[copy_cmd.c] -->|includes| B[config.h / bashtypes.h]
    A -->|implements| C[copy_command]
    C --> D[bash-5.1 function definition storage]
    D --> E[Function reuse across script invocations in ALDECI]
```

---

## Source Files

- `bash-5.1/copy_cmd.c`

**Graph node label (truncated):** `copy_cmd.c`
**Source location:** `L1`

---

## Code Proof

bash-5.1/copy_cmd.c:L1 – 'copy a COMMAND structure; needed primarily for making function definitions'; includes config.h, bashtypes.h

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 751 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/command.h`
- `bash-5.1/make_cmd.h`

---

## Acceptance Criteria

- [ ] Function definitions survive re-invocation without memory corruption

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
