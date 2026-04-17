# PRD — Community 793: Bash Built-in Command Registry (builtins.c)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Implement the shell_builtins[] array and builtin dispatch table for all bash-5.1 built-in commands (cd, export, read, source, printf, etc.), providing the full built-in set to ALDECI's script-runner.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/builtins/builtins.c`
- Graph community: 793 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[builtins.c] -->|shell_builtins[]| B[All bash built-in commands]
    B --> C[bash-5.1 execute_cmd.c dispatch]
    C --> D[cd / export / read / source / printf in ALDECI scripts]
```

---

## Source Files

- `bash-5.1/builtins/builtins.c`

**Graph node label (truncated):** `builtins.c`
**Source location:** `L1`

---

## Code Proof

bash-5.1/builtins/builtins.c – shell_builtins[] array implementation

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 793 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/builtins.h`

---

## Acceptance Criteria

- [ ] All POSIX and bash-extension built-ins available in ALDECI scripts

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
