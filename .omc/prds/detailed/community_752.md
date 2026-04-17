# PRD — Community 752: Bash Built-in Command Header (builtins.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Define the builtin struct (name, function pointer, flags, documentation) and the shell_builtins[] table so bash-5.1 can dispatch built-in commands (cd, export, source, etc.) within ALDECI's script-runner.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/builtins.h`
- Graph community: 752 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[builtins.h] -->|includes| B[config.h]
    A -->|defines| C[struct builtin / shell_builtins[]]
    C --> D[bash-5.1 builtins/builtins.c]
    D --> E[cd / export / source / etc. in ALDECI scripts]
```

---

## Source Files

- `bash-5.1/builtins.h`

**Graph node label (truncated):** `builtins.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/builtins.h:L1 – 'What a builtin looks like, and where to find them'; includes config.h

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 752 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/builtins/builtins.c`

---

## Acceptance Criteria

- [ ] All POSIX built-ins available; enable/disable builtin works

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
