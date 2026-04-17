# PRD — Community 772: Bash Redirection Header (redir.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Declare do_redirections(), undo_redirections(), and close_all_files() for bash-5.1's I/O redirection subsystem, enabling ALDECI scripts to redirect stdin/stdout/stderr to log files and pipes correctly.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/redir.h`
- Graph community: 772 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[redir.h] -->|declares| B[do_redirections / undo_redirections / close_all_files]
    B --> C[bash-5.1 redir.c]
    C --> D[I/O redirection in ALDECI automation scripts]
```

---

## Source Files

- `bash-5.1/redir.h`

**Graph node label (truncated):** `redir.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/redir.h – I/O redirection function declarations

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 772 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/redir.c`

---

## Acceptance Criteria

- [ ] cmd > file 2>&1 and here-doc << EOF work correctly in ALDECI scripts

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
