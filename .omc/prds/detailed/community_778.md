# PRD — Community 778: Bash File-Control Include (filecntl.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Provide portable fcntl.h inclusion and F_DUPFD / O_NONBLOCK definitions for bash-5.1's file-descriptor management, ensuring ALDECI's script-runner correctly sets non-blocking I/O on pipes.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/include/filecntl.h`
- Graph community: 778 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[filecntl.h] -->|portable fcntl| B[F_DUPFD / O_NONBLOCK]
    B --> C[bash-5.1 redir.c / input.c]
    C --> D[Non-blocking pipe I/O in ALDECI pipelines]
```

---

## Source Files

- `bash-5.1/include/filecntl.h`

**Graph node label (truncated):** `filecntl.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/include/filecntl.h – fcntl portability

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 778 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/redir.h`

---

## Acceptance Criteria

- [ ] Non-blocking reads on pipes don't block ALDECI pipeline execution

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
