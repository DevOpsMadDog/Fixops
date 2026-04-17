# PRD — Community 794: Bash getopt Header for Builtins (bashgetopt.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Declare bash-5.1's internal getopts implementation (bash_getopt, reset_internal_getopt) used by built-in command argument parsing, ensuring ALDECI scripts' getopts loops parse flags correctly.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/builtins/bashgetopt.h`
- Graph community: 794 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[bashgetopt.h] -->|declares| B[bash_getopt / reset_internal_getopt]
    B --> C[bash-5.1 builtins argument parsing]
    C --> D[getopts loops in ALDECI scripts]
```

---

## Source Files

- `bash-5.1/builtins/bashgetopt.h`

**Graph node label (truncated):** `bashgetopt.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/builtins/bashgetopt.h – internal getopt declarations

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 794 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/builtins/getopt.h`

---

## Acceptance Criteria

- [ ] getopts 'abc:' opt processes flags with arguments correctly

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
