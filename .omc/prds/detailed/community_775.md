# PRD — Community 775: Bash POSIX Stat Include (posixstat.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Provide portable stat() / lstat() / S_IS* macro definitions for bash-5.1's file-testing commands, ensuring ALDECI scripts' [[ -f ]] / [[ -d ]] tests work correctly across container OS variants.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/include/posixstat.h`
- Graph community: 775 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[posixstat.h] -->|portable| B[stat / S_ISREG / S_ISDIR macros]
    B --> C[bash-5.1 test.c / execute_cmd.c]
    C --> D[File-type tests in ALDECI scripts]
```

---

## Source Files

- `bash-5.1/include/posixstat.h`

**Graph node label (truncated):** `posixstat.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/include/posixstat.h – POSIX stat portability

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 775 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/test.h`

---

## Acceptance Criteria

- [ ] [[ -f /etc/passwd ]] returns 0 on all ALDECI container targets

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
