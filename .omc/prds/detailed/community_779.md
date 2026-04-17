# PRD — Community 779: Bash POSIX-Time Include (posixtime.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Provide portable time.h / sys/time.h inclusion for bash-5.1's gettimeofday and clock-related functionality, enabling correct timing in ALDECI's time builtin and history timestamps.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/include/posixtime.h`
- Graph community: 779 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[posixtime.h] -->|portable time.h| B[gettimeofday / struct timeval]
    B --> C[bash-5.1 bashhist.c / time builtin]
    C --> D[History timestamps and timing in ALDECI]
```

---

## Source Files

- `bash-5.1/include/posixtime.h`

**Graph node label (truncated):** `posixtime.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/include/posixtime.h – POSIX time portability

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 779 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/bashhist.h`

---

## Acceptance Criteria

- [ ] HISTTIMEFORMAT timestamps display correctly; time builtin accurate

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
