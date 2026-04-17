# PRD — Community 764: Bash Fundamental-Types Header (bashtypes.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Define pid_t, uid_t, gid_t, and other POSIX fundamental types for bash-5.1 on platforms where they may be missing, ensuring portability across the OS variants used in ALDECI's deployment targets.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/bashtypes.h`
- Graph community: 764 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[bashtypes.h] -->|conditional typedef| B[pid_t / uid_t / gid_t / time_t]
    B --> C[All bash-5.1 .c files needing POSIX types]
    C --> D[Portable bash build across ALDECI deployment targets]
```

---

## Source Files

- `bash-5.1/bashtypes.h`

**Graph node label (truncated):** `bashtypes.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/bashtypes.h – POSIX type portability definitions

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 764 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/config.h`

---

## Acceptance Criteria

- [ ] bash-5.1 compiles on Alpine Linux (musl), Ubuntu (glibc), and macOS

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
