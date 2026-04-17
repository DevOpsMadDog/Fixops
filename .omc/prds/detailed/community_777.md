# PRD — Community 777: Bash Maximum-Path Include (maxpath.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Define PATH_MAX and MAXPATHLEN portably for bash-5.1, preventing buffer-overflow risks when bash constructs absolute paths in ALDECI's container filesystem environment.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/include/maxpath.h`
- Graph community: 777 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[maxpath.h] -->|defines| B[PATH_MAX / MAXPATHLEN]
    B --> C[bash-5.1 pathexp.c / general.c]
    C --> D[Safe path buffer sizing in ALDECI script-runner]
```

---

## Source Files

- `bash-5.1/include/maxpath.h`

**Graph node label (truncated):** `maxpath.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/include/maxpath.h – PATH_MAX portability

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 777 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/config.h`

---

## Acceptance Criteria

- [ ] Paths up to 4096 chars handled without truncation

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
