# PRD — Community 790: Bash POSIX Directory Include (posixdir.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Provide portable dirent.h / sys/dir.h inclusion for bash-5.1's directory-traversal functions, enabling glob expansion and cd completion to traverse ALDECI's filesystem correctly across container OS variants.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/include/posixdir.h`
- Graph community: 790 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[posixdir.h] -->|portable dirent| B[opendir / readdir / closedir]
    B --> C[bash-5.1 pathexp.c / general.c]
    C --> D[Directory traversal in ALDECI glob and cd operations]
```

---

## Source Files

- `bash-5.1/include/posixdir.h`

**Graph node label (truncated):** `posixdir.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/include/posixdir.h – POSIX dirent portability

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 790 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/pathexp.h`

---

## Acceptance Criteria

- [ ] Glob *.py and cd /suite-core/ work on Alpine and Ubuntu containers

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
