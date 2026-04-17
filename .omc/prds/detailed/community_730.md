# PRD — Community 730: Bash Version Header (version.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – generated vendor file; updated by mkversion
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Expose DISTVERSION, BUILDVERSION, RELSTATUS, DEFAULT_COMPAT_LEVEL, and SCCSVERSION macros so the bash-5.1 runtime embedded in ALDECI correctly self-identifies as 'Bash 5.1.0(1) release'.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/version.h`
- Graph community: 730 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[version.h] -->|DISTVERSION=5.1| B[bash-5.1 version.c]
    B -->|--version output| C[ALDECI script-runner]
```

---

## Source Files

- `bash-5.1/version.h`

**Graph node label (truncated):** `version.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/version.h:L5 – #define DISTVERSION '5.1'; #define DEFAULT_COMPAT_LEVEL 51

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 730 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/support/mkversion.sh`

---

## Acceptance Criteria

- [ ] bash --version prints 'GNU bash, version 5.1'; compat level 51

---

## Effort Estimate

**XS – generated vendor file; updated by mkversion**

| Task | Points |
|------|--------|
| Understand file purpose | 1 |
| Verify vendored build compiles cleanly | 2 |
| CI build matrix validation | 2 |

---

## Status

**Stable**

> Vendored file. No ALDECI-side changes required. Only action: ensure bash-5.1 builds cleanly in CI and GPLv3 license headers are preserved.
