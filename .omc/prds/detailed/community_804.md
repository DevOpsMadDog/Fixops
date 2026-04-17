# PRD — Community 804: Bash GNU Message-Object Header (gmo.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Define the GNU MO binary file format structures (struct mo_file_header, struct string_desc) for bash-5.1's bundled libintl, enabling .mo catalogue loading for localised ALDECI shell messages.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/lib/intl/gmo.h`
- Graph community: 804 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[gmo.h] -->|defines| B[struct mo_file_header / string_desc]
    B --> C[bash-5.1 lib/intl/loadmsgcat.c]
    C --> D[.mo binary catalogue loading for ALDECI locales]
```

---

## Source Files

- `bash-5.1/lib/intl/gmo.h`

**Graph node label (truncated):** `gmo.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/lib/intl/gmo.h – GNU MO binary file format structures

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 804 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/lib/intl/`

---

## Acceptance Criteria

- [ ] LC_ALL=fr_FR bash loads French .mo catalogue without errors

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
