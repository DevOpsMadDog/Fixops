# PRD — Community 809: Bash Locale Load-Info Header (loadinfo.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Define the locale-specification parsing structs (loaded_l10nfile, locale_entry) for bash-5.1's bundled libintl, enabling correct .mo file discovery across complex locale hierarchies in ALDECI deployments.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/lib/intl/loadinfo.h`
- Graph community: 809 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[loadinfo.h] -->|defines| B[loaded_l10nfile / locale_entry structs]
    B --> C[bash-5.1 lib/intl/loadl10n.c]
    C --> D[.mo file discovery for complex locales in ALDECI]
```

---

## Source Files

- `bash-5.1/lib/intl/loadinfo.h`

**Graph node label (truncated):** `loadinfo.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/lib/intl/loadinfo.h – locale load-info structures

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 809 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/lib/intl/`

---

## Acceptance Criteria

- [ ] zh_CN.UTF-8 and en_US.UTF-8 .mo files discovered and loaded correctly

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
