# PRD — Community 760: Bash Internationalisation Header (bashintl.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Provide the _(string) gettext macro and locale-initialisation wrappers for bash-5.1, enabling internationalised error messages in ALDECI deployments serving non-English operators.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/bashintl.h`
- Graph community: 760 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[bashintl.h] -->|defines| B[_ macro / N_ macro]
    B --> C[bash-5.1 i18n error messages]
    C --> D[Localised ALDECI shell error output]
```

---

## Source Files

- `bash-5.1/bashintl.h`

**Graph node label (truncated):** `bashintl.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/bashintl.h – gettext _(str) macro definitions

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 760 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/lib/intl/`

---

## Acceptance Criteria

- [ ] LANG=fr_FR bash produces localised messages if locale pack installed

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
