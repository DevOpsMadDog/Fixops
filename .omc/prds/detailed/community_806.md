# PRD — Community 806: Bash Category gettext Implementation (dcgettext.c)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Implement dcgettext() (domain+category variant of gettext) for bash-5.1's bundled libintl, enabling per-LC_* category message lookup to support ALDECI's mixed-locale operator environments.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/lib/intl/dcgettext.c`
- Graph community: 806 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[dcgettext.c] -->|implements| B[dcgettext / dcngettext]
    B --> C[bash-5.1 per-category i18n lookup]
    C --> D[Mixed LC_MESSAGES / LC_NUMERIC locale in ALDECI]
```

---

## Source Files

- `bash-5.1/lib/intl/dcgettext.c`

**Graph node label (truncated):** `dcgettext.c`
**Source location:** `L1`

---

## Code Proof

bash-5.1/lib/intl/dcgettext.c – dcgettext implementation

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 806 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/lib/intl/gettext.c`

---

## Acceptance Criteria

- [ ] LC_MESSAGES=fr LC_NUMERIC=en produces correct mixed-locale output

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
