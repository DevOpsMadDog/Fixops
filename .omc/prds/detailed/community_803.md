# PRD — Community 803: Bash gettext Implementation (gettext.c)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Implement the gettext() lookup in bash-5.1's bundled libintl, providing message-catalogue translation for bash's own error strings without requiring the host system's gettext library in ALDECI containers.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/lib/intl/gettext.c`
- Graph community: 803 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[gettext.c] -->|implements| B[gettext / dgettext]
    B --> C[bash-5.1 i18n message lookup]
    C --> D[Localised bash messages in ALDECI containers without host gettext]
```

---

## Source Files

- `bash-5.1/lib/intl/gettext.c`

**Graph node label (truncated):** `gettext.c`
**Source location:** `L1`

---

## Code Proof

bash-5.1/lib/intl/gettext.c – gettext lookup implementation

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 803 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/lib/intl/`
- `bash-5.1/include/gettext.h`

---

## Acceptance Criteria

- [ ] bash messages translate without host libintl on Alpine containers

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
