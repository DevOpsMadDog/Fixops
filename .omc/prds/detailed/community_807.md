# PRD — Community 807: Bash Text-Domain Binding Implementation (textdomain.c)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Implement textdomain() and bindtextdomain() for bash-5.1's bundled libintl, establishing the message-catalogue domain and directory path used by ALDECI's embedded bash for locale resolution.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/lib/intl/textdomain.c`
- Graph community: 807 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[textdomain.c] -->|implements| B[textdomain / bindtextdomain]
    B --> C[bash-5.1 locale domain setup]
    C --> D[/usr/share/locale/bash .mo catalogue path in ALDECI]
```

---

## Source Files

- `bash-5.1/lib/intl/textdomain.c`

**Graph node label (truncated):** `textdomain.c`
**Source location:** `L1`

---

## Code Proof

bash-5.1/lib/intl/textdomain.c – textdomain/bindtextdomain implementation

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 807 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/lib/intl/gettext.c`

---

## Acceptance Criteria

- [ ] bindtextdomain correctly resolves .mo path in ALDECI containers

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
