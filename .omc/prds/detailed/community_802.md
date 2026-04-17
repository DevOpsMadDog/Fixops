# PRD — Community 802: Bash Perl Loadable Example (bperl.c)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor example; reference only
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Provide the bperl loadable built-in example that embeds a Perl interpreter in bash-5.1, serving as a reference implementation for building ALDECI's own loadable security-tool built-ins.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/examples/loadables/perl/bperl.c`
- Graph community: 802 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[bperl.c] -->|embeds| B[Perl interpreter via libperl]
    A -->|loadable pattern| C[loadables.h interface]
    C --> D[Reference for ALDECI custom loadable built-ins]
```

---

## Source Files

- `bash-5.1/examples/loadables/perl/bperl.c`

**Graph node label (truncated):** `bperl.c`
**Source location:** `L1`

---

## Code Proof

bash-5.1/examples/loadables/perl/bperl.c – Perl-embedding loadable example

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 802 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/examples/loadables/loadables.h`

---

## Acceptance Criteria

- [ ] bperl.c compiles with libperl on macOS and Linux CI runners

---

## Effort Estimate

**XS – vendor example; reference only**

| Task | Points |
|------|--------|
| Understand file purpose | 1 |
| Verify vendored build compiles cleanly | 2 |
| CI build matrix validation | 2 |

---

## Status

**Stable**

> Vendored file. No ALDECI-side changes required. Only action: ensure bash-5.1 builds cleanly in CI and GPLv3 license headers are preserved.
