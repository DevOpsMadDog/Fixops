# PRD — Community 795: Bash External Builtin-Text Header (builtext.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – generated vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Declare extern references to all bash-5.1 built-in help-text strings generated from *.def files, enabling 'help cmd' to display documentation for every built-in within ALDECI's interactive shell.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/builtins/builtext.h`
- Graph community: 795 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[builtext.h] -->|extern char* help texts| B[bash-5.1 builtins/*.def]
    B --> C[help builtin documentation]
    C --> D[help cd / help export in ALDECI interactive shell]
```

---

## Source Files

- `bash-5.1/builtins/builtext.h`

**Graph node label (truncated):** `builtext.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/builtins/builtext.h – extern help-text string declarations

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 795 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/builtins/mkbuiltins`

---

## Acceptance Criteria

- [ ] help export displays full usage text in ALDECI interactive session

---

## Effort Estimate

**XS – generated vendor file; no modification required**

| Task | Points |
|------|--------|
| Understand file purpose | 1 |
| Verify vendored build compiles cleanly | 2 |
| CI build matrix validation | 2 |

---

## Status

**Stable**

> Vendored file. No ALDECI-side changes required. Only action: ensure bash-5.1 builds cleanly in CI and GPLv3 license headers are preserved.
