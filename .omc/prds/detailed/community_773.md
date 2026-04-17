# PRD — Community 773: Bash POSIX-Times Include (systimes.h)

**Domain:** Shell Runtime / bash-5.1 Vendor Dependency
**Status:** Stable
**Effort:** XS – vendor file; no modification required
**Personas:** Platform Engineer
**Generated:** 2026-04-16

---

## Master Goal Mapping

Provide portable inclusion of sys/times.h (or fallback struct tms definition) for bash-5.1's time builtin, enabling ALDECI scripts to measure execution time of security scan sub-commands.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `bash-5.1/include/systimes.h`
- Graph community: 773 (1 source file)

---

## Architecture Diagram

```mermaid
graph LR
    A[systimes.h] -->|portable| B[sys/times.h or struct tms fallback]
    B --> C[bash-5.1 time builtin]
    C --> D[time cmd output in ALDECI scan scripts]
```

---

## Source Files

- `bash-5.1/include/systimes.h`

**Graph node label (truncated):** `systimes.h`
**Source location:** `L1`

---

## Code Proof

bash-5.1/include/systimes.h – POSIX times portability

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 773 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. The file is a vendored C header/source and has no runtime data flow into ALDECI FastAPI; it is compiled into the embedded bash-5.1 runtime.

---

## Referenced Docs

- `bash-5.1/builtins/time.def`

---

## Acceptance Criteria

- [ ] time nmap-scan-script.sh reports real/user/sys times

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
