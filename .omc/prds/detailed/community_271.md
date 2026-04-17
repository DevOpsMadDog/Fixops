# PRD: Community 271 — Bash Loadable Builtin — necho()

## Master Goal Mapping
**Goal:** Provide necho() as a bash loadable that echoes arguments without a trailing newline, serving as a portable replacement for `echo -n`.

**Domain:** Infrastructure / Shell Utilities
**Personas:** Platform Engineer
**Node Count:** 2 | **Status:** Implemented

---

## Source Files
- `bash-5.1/examples/loadables/necho.c`

## Graph Nodes (Labels)
- necho.c
- necho_builtin()

---

## Architecture Diagram

```mermaid
graph TD
    A[bash script] --> B[necho_builtin()]
    B --> C[fputs stdout]
    C --> D[Terminal / Pipe]
```

---

## Code Proof

- `bash-5.1/examples/loadables/necho.c:L1-L50` — necho_builtin() iterates argv, fputs without newline

---

## Inter-Dependencies

- None (isolated leaf module)

### Community Link Dependencies
- No external community dependencies

---

## Data Flow

```
bash → enable -f necho → necho_builtin(argv) → stdout (no newline)
```

---

## Referenced Docs

- `bash-5.1/examples/loadables/README`

---

## Acceptance Criteria

- [ ] necho foo prints foo without newline
- [ ] Multiple args space-separated
- [ ] Loadable via enable -f

---

## Effort Estimate

**0.5 day (Trivial — isolated leaf module)**

---

## Status

**Implemented** — Module exists in codebase. Integration tests recommended.
