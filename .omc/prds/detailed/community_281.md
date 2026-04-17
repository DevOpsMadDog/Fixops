# PRD: Community 281 — Bash Malloc Stub (bash_malloc_stub)

## Master Goal Mapping
**Goal:** Provide a stub malloc implementation for bash builds that link against system malloc, preventing symbol conflicts with bash internal allocator.

**Domain:** Memory Management / Build System
**Personas:** Platform Engineer
**Node Count:** 2 | **Status:** Implemented

---

## Source Files
- `bash-5.1/lib/malloc/stub.c`

## Graph Nodes (Labels)
- bash_malloc_stub()
- stub.c

---

## Architecture Diagram

```mermaid
graph TD
    A[bash binary] --> B[bash_malloc_stub()]
    B --> C{USE_SYSTEM_MALLOC}
    C -->|defined| D[delegates to system malloc]
    C -->|undefined| E[bash internal xmalloc]
```

---

## Code Proof

- `bash-5.1/lib/malloc/stub.c:L1-L40` — bash_malloc_stub() conditionally delegates to system or internal allocator

---

## Inter-Dependencies

- `bash-5.1/lib/malloc/malloc.c`
- `bash-5.1/config.h`

### Community Link Dependencies
- No external community dependencies

---

## Data Flow

```
malloc(size) call → stub → system malloc or xmalloc → pointer
```

---

## Referenced Docs

- `bash-5.1/INSTALL §malloc`
- `bash-5.1/lib/malloc/README`

---

## Acceptance Criteria

- [ ] Compiles with -DUSE_SYSTEM_MALLOC
- [ ] No double-free on bash exit
- [ ] valgrind clean for simple scripts

---

## Effort Estimate

**0.5 day (Trivial — isolated leaf module)**

---

## Status

**Implemented** — Module exists in codebase. Integration tests recommended.
