# PRD: Community 270 — Bash Loadable Builtin — sync()

## Master Goal Mapping
**Goal:** Provide a sync() system call as a loadable bash builtin for flushing filesystem buffers from bash scripts without spawning a subprocess.

**Domain:** Infrastructure / Shell Utilities
**Personas:** Platform Engineer, DevOps Operator
**Node Count:** 2 | **Status:** Implemented

---

## Source Files
- `bash-5.1/examples/loadables/sync.c`

## Graph Nodes (Labels)
- sync.c
- sync_builtin()

---

## Architecture Diagram

```mermaid
graph TD
    A[bash shell] --> B[sync_builtin()]
    B --> C[sync syscall]
    C --> D[Kernel VFS Buffer Flush]
```

---

## Code Proof

- `bash-5.1/examples/loadables/sync.c:L1-L40` — sync_builtin() calling libc sync()

---

## Inter-Dependencies

- None (isolated leaf module)

### Community Link Dependencies
- No external community dependencies

---

## Data Flow

```
bash script → enable -f sync → sync_builtin() → sync() → returns 0
```

---

## Referenced Docs

- `bash-5.1/doc/loadables.md`
- `POSIX sync(2)`

---

## Acceptance Criteria

- [ ] sync builtin loads via enable -f ./sync sync
- [ ] Returns exit code 0 on success
- [ ] Flushes dirty kernel buffers

---

## Effort Estimate

**0.5 day (Trivial — isolated leaf module)**

---

## Status

**Implemented** — Module exists in codebase. Integration tests recommended.
