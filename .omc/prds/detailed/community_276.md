# PRD: Community 276 — Bash Physical Path Resolver (_path_readlink)

## Master Goal Mapping
**Goal:** Resolve symlinks to physical absolute paths for bash cd -P and pwd builtins, avoiding logical path confusion in security-sensitive scripts.

**Domain:** Filesystem / Path Utilities
**Personas:** Platform Engineer, Security Engineer
**Node Count:** 2 | **Status:** Implemented

---

## Source Files
- `bash-5.1/lib/sh/pathphys.c`

## Graph Nodes (Labels)
- _path_readlink()
- pathphys.c

---

## Architecture Diagram

```mermaid
graph TD
    A[cd -P / pwd -P] --> B[_path_readlink()]
    B --> C[readlink syscall loop]
    C --> D{more symlinks?}
    D -->|yes| C
    D -->|no| E[physical path string]
```

---

## Code Proof

- `bash-5.1/lib/sh/pathphys.c:L1-L120` — _path_readlink() iterative symlink resolution with cycle detection

---

## Inter-Dependencies

- `bash-5.1/builtins/cd.def`
- `bash-5.1/builtins/common.c`

### Community Link Dependencies
- No external community dependencies

---

## Data Flow

```
logical path → _path_readlink() → readlink() loop → physical realpath string
```

---

## Referenced Docs

- `POSIX realpath(3)`
- `bash-5.1/CHANGES`

---

## Acceptance Criteria

- [ ] Symlink chains resolved fully
- [ ] Circular symlinks return error
- [ ] ENAMETOOLONG handled

---

## Effort Estimate

**0.5 day (Trivial — isolated leaf module)**

---

## Status

**Implemented** — Module exists in codebase. Integration tests recommended.
