# PRD: Community 273 — GNU gettext Hash String Utility

## Master Goal Mapping
**Goal:** Provide a fast string hashing function for GNU gettext message catalog lookup, enabling O(1) average-case translation string retrieval.

**Domain:** Internationalization / Localization
**Personas:** Platform Engineer
**Node Count:** 2 | **Status:** Implemented

---

## Source Files
- `bash-5.1/lib/intl/hash-string.h`

## Graph Nodes (Labels)
- hash-string.h
- hash_string()

---

## Architecture Diagram

```mermaid
graph TD
    A[gettext runtime] --> B[hash_string()]
    B --> C[Hash table bucket lookup]
    C --> D[MO catalog entry]
```

---

## Code Proof

- `bash-5.1/lib/intl/hash-string.h:L1-L60` — hash_string() computes djb2-style hash for NLS lookup

---

## Inter-Dependencies

- `bash-5.1/lib/intl/gettextP.h`

### Community Link Dependencies
- No external community dependencies

---

## Data Flow

```
msgid string → hash_string() → bucket index → strcmp chain → translated string
```

---

## Referenced Docs

- `GNU gettext manual §8`
- `bash-5.1/lib/intl/loadmsgcat.c`

---

## Acceptance Criteria

- [ ] hash_string("") returns 0
- [ ] Collisions resolved via chaining
- [ ] O(1) avg for catalog lookup

---

## Effort Estimate

**0.5 day (Trivial — isolated leaf module)**

---

## Status

**Implemented** — Module exists in codebase. Integration tests recommended.
