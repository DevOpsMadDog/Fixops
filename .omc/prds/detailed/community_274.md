# PRD: Community 274 — GNU gettext Plural Form Evaluator

## Master Goal Mapping
**Goal:** Evaluate C-style plural expression trees to select correct plural form index for multi-language plural rules in GNU gettext.

**Domain:** Internationalization / Localization
**Personas:** Platform Engineer
**Node Count:** 2 | **Status:** Implemented

---

## Source Files
- `bash-5.1/lib/intl/eval-plural.h`

## Graph Nodes (Labels)
- eval-plural.h
- plural_eval()

---

## Architecture Diagram

```mermaid
graph TD
    A[ngettext runtime] --> B[plural_eval()]
    B --> C[Expression tree walk]
    C --> D[Plural index 0..N]
    D --> E[Translated plural string]
```

---

## Code Proof

- `bash-5.1/lib/intl/eval-plural.h:L1-L80` — plural_eval() recursive descent evaluator for plural AST

---

## Inter-Dependencies

- `bash-5.1/lib/intl/plural.y`
- `bash-5.1/lib/intl/plural-exp.h`

### Community Link Dependencies
- No external community dependencies

---

## Data Flow

```
n (count) + plural expression AST → plural_eval(expr, n) → index → catalog string array[index]
```

---

## Referenced Docs

- `GNU gettext §11.2.5 Plural forms`
- `CLDR plural rules`

---

## Acceptance Criteria

- [ ] English: n==1 → 0, else → 1
- [ ] Polish 4-form rule evaluates correctly
- [ ] Zero-division guarded

---

## Effort Estimate

**0.5 day (Trivial — isolated leaf module)**

---

## Status

**Implemented** — Module exists in codebase. Integration tests recommended.
