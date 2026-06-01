# ALDECI Spec System

Spec-driven requirements for every API (or API group). Each spec is the **contract** that an
implementation must satisfy and a test must verify. Specs are the unit of future extension +
maintenance, designed to be managed in **Augment Code intent IDE** and debated in **Mysti**.

## Why specs (the goal)

ALDECI's north star is an **intelligence platform**: interconnected issues → automated pen-tests →
reachability analysis → all signal into **TrustGraph** → a **per-customer local LLM** that learns.
That vision only stays maintainable if each capability has a written, testable contract. Specs are
how we extend without regressing and onboard future devs (and future agents) instantly.

## Layout

```
specs/
  README.md              # this file — the system + conventions
  TEMPLATE.md            # copy this to start a new spec
  INDEX.md               # registry: spec id → title → status → owner family
  SPEC-001-...md         # one spec per API group / capability
  SPEC-002-...md
```

## Spec lifecycle (status field)

`DRAFT → DEBATED → APPROVED → IMPLEMENTED → VERIFIED → LIVE`

- **DRAFT** — chief architect authors intent + requirements.
- **DEBATED** — run through Mysti **Debate** (architecture) + **Red-Team** (security). Record the
  verdicts/changes in the spec's "Debate Log".
- **APPROVED** — founder/architect sign-off.
- **IMPLEMENTED** — senior developer builds to the spec; links the commit.
- **VERIFIED** — tester proves every acceptance criterion against the running app (not stored tests
  alone — live behaviour, code-as-truth).
- **LIVE** — deployed + smoke-confirmed on the target environment.

## How the IDE tools plug in

- **Augment Code intent IDE**: each `SPEC-NNN-*.md` is an "intent" — Augment reads the Requirements
  (REQ-*) + Acceptance Criteria (AC-*) as the source of truth for code generation/refactor. Keep
  REQ/AC IDs stable so Augment can map code ↔ requirement over time.
- **Mysti (VS Code ext)**: before APPROVED, run the spec through Brainstorm Mode →
  **Debate** (Critic vs Defender — does the design hold?) and **Red-Team** (Proposer vs Challenger —
  what breaks it / security). Paste the spec + the relevant files (`@file`) and record outcomes in
  the Debate Log section.

## Authoring rules

1. Every requirement gets a stable id `REQ-<spec>-NN`; every acceptance criterion `AC-<spec>-NN`.
2. Acceptance criteria MUST be **executable** (a curl/pytest/observable assertion), never "works well".
3. No fake/stub data in an implementation that claims a REQ done — honest 501/503 when unconfigured.
4. Data contracts are explicit (request/response shape, status codes incl the honest 503 path).
5. Every spec names its **engine(s)** and **store(s)** so tenancy + persistence are unambiguous.
6. Cross-tenant: every tenant-scoped REQ states the org_id source + the cross-org expectation (404).
