# Architecture Decision Records

Decisions required to turn FixOps from a large codebase into a sellable product.

Every ADR here is grounded in measurement, not opinion. The measurements come from
three independent passes taken on 2026-08-16/17 and recorded in
`docs/CODEBASE_UNDERSTANDING_2026-08-16.md` and `docs/FEATURE_REALITY_2026-08-16.md`:

| Pass | Tool | What it produced |
|---|---|---|
| Structure | `Understand-Anything` scan | 17,831 files, verdict `very-large`, 801 LLM batches for a full semantic pass |
| Symbols | tree-sitter AST extraction | 16,597 files parsed with **0 failures**: 49,436 functions, 20,416 classes, 558,590 call-graph edges, 2,883,029 lines |
| Behaviour | 1,490 live HTTP calls | 745 API domains, each probed as a real tenant and as a nonexistent one |

## The finding that drives most of these decisions

The three passes disagree in a way that is itself the answer:

- The repo **looks** enormous — 17,831 files, 2.88M lines parsed.
- **68% of tracked files (12,189 of 17,961) are generated SDK**, including a Python
  client committed *twice* under two names with identical file sets (4,465 files each).
- Hand-written product Python is **2,086 files / 1,001,839 lines**.
- Of the API surface that code exposes, **168 of 745 domains (22%) carry real tenant
  data**; 396 are identical for every tenant; 140 are empty; 21 are broken.

So the codebase is neither mostly broken nor mostly fake. It is **mostly unreachable,
and made to look three times larger than it is by committed build artifacts.** Both are
cheap to fix and neither requires a rewrite.

## Index

| ADR | Title | Status |
|---|---|---|
| [001](001-single-product-two-deployment-profiles.md) | Single product, two deployment profiles | Proposed |
| [002](002-pluggable-council-backend.md) | The council's backend is pluggable; consensus is the invariant | Proposed |
| [003](003-offline-threat-feed-bundle.md) | Offline threat-feed bundle for air-gapped enrichment | Proposed |
| [004](004-generated-sdks-are-build-artifacts.md) | Generated SDKs are build artifacts, not committed source | Proposed |
| [005](005-core-mode-is-the-default-surface.md) | Core mode is the default shipping surface | Proposed |
| [006](006-engine-persistence-standard.md) | One anchored store; engines never resolve paths from the working directory | Accepted |
| [007](007-credential-gated-integrations.md) | Credential-gated integrations report "not configured", never 5xx | Proposed |
| [008](008-evidence-is-the-commercial-wedge.md) | The signed evidence bundle is the commercial wedge | Proposed |
| [009](009-ingest-first-is-the-product-thesis.md) | Ingest-first is the product thesis | Proposed |

## Format

Each record states **Context** (measured, with the number and how it was obtained),
**Decision**, **Consequences** (including what we accept losing), and **Verification** —
the check that proves the decision was actually implemented, so an ADR cannot quietly
become aspirational.
