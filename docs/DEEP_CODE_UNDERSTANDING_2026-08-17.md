# Deep code understanding — full symbol pass, 2026-08-17

What `Understand-Anything` tells us about the 17,831 files, taken all the way down to
symbol level, and correlated against what the running system actually does.

---

## 1. The pass that was missing

The earlier run (2026-08-16) reported file counts only — tree-sitter could not load its
grammars in a manual bootstrap, so symbol extraction was degraded and the analysis stopped
at "17,831 files, `very-large`, 801 batches".

That is now fixed. The grammars (`tree-sitter-python`, `tree-sitter-typescript`,
`tree-sitter-javascript`) were installed into the plugin and the extractor run across the
whole repository in 42 batches:

| | |
|---|---|
| Files parsed | **16,597** |
| Structure extraction failures | **0** |
| Call-graph extraction failures | **0** |
| Files skipped | **0** |
| Functions | **49,436** |
| Classes | **20,416** |
| Exports | **71,747** |
| Call-graph edges | **558,590** |
| Lines parsed | **2,883,029** |
| Distinct symbols | **61,442** |

This is a complete deterministic pass — every file, every definition, every call edge —
at zero LLM cost. The 801-batch figure is what a *semantic* pass would cost on top of it.

## 2. The finding that changes the shape of the problem

Splitting the parsed corpus by area shows the repo is not what the file count suggests:

| Area | Files | Lines | Functions | Classes |
|---|---:|---:|---:|---:|
| **Generated SDKs** | **12,130** | **1,013,545** | 11,241 | 7,145 |
| Product Python | 2,104 | 1,014,840 | 12,895 | 7,652 |
| Tests | 1,616 | 604,155 | 21,628 | 5,504 |
| UI | 523 | 145,089 | 1,887 | 8 |
| Scripts / tools | 188 | 93,588 | 1,595 | 89 |
| Other | 36 | 11,812 | 190 | 18 |

**68% of tracked files (12,189 of 17,961) are generated SDK**, every file carrying
`/* generated using openapi-typescript-codegen -- do not edit */`. And the Python client
is committed **twice** — `sdks/python/aldeci_client` and
`sdks/python/aldeci_security_intelligence_platform_client`, 4,465 files each, identical
file sets. 134 MB on disk.

So the "very-large / 801 batches" verdict is dominated by machine-generated code that no
human maintains. Strip it and the repository is ~5,772 tracked files. See
[ADR-004](architecture/adr/004-generated-sdks-are-build-artifacts.md).

## 3. Inside the product code

Hand-written Python, excluding tests:

| | Files | Lines | Functions | Classes |
|---|---:|---:|---:|---:|
| `core/` (non-engine) | 464 | 328,909 | 1,399 | 2,250 |
| `*_engine.py` | 475 | 293,405 | 904 | 979 |
| `*_router.py` | 829 | 250,259 | 8,958 | 3,596 |
| misc | 272 | 96,041 | 1,247 | 565 |
| `connectors/` | 40 | 29,403 | 213 | 164 |
| `trustgraph/` | 6 | 3,822 | 10 | 16 |
| **Total** | **2,086** | **1,001,839** | **12,731** | **7,570** |

Two things stand out:

- **Routers hold 8,958 of 12,731 functions (70%)** in a quarter of the lines. That is the
  expected shape for an API layer — many small handlers — and it is why route count
  (7,940) outruns engine count.
- **Engines average under 2 public functions per file across 475 files.** Combined with
  the earlier finding that 104 of 464 `*_engine.py` have no persistence layer at all, a
  large number of "engines" are thin. They compute; they do not remember.

## 4. Duplication, measured

**4,213 class names are defined in more than one file.** The heaviest repeats:

| Class | Files | What it is |
|---|---:|---|
| `_StubResponse` | 79 | test double |
| `_StubClient` | 63 | test double |
| `CapabilityResponse` | 46 | API response model |
| `ScanRequest` | 24 | request model |
| `StubHTTPXClient` | 15 | test double |

Two conclusions, and they point opposite ways:

- **The stubs are entirely in tests — 0 in production code.** The "no stubs in the
  product" rule holds. What we have instead is 79 test files each redefining the same
  double: a maintenance cost, not a product defect.
- **The repeated request/response models are real duplication.** `CapabilityResponse` in
  46 files and `ScanRequest` in 24 means the same contract is re-declared per router
  rather than shared, which is how 740 duplicate `(method, path)` route groups arose in
  the first place.

## 5. Reachability

76% of distinct symbols (46,927 of 61,442) never appear as a callee anywhere in the
repository. That number must be read carefully — FastAPI handlers are invoked by the
framework rather than by name, Pydantic models are constructed implicitly, and pytest
functions are collected. It is **not** a dead-code count.

The reachability question that *is* answerable was answered by the live probe rather than
the graph: of 745 API domains, **168 (22%) return data that differs per tenant**, 396
return identical bytes for every tenant, 140 are empty, and **374 (50%) have a UI
callsite**.

## 6. The correlation

Put the two independent measurements side by side:

- Code mass: the value path is ~2.3% of product Python.
- Surface realness: 22% of API domains carry tenant data.

Those do not match, and the mismatch is the whole story. If the codebase were
proportionally hollow, ~2% of the code would yield ~2% real surface. It yields 22%.

**The code is not mostly broken and not mostly fake. It is mostly unreachable — and the
repository is made to look three times larger than it is by committed build artifacts.**

Both are packaging problems. Neither requires a rewrite. That is the good news buried in
a million lines.

## 7. What this justifies

| Observation | Decision |
|---|---|
| 68% generated files, Python client committed twice | [ADR-004](architecture/adr/004-generated-sdks-are-build-artifacts.md) |
| 22% real surface, 50% with UI | [ADR-005](architecture/adr/005-core-mode-is-the-default-surface.md) |
| 49 split stores, 13 diverged | [ADR-006](architecture/adr/006-engine-persistence-standard.md) |
| 10 integrations 503 when unconfigured | [ADR-007](architecture/adr/007-credential-gated-integrations.md) |
| 34 normalizers / 45 connectors are the asset | [ADR-009](architecture/adr/009-ingest-first-is-the-product-thesis.md) |
| Council bound to egress; SCIF target | [ADR-001](architecture/adr/001-single-product-two-deployment-profiles.md), [ADR-002](architecture/adr/002-pluggable-council-backend.md), [ADR-003](architecture/adr/003-offline-threat-feed-bundle.md) |
| ML-DSA-65 signing verified real | [ADR-008](architecture/adr/008-evidence-is-the-commercial-wedge.md) |

## 8. Reproducing this pass

```bash
git clone https://github.com/Egonex-AI/Understand-Anything /tmp/ua
cd /tmp/ua/understand-anything-plugin && npm install --ignore-scripts
# the step that was missing: real grammars
npm install --no-save tree-sitter-python tree-sitter-typescript tree-sitter-javascript
node skills/understand/scan-project.mjs <repo> /tmp/scan.json
# then batch skills/understand/extract-structure.mjs over the scan
```

The operator path is `/plugin marketplace add Egonex-AI/Understand-Anything`, which an
agent cannot invoke. Scope any *semantic* run — at 801 batches a full pass is expensive,
and after ADR-004 lands it should fall by roughly two thirds.
