# Reachability, measured on a real repo — and the honest number is 0%

Apiiro quotes 95% triage reduction. We have quoted nothing, because nobody had
measured it. This is the measurement. It does not produce a number we can put on
a slide, and the reason it doesn't is the most useful thing in this document.

## What was actually run

No fixtures. A real scanner, on this repository, against a real call graph.

```
pip-audit -r requirements.txt          156 packages scanned
                                         3 vulnerable findings (all cryptography)
                                           PYSEC-2026-3552 / 3553 / 3554

parse_python_repo("suite-core/core")  42,874 call-graph nodes in 14.1 s
```

Then each CVE was put to the engine with the dependency pattern an ingested
finding actually carries:

| CVE | package | callers found | verdict |
|---|---|---|---|
| PYSEC-2026-3552 | cryptography | 94 | reachable |
| PYSEC-2026-3553 | cryptography | 94 | reachable |
| PYSEC-2026-3554 | cryptography | 94 | reachable |

**3 reachable of 3. Noise reduction: 0%.**

## Why that is not a failure of the engine

The obvious reading is that reachability does not work. It is the wrong reading,
and one more query settles it. Holding the CVE fixed and narrowing only the
symbol pattern:

| pattern | callers |
|---|---|
| `cryptography.%` | **94** |
| `cryptography.hazmat.primitives.ciphers.%` | **15** |
| `cryptography.x509.ocsp.%` | **0** |
| `cryptography.hazmat.bindings._rust.openssl.x509.%` | **0** |
| `cryptography.this.symbol.does.not.exist.%` | 0 |

The engine discriminates, and it discriminates sharply: 94 → 15 → 0 as the
pattern tightens, with a clean zero for a module this codebase never touches.
That is precisely the behaviour the product claims. It is working.

## So where does the 0% come from?

**The query was asked at package granularity, because that is all the ingested
finding knows.**

`pip-audit` — like `osv-scanner`, `grype` and every other SCA tool we normalise —
reports *"this package version is vulnerable"*. It does not report *"the
vulnerability is in `cryptography.x509.ocsp.load_der_ocsp_response`"*. So the
finding arrives carrying a package name and nothing finer, the query degrades to
`cryptography.%`, and the answer is "you use cryptography" — which we already
knew from the dependency file.

Package-level reachability collapses to *do you depend on it*, and every finding
is reachable, and the reduction is zero. Function-level reachability is a
different product, and this engine can already do it. The missing piece is not
analysis. It is **the vulnerable symbol**.

## What that makes the real task

Not "improve reachability". **Source the vulnerable symbol per advisory**, then
feed it to a query the engine already answers correctly:

- OSV records carry `affected[].ecosystem_specific.imports` for some ecosystems
  — the affected module and symbol names, exactly the input needed.
- GitHub Security Advisories sometimes name the vulnerable function in prose.
- The fix commit referenced by an advisory identifies the changed symbols
  directly, and is the most reliable source when it exists.

Until one of those is wired into ingest, we should quote **no** noise-reduction
figure. A number produced by asking a package-level question would be a real
measurement of the wrong thing, and it would collapse the first time a customer
checked it against their own repo.

## What can be said today, truthfully

- The call graph is real and fast: **42,874 nodes from 14.1 seconds** of parsing.
- The reachability query is exact at module granularity, verified against a
  module this codebase uses (15 callers) and one it does not (0).
- On this repository all three real CVEs are genuinely reachable — this codebase
  uses `cryptography` in 94 places. A 0% reduction here is a true statement about
  a small, concentrated sample, not a product defect.
- **We cannot yet quote a noise-reduction percentage**, and the reason is a data
  gap in ingest, not a capability gap in the engine.

Three findings in one package is not a measurement anyway. The number a buyer
wants needs a repo with hundreds of findings across dozens of packages, most of
them transitive and untouched — which is where package-level and function-level
reachability diverge most sharply, and where the real figure lives.
