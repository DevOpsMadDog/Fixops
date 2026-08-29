# Reachability, measured on a real repo: 0% at package level, 2 of 3 ruled out at symbol level

Apiiro quotes 95% triage reduction. We had quoted nothing, because nobody had
measured it. This is the measurement, and the first pass produced **0%** — which
turned out to be a fact about the question being asked, not about the engine.
Fixing the question, on the same real data, ruled out two of three findings.

Read in order: the 0%, why it is not an engine failure, and what closed it.

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

## Closing it — measured, same day

The three sources I listed as candidates were not equal, and one of them is
simply empty. Queried live:

| candidate source | result |
|---|---|
| OSV `affected[].ecosystem_specific.imports` | **absent for every PyPI advisory checked** — this route does not exist for Python |
| advisory prose | **the symbol is right there, in backticks** |

From the real text of PYSEC-2026-3552:

> `pkcs7_decrypt_der`, `pkcs7_decrypt_pem`, and `pkcs7_decrypt_smime` reported
> the outcome of decrypting a `RecipientInfo`'s `encryptedKey` …

`suite-core/core/advisory_symbols.py` extracts it deterministically — no LLM, no
network, which matters for an air-gapped deployment, and it is auditable and
testable in a way a model call is not.

## The number, end-to-end against live OSV and the real call graph

```
PYSEC-2026-3552  package= 94  symbol= 0  via pkcs7_decrypt_{der,pem,smime}  RULED OUT
PYSEC-2026-3553  package= 94  symbol= 0  via build_chain_inner              RULED OUT
PYSEC-2026-3554  package= 94             advisory names no symbol           UNDETERMINED

PACKAGE-LEVEL : 3/3 reachable                          →  0% reduction
SYMBOL-LEVEL  : 0/3 reachable, 2/3 ruled out, 1/3 undetermined
```

**Two of three real findings eliminated. The third is carried as undetermined,
not as a win.** This codebase never calls PKCS#7 decryption or the chain-builder
internals, so those two CVEs were never exploitable here — and package-level
analysis would have sent an engineer after both.

The undetermined case is the part that makes the number honest. An advisory that
names no function cannot be ruled out, and `reachability_patterns()` returns an
empty list rather than degrading to `package.%`. That empty list is a
deliberate refusal: the fallback is what produced the 0% figure, and it dresses
"we don't know where the flaw is" as "you use this library".

## One false positive, caught by running it for real

The first end-to-end run "RULED OUT" PYSEC-2026-3554 using `foo.example.com` and
`bar.example.com` as symbols — DNS hostnames from the advisory's wildcard-SAN
example. A hostname is shaped exactly like a module path.

The unit test had passed, because it *paraphrased* that advisory into prose with
no backticks. It agreed with an idea of what advisories look like rather than
with what they say. The test now quotes the real text, and there is a filter for
hostname-shaped paths.

Confidently ruling out a CVE is worse than admitting ignorance about it:
undetermined keeps the finding in the queue where a human sees it.

## What remains

- **Sample size.** Three findings in one package is not a benchmark. The figure
  a buyer should be quoted needs a repo with hundreds of findings across dozens
  of packages, most transitive and untouched — that is where package-level and
  symbol-level diverge most sharply.
- **Coverage of the extractor.** It recovered a symbol from two of three real
  advisories. That ratio is from a sample of three; measure it across a few
  hundred before claiming it.
- **Wire it into ingest.** The extractor exists and is tested; findings do not
  carry the symbol yet. Until they do, this measurement is reproducible from a
  script, not from the product.
