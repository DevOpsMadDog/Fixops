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

---

# At scale: 119 real findings, 475 packages

The three-finding sample above was never a benchmark. This is the same method on
a real environment scan.

```
pip-audit (whole environment)   475 packages, 120 findings, 24 distinct packages
call graph                       42,874 nodes from suite-core/core
advisories                       fetched live from OSV (1 fetch failure, excluded)
```

## The funnel

| stage | result |
|---|---|
| findings ingested | **119** |
| package-level reachable | **20 / 119 — 17%** |
| …of those, symbol-level ruled out | 3 |
| …of those, undetermined (advisory names no symbol) | 17 |
| **must act on** | **17 / 119 — 14%** |
| **eliminated** | **102 / 119 — 86%** |

## Read this honestly

**Most of the reduction is package-level, not symbol-level.** 83 of the 86
points come from "this package is never called from our code at all". Symbols
add 3 findings. On the three-CVE sample symbols looked like the whole story;
at scale they are a refinement on top of a much blunter filter that does most
of the work.

**Symbol recall is 30%, not 67%.** The extractor recovered a symbol from 36 of
119 advisories. The earlier 2-of-3 was a small-sample artifact, exactly as the
caveat above predicted. Recall is now the limiting factor: 17 findings sit in
*undetermined* purely because their advisory never names a function.

**The graph-scope threat was real but small — measured, not assumed.** The first
run used a `suite-core/core` graph, so a package used elsewhere in the repo
would have scored "not called". Rather than caveat it, I built the whole-repo
graph (**72,050 nodes across all six suites, 15 seconds**) and re-ran the same
119 findings:

| graph | package-reachable | actionable | eliminated |
|---|---|---|---|
| suite-core/core — 42,874 nodes | 20/119 | 17/119 | **86%** |
| whole repo — 72,050 nodes | 24/119 | 19/119 | **84%** |

Widening the graph by 68% moved the result by two points. Four findings changed
from "never called" to "reachable", which is exactly the direction a wider graph
should move things, and the figure is stable enough to quote.

**84% eliminated / 16% actionable, on a whole-repo graph** is the number.

## A measurement bug found by measuring

The first run at scale reported **more** symbol-level reachable findings than
package-level — impossible if the symbol query refines the package query.

`AdvisorySymbols.reachability_patterns(package)` accepted a `package` argument
and never used it, so a bare symbol pattern like `%build_chain_inner%` matched a
function of that name in *any* package. A parameter that looks like it scopes
and does not is worse than no parameter, because every caller reads it as
scoping. Fixed to emit `cryptography.%build_chain_inner%`, and the funnel became
monotonic.

## What can be quoted, and what cannot

Quotable: **84% of findings eliminated, 16% requiring action**, on a real
475-package environment against a whole-repo call graph.

Not quotable: any claim that symbol-level reachability is what produces that
number. It is not — package-level does. The symbol work matters for a different
reason: it is what will move the 17 *undetermined* findings, and undetermined is
the category a customer actually feels, because those are the ones nobody can
close.


---

# Recall, and why a higher recall did not move the headline

Recall was the limiter: the extractor found a symbol in only 30% of advisories,
so most package-reachable findings sat *undetermined*. Looking at the 59 misses
rather than guessing at them:

| signal present in a missed advisory | count |
|---|---|
| names a call like `CookieJar.load()` | **25** |
| names a dotted call | 9 |
| has backticks the filters rejected | 7 |

The fix follows from the data. Advisories write calls as ``CookieJar.load()`` —
RST double backticks, which the single-backtick pattern never saw — and the
CamelCase filter rejected the receiver. That filter is right about a *type*
(`RecipientInfo` is what the flaw operates on) and wrong about a *method call*
(`CookieJar.load()` is an entry point). **The parentheses are the difference.**

Matching on the parentheses instead took recall from **30% to 64%**.

## Then the audit, which mattered more than the recall

Listing every finding the symbols eliminated showed three resting on:

    cookies        session_id        allowed_hosts

A noun, a parameter, and a config key. Finding no `session_id` in a call graph
says *nothing* about whether a vulnerability is reachable — yet it was deleting
findings from the queue. Higher recall had bought a worse product.

So rule-outs now require **call-shaped evidence**. `can_rule_out` is true only
for a symbol recovered from an actual call or a dotted path; anything weaker may
still be reported but leaves the finding UNDETERMINED, where a human sees it.
This is the same measured-versus-estimated line the verdict engine already
draws.

## The result

| | before recall work | after |
|---|---|---|
| symbol recall | 30% | **64%** |
| symbol rule-outs | 3 | **5** |
| undetermined | 19 | 16 |
| **actionable** | 19/119 — 16% | **19/119 — 16%** |
| **eliminated** | 84% | **84%** |

The headline did not move, and that is the point. What changed is that all five
remaining eliminations trace to a named call — `CookieJar.load`, `click.edit`,
`mcp.server.websocket.websocket_server` — and the three unsound ones moved into
undetermined rather than being silently deleted.

A number that stays put while the reasoning under it gets sounder is the
outcome to want. Had the audit not run, this work would have shipped an
improvement to 87% that was partly built on searching a call graph for the word
"cookies".

---

# The product reproduces the measurement

Everything above was computed by a script driving the engine directly. This is
the same 96 findings through the actual product — ingest, symbol extraction,
call graph, pipeline, verdict, store:

```
tenant onboarded with scripts/onboard.sh (REPO_PATH set)
  call graph            42,906 python nodes, tenant-scoped
  scan                  real pip-audit output, 120 findings -> 96 after dedup

  reachability   unreachable 80 | reachable 4 | undetermined 12
  asked by       symbol 61 | package 35
  verdict        defer 79 | schedule 4 | watch 1 | insufficient_evidence 12

  ELIMINATED     80/96 = 83%
```

The script measured **84%**. The product measures **83%**. Two independent paths
over the same data landing within a point of each other is the strongest
evidence available that the number is real and that the pipeline implements what
the measurement described.

The 12 undetermined are the honest remainder: their advisories name no function,
so nothing can settle them, and they stay in the queue as
`insufficient_evidence` rather than being closed.

## What had to be true for this to work

Onboarding must build the tenant's call graph. Reachability refuses to rule
anything out without coverage (see the Java-graph incident below), so a tenant
onboarded without `REPO_PATH` gets `undetermined` for everything — honest, and
worth nothing. `scripts/onboard.sh` now does it, and says plainly what is lost
when it is skipped.

---

# Browser-verified, on the real product

The numbers above are API-level. This is the Decide screen rendering them, with
a real pip-audit scan, a real 42,910-node call graph, and the pipeline having
actually run:

```
Assessed 96          Measured 0     Estimated 1     Not assessed 2

Triage reduction — 96 analysed
  83%  ELIMINATED         80 never reached from your code
  16   YOU MUST ACT ON    17% of analysed
  12   UNDETERMINED       advisory names no function
  61   ASKED BY SYMBOL    function-level
```

Rows carry real CVE ids with `Defer` on unreachable and `Schedule` on reachable.

## Two things on that screen are worth defending

**"Measured 0" is correct, not a bug.** Every one of the 96 EPSS scores is
marked *estimated*, and the reason is honest: the shipped feed's newest entry is
`CVE-2026-6328`, while these findings are `CVE-2026-49855` and later — **newer
than the 135-day-old feed**. The product cannot look them up, so it says so
rather than presenting a synthesised score as measured. This is the staleness
problem surfacing exactly where it should.

**"Evidence used —" is also correct.** No finding is in KEV and only one exceeds
the EPSS-high threshold, so there is genuinely no exploit evidence to show. An
empty column here is the product declining to invent one.

Checked that the online and air-gapped paths enrich identically on the same data
(`kev=0, epss>0=96` both ways, differing only in `_enrich_source`), so the sparse
evidence is a fact about these CVEs and the feed's age — not a defect in either
path.

---

# Does the number hold on someone else's code?

84% was measured on this repository. A triage figure that only holds on its own
codebase is worth nothing to a buyer, so the same 119 advisories were put to a
second, unrelated codebase: **Apache Airflow**, cloned fresh, 118,302 call-graph
nodes parsed in 29 seconds.

| codebase | graph | package-reachable | actionable | eliminated |
|---|---|---|---|---|
| FixOps | 72,050 nodes | 24 | 19/119 | **84%** |
| Apache Airflow | 118,302 nodes | 25 | 22/119 | **82%** |

**Two points apart, on codebases that share no code.** The elimination rate is a
property of how narrowly a vulnerability's reachable surface sits inside a
typical Python application, not an artifact of our repository.

Airflow's own `uv.lock` is worth noting separately: `osv-scanner` found **one**
vulnerable package in it. Modern, well-maintained lockfiles largely are clean,
which is why the finding volume that makes triage painful comes from the
*installed environment* — 475 packages and 120 findings here — rather than from
declared direct dependencies. That is a fact about where the noise actually
lives, and it is the case the product should be sold against.

## What this still does not establish

Both codebases are Python. The extractor, the call-graph parser and the symbol
patterns are all language-shaped, and nothing here says the figure transfers to
a JavaScript or Java estate. The engine parses TypeScript and Java, so the
measurement is repeatable — it simply has not been repeated.

---

# The second ecosystem: TypeScript gives 57%, not 84%

The Python figure had no right to be assumed portable, so it was tested. Real
`npm audit` output from this repo's own UI — 23 advisories across 6 packages —
against a TypeScript call graph of 12,590 nodes parsed in 5.1 seconds.

```
TypeScript (12,590 nodes)
  package-reachable 10   reachable 0   undetermined 10
  ACTIONABLE 10/23 = 43%      ELIMINATED 57%
```

**57%, against 82–84% for Python.** That is the honest number for a JavaScript
estate today, and it should be quoted as such rather than averaged away.

## Why, exactly

Every one of the ten package-reachable findings came back *undetermined*, and
the cause is not the engine. `npm audit --json` gives an advisory **title** and
no prose body. Measured on eight of them:

| source | symbol recovered |
|---|---|
| npm audit title only | **0 / 8** |
| the same advisory's OSV body | **8 / 8** |

So the gap is data, not method: the symbol exists, `npm audit` just does not
carry it. Fetching the GHSA/OSV body — or shipping it in the local feed bundle,
which an air-gapped site needs anyway — would close most of it.

## The trap that came with it

The OSV bodies did yield symbols, and some of them were rubbish:

```
index.js      index.d.ts        <- filenames
config.proxy  req.body          <- object properties
server.address
```

JavaScript advisories name files constantly ("the fix is in index.js") and
describe data flow through properties. Ruling a finding out because the codebase
never calls something named `req.body` is precisely the `cookies` /
`session_id` mistake from the Python work, arriving again in a new ecosystem —
and this time it would have been *introduced by expanding coverage*.

The extractor now rejects dotted tokens whose last segment is a source-file
extension, and those whose head is a known request/config/response root. A real
call like `axios.formToJSON()` still survives.

## What may be claimed

- **Python: 82–84% eliminated**, measured on two unrelated codebases.
- **TypeScript: 57% eliminated**, limited by advisory metadata rather than by
  analysis, with a identified path to improve it.
- **Java: not measured.** The engine parses it; nobody has run the numbers.

Quoting a single blended figure across ecosystems would be the most flattering
and least defensible way to present this.

---

# Closing the JS gap — and the 87% that was not real

`npm audit` carries no advisory prose, so `scripts/fetch_advisory_bodies.py`
stores the OSV bodies in `feeds.db` (table `advisory_details`) and ingest reads
them from there. Deliberately **not** a live fetch: the bodies travel in the
signed feed bundle, so an air-gapped site gets the same extraction as a
connected one. 118 advisories stored across both ecosystems.

That alone moved TypeScript from 57% to **87%** — and the audit killed it.

## What the 87% was resting on

Listing the individual rule-outs, as every win here has to be:

```
index.d.cts        a filename
v1.x               a VERSION STRING
JSON.stringify     a language builtin
proxy.address      an object property
auth.username      an object property
```

Each searched the call graph, matched nothing, and produced a confident
"unreachable". This is the `cookies` mistake running the other way: there a real
finding was closed on a noun; here on a filename. **Extraction recall improved
and precision collapsed, and the headline number went up because of it.**

## The fix: the symbol's head must be the package

`AdvisorySymbols.rule_out_symbols(package)` keeps a dotted symbol only when its
head *is* the vulnerable package — `axios.formToJSON` for axios. Then the
advisory is naming that package's own API, which is exactly what a call graph
can answer. Bare calls with no dot (`pkcs7_decrypt_der`) are kept, because that
is how Python advisories name functions.

`v1.x` and `.cts`/`.mts` filenames are now rejected outright too.

## The numbers after tightening

| codebase | graph | actionable | eliminated |
|---|---|---|---|
| Python / FixOps | 72,050 | 19/120 | **84%** |
| Python / Airflow | 118,302 | 22/120 | **82%** |
| TypeScript / UI | 12,590 | 2/23 | **91%** |

Python is unchanged, which is the point — the tightening had to not regress the
measurement it was not aimed at. It did make Python *more* conservative
(undetermined 16 → 19), which is the right direction.

## Is the 91% real?

One rule-out was checked by hand because it looked wrong: `GHSA-mmx7-hfxf-jppx`
was closed on `axios.get`, and this codebase certainly uses axios.

```
axios.%        ->   5 callers   (the graph does see axios)
axios.get%     ->   0 callers
grep "axios.get(" src/   ->  no matches
```

axios is imported in five files and called through instances, never as
`axios.get`. The rule-out is correct.

**But the sample is weak** and the number should carry that: 23 advisories
across 6 packages, almost all axios, against one small UI. Compared with 120
advisories over 24 packages for Python, this is a single-library result. It is
evidence that the method transfers to TypeScript, not yet a figure to quote.
