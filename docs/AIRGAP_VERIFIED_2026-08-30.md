# Air-gapped operation, verified by blocking the network

Air-gap is the flank we sell hardest — Apiiro's loudest on-premises complaint is
performance, and neither competitor is in the SCIF market. It had never been
tested. This is the test: every outbound socket blocked at the Python level, then
the whole value path run against real data.

## Method

`socket.socket.connect` is patched to raise on any address that is not loopback,
counting what was attempted. Nothing is mocked below that line — the real
pipeline, the real 120-finding pip-audit scan, the real advisory text.

## Result 1 — the app boots with no network at all

```
BOOT_OK routes: 7951
OUTBOUND_ATTEMPTS {}
```

Not one connection attempted during import or `create_app()`. Nothing about
startup requires the internet.

## Result 2 — the value path completes offline, and stays honest

```
INGEST     120 parsed, 81 symbol-enriched, 96 after dedup
PIPELINE   COMPLETED
REACH      undetermined 96
VERDICT    insufficient_evidence 95, exploited_unknown_reach 1
BLOCKED    12 hosts attempted (NVD, CISA, FIRST.org, abuse.ch)
```

Two things matter here.

**It did not fabricate.** With the feeds unreachable the verdicts became
`insufficient_evidence`, not a confident-looking score. That is the behaviour the
whole product rests on, and it survived the network being taken away.

**Symbol extraction still worked** — 81 of 120 findings enriched. It is
deterministic and local by design, precisely so that an air-gapped deployment
gets the same triage quality as a connected one.

## Result 3 — the fix: enforced air-gap stops reaching out

Twelve connection attempts per run is not a correctness problem, but in a SCIF
each one is a connect timeout, on every pipeline run, for a network we told the
customer they do not need. `_step_enrich_threats` now consults
`is_airgap_enforced()` before trying live feeds.

With `FIXOPS_AIRGAP_MODE=enforced`:

```
PIPELINE   COMPLETED   offline flag: True
VERDICT    exploited_unknown_reach 75, insufficient_evidence 21
BLOCKED    0 hosts
```

**Zero outbound attempts** — and the verdicts got *better*, not worse. Skipping
the doomed live calls goes straight to the local feed databases (317K EPSS +
1.5K KEV rows shipped with the product), so 75 findings gained real exploit
evidence that the failing-network path never reached.

Air-gapped is not a degraded mode of this product. On a disconnected host it is
strictly better than a connected host with a broken network, because it stops
pretending the network might answer.

## The install path

The runtime being air-gap clean is not the same as the install working. The
default `docker-compose.yml` **builds from source**, which needs
`python:3.11-slim`, `node:20-alpine`, `nginx:1.27-alpine` and then pip and npm
against public registries. On a disconnected host that cannot work, so "one
command" has to mean the images arrive already built.

```
connected host      ./scripts/build_airgap_bundle.sh
disconnected host   docker load -i fixops-airgap-<version>.tar
                    docker compose -f docker-compose.airgap.yml up -d
```

`docker/docker-compose.airgap.yml` never builds and never pulls
(`pull_policy: never`), and sets `FIXOPS_AIRGAP_MODE=enforced` itself rather
than trusting the operator to remember. Verified: the file parses with **zero
build directives**.

Two things it deliberately leaves out. **The demo-seed service** — it exists
behind a `seed` profile in the default compose and must never be reachable
here, because an air-gapped customer evaluating the product must not find
fabricated findings in their tenant. And the **third-party services**
(Dependency-Track, n8n, Shuffle, LocalStack), which have their own images and
their own air-gap stories and are not on the value path.

## The feeds, which the whole offline story rests on

Checked rather than assumed:

```
data/feeds/feeds.db    327,252 EPSS scores
                         1,568 KEV entries
                 last refreshed 2026-04-16 — 135 days old
```

The data is real and substantial. It is also **stale**, well past the 30-day
threshold — which is exactly why the verdict now carries
`exploitability_evidence_age_days` and flags staleness per finding. An
air-gapped site never refreshes these, so a bundle built today ships 135-day-old
KEV data and the product will say so on every verdict that rests on it.

The build script checks both presence and age, and warns rather than shipping
blind. Two field-name slips were caught writing that check — the table is
`epss_scores` not `epss`, the column is `last_refresh` not `updated_at`. Both
would have reported "?" for a perfectly good bundle and taught the operator to
ignore the warning. Same class of defect as the `cve_id`/`rule_id` mismatch that
cost four bugs elsewhere: verify a query against the real schema.

## What is still owed

- **A disconnected test host.** Everything above is verified by blocking sockets
  and by parsing the compose file. Nobody has yet run `docker load` on a machine
  with no route to the internet. Until someone does, this is a well-founded
  expectation, not a demonstration.
- ~~A feed refresh path for air-gapped sites~~ **DONE** — see below.


---

# The carry-in feed refresh

`scripts/feed_bundle.py` closes the staleness gap named above.

```
connected host      python scripts/feed_bundle.py export
sneakernet          fixops-feeds-<date>.tar.gz  +  .sig.json
air-gapped host     python scripts/feed_bundle.py verify <bundle>
                    python scripts/feed_bundle.py import <bundle> --apply
```

The bundle is signed with the **same RSA key the evidence bundles use**, and
`verify` is deliberately a separate command: a feed database that crossed an air
gap on removable media is precisely the artifact whose provenance matters, and a
swapped one would silently change every exploitability verdict the site
produces.

Verified end to end on the real 327,252-row database:

```
export    11.4 MB, signed, key 0be15c5769d447b6
verify    hash matches, signature valid (key 0be15c5769d447b6…)     exit 0
tamper    append one byte -> CONTENT HASH MISMATCH                  exit 1
import    tampered  -> REFUSING to import an unverified feed bundle exit 1
          genuine   -> EPSS None -> 327252, KEV None -> 1568, integrity ok
```

`import` refuses an unverified bundle unless the operator passes
`--allow-unsigned`, and that override is written into `feed_metadata` as
`_import_provenance` with status `unverified` — so a deployment cannot quietly
forget that its exploit intelligence arrived unchecked. The previous database is
copied aside before replacement, and a staged file that fails `integrity_check`
is never installed: a half-written feed database is worse than a stale one,
because the verdicts it produces look current.

One bug worth recording from building it: `verify()` takes `(data, signature)`,
and I called it with a third argument. `_verify` caught the `TypeError` and
reported "could not verify" — a broken verifier that reports failure is
survivable; one that reported *success* would not be. The fingerprint is now
checked separately, because a valid signature from an unexpected key is not the
same as a valid signature from ours.
