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

## What is still owed

- **One-command install.** This verifies the *runtime* is air-gap clean. It does
  not verify that `docker compose up` works on a host that has never pulled an
  image; that needs a bundled image tarball and a disconnected test host.
- **Feed freshness.** The local databases ship with the product, so an
  air-gapped deployment's EPSS/KEV data ages. The verdict already carries
  measured-versus-estimated, but it does not yet carry *how old* the measurement
  is. An operator deciding tonight should see that.
