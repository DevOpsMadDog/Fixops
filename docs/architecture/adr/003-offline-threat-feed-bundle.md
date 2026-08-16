# ADR-003 — Offline threat-feed bundle for air-gapped enrichment

**Status:** Proposed
**Date:** 2026-08-17
**Depends on:** ADR-001

---

## Context

Enrichment is the step that turns an ingested finding into a prioritised one, and it is
demonstrably real: the running system holds **1,665 CISA KEV CVEs** (20.96%
ransomware-linked), **360,142 FIRST EPSS scores**, and **2,000 NVD CVEs**, with pipeline
runs reporting `enrichment_source="real_api"`, `kev_matches=1`, `epss_api_hits=1`.

All of it arrives by outbound HTTP. Under `FIXOPS_PROFILE=scif` (ADR-001) that fetch
cannot happen, which would reduce enrichment to CVSS-only — and CVSS-only prioritisation
is precisely the commodity behaviour our pitch says we replace. **Air-gapped enrichment
is therefore not a nice-to-have; without it the SCIF product loses its main claim.**

Air-gapped sites already have an established pattern for this: content is transferred on
removable media through a review process. The requirement is not connectivity, it is a
**verifiable, dated, signed artifact** that an accreditor can reason about.

There is a second, subtler requirement. In an accredited environment, "how did this
finding get its score?" must be answerable months later. A live API call is not
reproducible; a versioned bundle is.

## Decision

**Publish threat intelligence as a signed, versioned offline bundle, and make the
air-gapped path a first-class ingest source rather than a degraded mode.**

1. A build job produces `fixops-feeds-<UTC-date>.bundle` containing the KEV catalogue,
   the EPSS daily scores, and the NVD CVE set, plus a manifest recording each source
   URL, its fetch timestamp, and a digest per file.
2. The bundle is **signed with the same hybrid RSA-4096 + ML-DSA-65 scheme already used
   for evidence** (`dilithium-py` is installed and verified working, so this is real
   post-quantum signing, not an RSA fallback). Import verifies the signature and
   **refuses an unsigned or tampered bundle**.
3. Import is idempotent and additive-by-version: importing the same bundle twice is a
   no-op; importing an older bundle over a newer one is refused.
4. Enrichment records **which bundle version produced each score**, so a prioritisation
   decision remains explainable after the fact.
5. Staleness is surfaced, never hidden: the UI and API report the bundle's age, and past
   a configurable threshold enrichment is labelled stale rather than silently trusted.

## Consequences

- We take on a release obligation: bundles must be produced on a schedule, or SCIF
  customers drift. This is an operational cost we accept.
- Bundle size is material (the EPSS set alone is ~360k rows) and must be chunkable for
  transfer media.
- The commercial profile can use the same importer, which gives us a tested restore path
  and a way to pin feeds for reproducible demos.
- We gain an accreditation-friendly property: enrichment provenance is a signed artifact
  with a date, not an unlogged outbound call.

## Verification

- A test imports a bundle with a corrupted digest and asserts it is refused.
- A test asserts KEV/EPSS lookups return identical results after live sync and after
  bundle import of the same date.
- Under `scif`, a pipeline run enriches a finding with `kev_matches >= 1` while the
  egress guard is enforced and no outbound connection occurs.
