# Where we actually beat Apiiro and Aikido

Written 2026-08-21. Every claim here was verified by running it — against the
deployed instance where the note says "production", against a rebuilt local
container otherwise. Anything not verified is in the last section, marked as
not yet true. That separation is the point of the document: a competitive claim
that turns out to be aspirational costs more in one sales call than it wins.

---

## 1. The decision, not the list

Every scanner gives a customer a severity. Apiiro adds reachability. EPSS and
KEV give exploitation likelihood. Each is half an answer.

We fuse them into one verdict per finding, computed in the pipeline after both
halves are measured:

| reachability | exploited in the wild | verdict |
|---|---|---|
| reachable | yes | **act now** |
| reachable | no | schedule |
| unreachable | yes | watch — reachability can change |
| unreachable | no | defer |

**The differentiator inside the differentiator is the confidence label.** Each
verdict carries whether its exploit evidence was *measured* (the KEV catalogue,
or an EPSS score from the feeds database) or *estimated* (an EPSS inferred from
severity). "Act now" resting on a guess is a weaker claim than "act now" resting
on the KEV list, and the person deciding what to fix tonight has to be able to
see the difference.

Three rules keep it honest, and each has a test:

- an estimate never promotes priority over a measured signal;
- a finding with no CVE gets **no verdict** rather than a default one — "we do
  not know" is a fact, "low" would be a claim;
- reachability that could not be determined is reported as
  `insufficient_evidence` with a caveat, never as safe.

Verified: 12 tests; verdicts persisted and shown in the finding detail view.

## 2. Evidence that is provably unaltered

The assessor's question is not "do you have a report". It is "can you show this
report has not changed since it was generated, and who has held it".

A generated bundle is written to the operator-managed evidence root, hashed by
its **file bytes**, and sealed into a chain of custody at the moment it exists.
Verification re-reads the artifact and re-computes the hash.

Proven by tampering, not asserted. A sealed bundle was edited on disk to claim
`overall_status: effective` and `controls_effective: 999` — the self-serving
edit someone would actually make — and verification returned:

```
hash_match: false     content_integrity: "tampered"
```

Before the edit it returned `hash_recomputed: true`, which is the part that
matters: "verified" means nothing unless the bytes were re-read.

Verified in production: generate → seal → verify returns
`recomputed: true, match: true, integrity: verified`.

## 2b. …and provably ours

Sealing answers "is this the same file". A signature answers "did it come from
you, and can you deny it later".

Every generated bundle is signed RSA-PKCS1v15-SHA256 over its content hash, and
the signature is persisted beside the artifact so it can be checked again. Both
halves are verified independently, because they fail for different reasons: the
artifact must still hash to what we recorded (tamper), and that hash must carry
our signature (provenance). A forged signature and a malformed one both return
`signature_valid: false` rather than crashing — an assessor asking "is this
authentic?" must never receive a stack trace in place of an answer.

**An auditor can verify without us.** `scripts/verify_evidence_bundle.py`
imports nothing from FixOps and needs no network or database — only the bundle,
its `.sig.json` record, and the public key from
`GET /api/v1/evidence/public-key`. Verified in test: exit 0 on an untouched
bundle, exit 1 with `NOT VERIFIED` on an edited one.

That matters more than it sounds. Every competitor's evidence is only as
trustworthy as their own console; ours can be checked on an air-gapped machine
by someone who does not trust us at all.

## 3. The customer's own risk model

Apiiro's knowledge graph is closed: their entity types, their relationships,
their rules. That holds until a customer's model contains a concept the vendor
never built — "this service is in the cardholder data environment", "this repo
is under regulatory hold", "these dependencies are approved for the classified
enclave". If you cannot express it, you cannot decide with it.

A tenant can declare its own entity types, attach entities, and write rules
saying what a match means for them. The pipeline applies those rules to real
findings.

Verified live:

```
POST /api/v1/graph/types     -> cardholder_data_environment
POST /api/v1/graph/entities  -> payments-db
POST /api/v1/graph/rules     -> "CDE assets escalate"

payments-db      priority 3 -> 2, labels [pci-scope], rules [CDE assets escalate]
marketing-site   priority 3 (untouched)
```

Three properties make this safe to offer rather than merely clever:

- **Tenant isolation.** A second tenant sees `types: 0, rules: 0` — verified.
- **Attribution.** Every change records which rule made it. A priority that
  moved for reasons a customer cannot reconstruct is exactly the opacity they
  are trying to escape.
- **Rules cannot invent measurements.** They move priority and attach labels.
  `action: set_reachable` is refused with HTTP 400. A customer rule must never
  make the product assert something it has not observed.

The rule grammar is published at `GET /api/v1/graph/vocabulary` rather than
discovered by trial and error.

## 4. Ingest-first, not another scanner

We normalise other tools' output rather than competing with them. Walked end to
end with real trivy output from this repository (46 findings), in production:

```
INGEST   46 findings -> the uploader's own tenant
SEE      33 after deduplication
TRIAGE   HTTP 200
READBACK accepted_risk
```

`accepted-risk` is a first-class status rather than folded into "suppressed",
because accepting risk is a governance decision with an owner, and collapsing it
into a dismissal erases the record an assessor asks for.

## 5. Deployable where they are not

`FIXOPS_PROFILE=scif` fails closed rather than degrading. The air-gapped council
mechanic is proven — two local models, independent reasoning, zero egress —
though it is hardware-bound and unproven at production speed (see below).

---

## Not yet true

Listed so nobody sells them by accident.

- **Air-gapped council is hardware-bound.** The mechanic works; on laptop CPU
  the six-key verdict prompt exceeds ten minutes and falls back to labelled
  heuristics. Unproven on inference-sized hardware.
- **Reachability's noise reduction is unmeasured on a customer repo.** The
  mechanism is proven (42,796 edges in 6.2s). The percentage of findings it
  filters for a real customer is not yet a measured number, and must not be
  quoted as one.
- **Two evidence subsystems remain unfed.** `evidence-collector` and
  `evidence-vault` return zeros. They are no longer advertised on the customer
  surface, which stops the confusion, but they are either features or dead
  weight.
- **Duplicate routes.** `GET /api/v1/findings` has three registered handlers and
  only the first is reached. It is real architecture debt: it makes a correct fix
  land somewhere no request goes, which happened twice while this work was done.
