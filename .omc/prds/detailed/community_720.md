# PRD — Community 720: SLSA Provenance Attestation Service

**Domain:** Supply-Chain Security / SLSA Compliance
**Status:** In Progress
**Effort:** M – 3–5 days (engine exists; wire API endpoint + tests)
**Personas:** DevSecOps Engineer, Compliance Officer, Security Architect
**Generated:** 2026-04-16

---

## Master Goal Mapping

Generate, sign, and verify SLSA v1 in-toto attestations for all build artefacts, enabling end-to-end supply-chain integrity across ALDECI pipelines.

### ALDECI Alignment
- Platform: ASPM + CTEM + CSPM
- Engine location: `suite-core/services/provenance/attestation.py`
- Graph community: 720 (1 source file)

---

## Architecture Diagram

```mermaid
graph TD
    A[Build Pipeline] -->|artefact + metadata| B[attestation.py]
    B -->|create_envelope()| C[In-toto Envelope]
    C -->|RSA-SHA256 sign| D[Signed DSSE Bundle]
    D --> E[TrustGraph KnowledgeStore]
    D --> F[/api/v1/provenance endpoint]
    F --> G[Compliance Dashboard]
    B -->|verify_envelope()| H[ProvenanceVerificationError?]
```

---

## Source Files

- `suite-core/services/provenance/attestation.py`

**Graph node label (truncated):** `Create an envelope from an in-toto statement.          Args:             stateme`
**Source location:** `L519`

---

## Code Proof

suite-core/services/provenance/attestation.py:L519 – create_envelope(); L1-60 – module docstring, SLSA_VERSION='1.0', IN_TOTO_STATEMENT_TYPE, RSA sign/verify optional import

---

## Inter-Dependencies

### Peer Communities (720–809)
None

### External Community Links
None

---

## Data Flow

1. Source file belongs to community 720 in the graphify knowledge graph (1 node, isolated cluster).
2. Linked communities: none detected.
3. Python module participates in ALDECI request/response flow via FastAPI router imports.

---

## Referenced Docs

- `docs/ALDECI_REARCHITECTURE_v2.md`
- `https://slsa.dev/provenance/v1`
- `https://github.com/in-toto/attestation`

---

## Acceptance Criteria

- [ ] POST /api/v1/provenance/attest returns signed envelope with slsaVersion=1.0
- [ ] GET  /api/v1/provenance/verify validates RSA-SHA256 signature or returns 400
- [ ] ProvenanceVerificationError raised on tampered payload
- [ ] Telemetry counter fixops_provenance_operations increments on each call
- [ ] 35+ pytest tests covering sign/verify/error paths

---

## Effort Estimate

**M – 3–5 days (engine exists; wire API endpoint + tests)**

| Task | Points |
|------|--------|
| Understand file purpose | 1 |
| Wire router to app.py + 35 tests | 5 |
| API endpoint smoke test | 2 |

---

## Status

**In Progress**

> Engine file exists. Next action: create `suite-api/apps/api/provenance_router.py`, wire to `app.py`, write 35+ tests.
