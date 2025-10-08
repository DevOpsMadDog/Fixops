# FixOps Demo I/O Contract

This document captures the canonical input/output contract for the FixOps demo pipeline that spans requirements through decisioning. It mirrors the "Demo I/O Contract + Full Simulation" brief and describes how artefacts are ingested, normalised, and persisted for every stage.

## Stage overview

| Stage | Input artefact | Processing highlights | Canonical output |
|-------|----------------|-----------------------|------------------|
| Requirements | `requirements-input.csv` (or JSON) | Parse business intake, normalise `control_refs`, derive SSVC anchor | `requirements.json` with `requirements[]` and `ssvc_anchor` |
| Design | `design-input.json` | Mint `app_id`/`component_id`, compute risk heuristics | `design.manifest.json` |
| Build | `sbom.json`, `scanner.sarif`, optional `provenance.slsa.json` | Correlate components, flag risky packages, wire stable links to inputs | `build.report.json` |
| Test | `tests-input.json` + SARIF reuse | Summarise severities, drift, compute risk score | `test.report.json` |
| Deploy | `tfplan.json` | Detect public resources & TLS posture, map controls to evidence, fetch marketplace packs | `deploy.manifest.json` + `marketplace_recommendations[]` |
| Operate | `ops-telemetry.json` (optional) | Surface KEV/EPSS hits and pressure metrics | `operate.snapshot.json` |
| Decision | `decision-input.json` | Resolve previous outputs, compute compliance rollups & top factors, bundle evidence | `decision.json` + `evidence_bundle.zip` |

Each output is persisted under `artefacts/<APP>/<RUN>/outputs/` with unsigned JSON. When signing keys are configured the run registry emits `outputs/signed/<name>.manifest.json` envelopes and appends to `outputs/transparency.index`.

## Linkages

* **Design → Build/Test:** component identifiers minted in `design.manifest.json` tag SBOM/SARIF matches, enabling component-level risk tracking.
* **Requirements → Deploy:** control references from `requirements.json` drive `deploy.manifest.json.control_evidence[]` and power marketplace recommendations for failing controls.
* **Operate → Decision:** runtime pressure and KEV/EPSS hits bubble into `decision.json.top_factors[]` to explain defer/block outcomes.
* **All → Decision:** `decision-input.json.artefacts[]` is resolved via the run registry so the decision stage can load consistent canonical outputs.

## Cryptographic evidence

If `FIXOPS_SIGNING_KEY` and `FIXOPS_SIGNING_KID` are present the registry signs each stage manifest using RS256 and records transparency lines (`<timestamp> <file> sha256=<digest> kid=<kid>`). The Evidence API exposes `GET /api/v1/evidence/{id}/verify` which re-hashes and validates signature envelopes.

## Marketplace integration

Marketplace packs live under `marketplace/packs/<framework>/<control>/`. The deploy and decision stages call `src.services.marketplace.get_recommendations()` to attach remediation packs for failing controls (e.g. `ISO27001:AC-2` → `iso-ac2-lp`). The public API exposes `GET /api/v1/marketplace/packs/{framework}/{control}` for demo consumption.

## Running the scripted demo

```bash
uvicorn fixops-blended-enterprise.server:app --reload  # optional if you want the HTTP server
python scripts/run_demo_steps.py --app "life-claims-portal"
ls artefacts/APP-1234/<RUN>/outputs/
cat artefacts/APP-1234/<RUN>/outputs/decision.json
# optional: verify evidence signatures
curl http://localhost:8001/api/v1/evidence/<EVIDENCE_ID>/verify
```

The script posts each artefact in the order Requirements → Design → Build → Test → Deploy → Operate → Decision, prints stored paths, and (if signing is enabled) verifies each signature envelope.
