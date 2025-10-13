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

## Running via Unified CLI

```bash
python -m apps.fixops_cli stage-run --stage requirements --input simulations/demo_pack/requirements-input.csv --app life-claims-portal
python -m apps.fixops_cli stage-run --stage design      --input simulations/demo_pack/design-input.json --app life-claims-portal
python -m apps.fixops_cli stage-run --stage build       --input simulations/demo_pack/sbom.json          --app life-claims-portal
python -m apps.fixops_cli stage-run --stage test        --input simulations/demo_pack/scanner.sarif      --app life-claims-portal
python -m apps.fixops_cli stage-run --stage deploy      --input simulations/demo_pack/tfplan.json        --app life-claims-portal
python -m apps.fixops_cli stage-run --stage operate     --input simulations/demo_pack/ops-telemetry.json --app life-claims-portal
python -m apps.fixops_cli stage-run --stage decision    --app life-claims-portal
```

## Ingest API example

```bash
curl -X POST http://localhost:8001/api/v1/artefacts \
  -H "Authorization: Bearer local-dev-key" \
  -F "type=design" \
  -F "payload=@simulations/demo_pack/design-input.json" \
  -F "app_name=life-claims-portal" -F "mode=demo"
```

## End-to-end walkthrough (life-claims-portal demo)

The scripted simulation under `simulations/demo_pack/` exercises every feature of the FixOps ingest pipeline. The following
sections highlight the exact request payloads, the relevant API calls, and the persisted outputs for the canonical demo run.

### Requirements → `outputs/requirements.json`

* **Input:**

  ```csv
  requirement_id,feature,control_refs,data_class,pii,internet_facing,notes
  REQ-1001,"Login page must use CAPTCHA","ISO27001:AC-1;PCI:8.3",confidential,true,true,"BA spec R1"
  REQ-2001,"Claims processing flows A,B,C","ISO27001:AC-2;SOC2:CC6.3",restricted,true,false,"BA spec C1-C3"
  ```

* **Ingress:** `POST /api/v1/artefacts` with `{"type": "requirements", "payload": <CSV|JSON>}`. The Run Registry stores the raw
  submission under `inputs/requirements-input.csv` and normalises it into structured JSON.

* **Output highlights (`requirements.json`):**

  ```json
  {
    "requirements": [
      {
        "requirement_id": "REQ-1001",
        "feature": "Login page must use CAPTCHA",
        "control_refs": ["ISO27001:AC-1", "PCI:8.3"],
        "data_class": "confidential",
        "pii": true,
        "internet_facing": true
      },
      {
        "requirement_id": "REQ-2001",
        "feature": "Claims processing flows A,B,C",
        "control_refs": ["ISO27001:AC-2", "SOC2:CC6.3"],
        "data_class": "restricted",
        "pii": true,
        "internet_facing": false
      }
    ],
    "ssvc_anchor": {"stakeholder": "mission", "impact_tier": "critical"}
  }
  ```

* **Key features surfaced:** SSVC anchor derivation, requirements normalisation, Run Registry input capture.

### Design → `outputs/design.manifest.json`

* **Input:**

  ```json
  {
    "app_name": "life-claims-portal",
    "components": [
      {"name": "login-ui", "tier": "tier-0", "exposure": "internet", "pii": true},
      {"name": "claims-core", "tier": "tier-0", "exposure": "internal", "pii": true},
      {"name": "auth-svc", "tier": "tier-0", "exposure": "internal", "pii": true}
    ],
    "flows": [["internet", "login-ui", "auth-svc"], ["login-ui", "claims-core"]],
    "threat_model_refs": ["tm/login-tm.md", "tm/claims-dfd.md"]
  }
  ```

* **Ingress:** `POST /api/v1/artefacts` with `{"type": "design", "payload": {...}}`.

* **Output highlights (`design.manifest.json`):** deterministic IDs and risk score.

  ```json
  {
    "app_id": "APP-1234",
    "app_name": "life-claims-portal",
    "components": [
      {"component_id": "C-login", "name": "login-ui", "tier": "tier-0", "exposure": "internet", "pii": true},
      {"component_id": "C-claims", "name": "claims-core", "tier": "tier-0", "exposure": "internal", "pii": true},
      {"component_id": "C-auth", "name": "auth-svc", "tier": "tier-0", "exposure": "internal", "pii": true}
    ],
    "flows": [["internet", "login-ui", "auth-svc"], ["login-ui", "claims-core"]],
    "threat_model_refs": ["tm/login-tm.md", "tm/claims-dfd.md"],
    "design_risk_score": 0.78
  }
  ```

* **Key features surfaced:** deterministic ID minting (`app_id`, `component_id`), Run Registry pathing, risk scoring for
  downstream correlation.

### Build → `outputs/build.report.json`

* **Inputs:** CycloneDX-style SBOM, SARIF scanner results, optional SLSA provenance.

  ```json
  {"components": [
    {"name": "openssl", "version": "1.1.1t", "purl": "pkg:generic/openssl@1.1.1t"},
    {"name": "log4j-core", "version": "2.14.0", "purl": "pkg:maven/log4j-core@2.14.0"}
  ]}
  ```

* **Ingress sequence:**
  * `POST /api/v1/artefacts` with `type="sbom"`
  * `POST /api/v1/artefacts` with `type="sarif"`
  * `POST /api/v1/artefacts` with `type="provenance"`

* **Output highlights (`build.report.json`):**

  ```json
  {
    "app_id": "APP-1234",
    "components_indexed": 2,
    "risk_flags": [
      {
        "purl": "pkg:maven/log4j-core@2.14.0",
        "reason": "historical RCE family"
      }
    ],
    "links": {
      "sbom": "../inputs/sbom.json",
      "sarif": "../inputs/scanner.sarif",
      "provenance": "../inputs/provenance.slsa.json"
    },
    "build_risk_score": 0.66
  }
  ```

* **Key features surfaced:** component correlation via minted IDs, risk flagging, provenance tracking, stable references back to
  inputs for auditing.

### Test → `outputs/test.report.json`

* **Input:**

  ```json
  {"coverage": {"lines": 0.73, "branches": 0.61}, "new_findings": [{"id": "SQLi::app/db.py"}]}
  ```

* **Ingress:** `POST /api/v1/artefacts` with `{"type": "tests", ...}` while the SARIF data is reused from the build stage.

* **Output highlights (`test.report.json`):**

  ```json
  {
    "summary": {"critical": 1, "high": 1, "medium": 0, "low": 0},
    "drift": {"new_findings": 1},
    "test_risk_score": 0.52
  }
  ```

* **Key features surfaced:** severity aggregation, drift detection, risk scoring that feeds decision factors.

### Deploy → `outputs/deploy.manifest.json`

* **Input:** Terraform plan delta.

  ```json
  {
    "resources": [
      {"type": "aws_s3_bucket", "name": "payments-logs", "changes": {"after": {"acl": "public-read"}}},
      {"type": "aws_lb_listener", "name": "edge", "changes": {"after": {"protocol": "HTTPS", "ssl_policy": "ELBSecurityPolicy-2016-08"}}}
    ]
  }
  ```

* **Ingress:** `POST /api/v1/artefacts` with `{"type": "tfplan", ...}`.

* **Output highlights (`deploy.manifest.json`):**

    ```json
    {
      "digests": ["sha256:aaaaaaaa..."],
      "control_evidence": [
        {"control": "ISO27001:AC-1", "result": "pass", "source": "tls_policy"},
        {"control": "ISO27001:AC-2", "result": "fail", "source": "public_buckets"},
        {"control": "ISO27001:AC-3", "result": "pass", "source": "checks"},
        {"control": "CIS-K8S:5.4.1", "result": "pass", "source": "checks"},
        {"control": "CIS-K8S:5.2.2", "result": "pass", "source": "checks"},
        {"control": "ISO27001:SC-28", "result": "fail", "source": "encryption_gaps"}
      ],
      "marketplace_recommendations": [
        {
          "control_id": "ISO27001:AC-2",
          "pack_id": "iso-ac2-lp",
          "title": "Least-Privilege Access Playbook",
          "link": "/api/v1/marketplace/packs/iso/ac-2"
        }
      ],
      "posture": {
        "encryption_gaps": ["payments-logs"],
        "open_security_groups": [],
        "privileged_containers": [],
        "public_buckets": ["payments-logs"],
        "tls_policy": "ELBSecurityPolicy-2016-08",
        "unpinned_images": []
      },
      "deploy_risk_score": 0.76
    }
    ```

* **Key features surfaced:** compliance evidence mapping from requirements, automatic marketplace recommendations, digest
  capture for IaC posture checks.

### Operate → `outputs/operate.snapshot.json`

* **Input:** optional runtime telemetry file.

  ```json
  {"alerts": [{"rule": "waf-blocks", "count": 12}], "latency_ms_p95": 580}
  ```

* **Ingress:** `POST /api/v1/artefacts` with `{"type": "ops", ...}`.

* **Output highlights (`operate.snapshot.json`):**

  ```json
  {
    "kev_hits": ["CVE-2021-44228"],
    "epss": [{"cve": "CVE-2021-44228", "score": 0.97}],
    "pressure_by_service": [{"service": "life-claims-portal", "pressure": 0.88}],
    "operate_risk_score": 0.69
  }
  ```

* **Key features surfaced:** KEV/EPSS enrichment, service pressure calculations feeding decision context.

### Decision → `outputs/decision.json` + `outputs/evidence_bundle.zip`

* **Input:**

  ```json
  {
    "app_id": "APP-1234",
    "artefacts": [
      "requirements.json",
      "design.manifest.json",
      "build.report.json",
      "test.report.json",
      "deploy.manifest.json",
      "operate.snapshot.json"
    ],
    "mode": "enterprise"
  }
  ```

* **Ingress:** `POST /api/v1/artefacts` with `{"type": "decision", ...}`. The Run Registry resolves prior outputs based on the
  run folder to guarantee consistency.

* **Output highlights (`decision.json`):**
  * See `simulations/demo_pack/decision.sample.json` for the canonical demo output capturing `top_factors[]`, `compliance_rollup`, and the signed evidence context.

  ```json
  {
    "decision": "DEFER",
    "confidence_score": 0.84,
    "top_factors": [
      {"reason": "Public S3 bucket violates guardrail", "weight": 0.4},
      {"reason": "High EPSS on tier-0 component", "weight": 0.35}
    ],
    "compliance_rollup": {
      "controls": [
        {"id": "ISO27001:AC-1", "coverage": 1.0},
        {"id": "ISO27001:AC-2", "coverage": 0.0}
      ],
      "frameworks": [
        {"name": "ISO27001", "coverage": 0.5}
      ]
    },
    "marketplace_recommendations": [
      {
        "control_id": "ISO27001:AC-2",
        "pack_id": "iso-ac2-lp",
        "title": "Least-Privilege Access Playbook",
        "link": "/api/v1/marketplace/packs/iso/ac-2"
      }
    ],
    "evidence_id": "ev_2025_10_08_123456"
  }
  ```

* **Key features surfaced:** guardrail-aware top factors, compliance rollups, evidence bundle packaging, marketplace guidance,
  and verification support through `GET /api/v1/evidence/{evidence_id}/verify`.

### Evidence handling & transparency

* Unsigned JSON manifests are emitted to `outputs/<name>.json`.
* When signing is enabled, `outputs/signed/<name>.manifest.json` contains an RS256 envelope with the digest and signature.
* `outputs/transparency.index` appends a timestamped ledger entry (`<timestamp> <file> sha256=<digest> kid=<kid>`).
* `outputs/evidence_bundle.zip` aggregates all stage manifests (signed or unsigned) so decision makers and auditors can download
  a single archive.

## Feature coverage summary

Running `python scripts/run_demo_steps.py --app "life-claims-portal"` (optionally alongside the FastAPI server) exercises:

* Unified artefact ingestion via a single endpoint.
* Deterministic ID allocation and run-scoped storage from the Run Registry.
* Risk scoring across design, build, test, deploy, and operate stages.
* Compliance evidence generation and marketplace recommendations for failing controls.
* Decision transparency through top factors, confidence, and rollups.
* Evidence signing, transparency indexing, and verification APIs when signing keys are configured.
* Automated bundling of run artefacts for downstream consumers and governance tooling.

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

## Unified CLI & Ingest API

### CLI: one stage at a time

```bash
python -m apps.fixops_cli stage-run --stage requirements --input simulations/demo_pack/requirements-input.csv --app life-claims-portal
python -m apps.fixops_cli stage-run --stage design      --input simulations/demo_pack/design-input.json --app life-claims-portal
python -m apps.fixops_cli stage-run --stage build       --input simulations/demo_pack/sbom.json          --app life-claims-portal
python -m apps.fixops_cli stage-run --stage test        --input simulations/demo_pack/scanner.sarif      --app life-claims-portal
python -m apps.fixops_cli stage-run --stage deploy      --input simulations/demo_pack/tfplan.json        --app life-claims-portal
python -m apps.fixops_cli stage-run --stage operate     --input simulations/demo_pack/ops-telemetry.json --app life-claims-portal
python -m apps.fixops_cli stage-run --stage decision    --app life-claims-portal
```

### API: upload a stage artefact

```bash
curl -X POST http://localhost:8001/api/v1/artefacts \
  -F "type=design" \
  -F "payload=@simulations/demo_pack/design-input.json" \
  -F "app_name=life-claims-portal" -F "mode=demo"
```

## Running the scripted demo

```bash
uvicorn src.main:app --reload  # optional if you want the HTTP server
python WIP/scripts/run_demo_steps_legacy.py --app "life-claims-portal"
ls artefacts/APP-1234/<RUN>/outputs/
cat artefacts/APP-1234/<RUN>/outputs/decision.json
# optional: verify evidence signatures
curl http://localhost:8001/api/v1/evidence/<EVIDENCE_ID>/verify
```

The script posts each artefact in the order Requirements → Design → Build → Test → Deploy → Operate → Decision, prints stored paths, and (if signing is enabled) verifies each signature envelope.
