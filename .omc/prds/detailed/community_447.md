# PRD — Community 447: SBOM Generator — Parse OpenVEX Method

## Master Goal Mapping
- **Platform Goal**: Parse OpenVEX JSON documents into typed VEXStatement objects for supply chain vulnerability tracking
- **Persona**: DevSecOps Engineer, Supply Chain Security Lead
- **ALDECI Pillar**: Supply Chain Security / SBOM / VEX
- **Backend**: `suite-evidence-risk/risk/sbom/generator.py`

## Architecture Diagram
```mermaid
graph TD
    A[SBOMGenerator] --> B[parse_openvex(vex_json: str)]
    B --> C[json.loads vex_json]
    C --> D[VEX context: document_id + timestamp + author]
    D --> E[statements array iteration]
    E --> F[VEXStatement: vuln_id + status + justification + products]
    F --> G[Returns: List of VEXStatement]
    G --> H[sbom_export_engine.py: attach VEX to SBOM]
    G --> I[SLSAProvenance: display VEX status]
```

## Code Proof
- **File**: `suite-evidence-risk/risk/sbom/generator.py`
- **Node label** (from graph): `"Parse an OpenVEX JSON document into VEXStatement objects."`
- **SBOMFormat enum**: `CYCLONEDX = "cyclonedx"`, `SPDX = "spdx"`
- **Dependency dataclass**: name, version, package_manager, purl, license, source_file, confidence, is_transitive, depth, parent

## Inter-Dependencies
- **Upstream**: OpenVEX JSON from NVD, OSV, GitHub Advisory, or manual attestation
- **Downstream**: `sbom_export_engine.py` (CycloneDX 1.4 + SPDX 2.3) — embeds VEX in export
- **UI**: SLSAProvenance dashboard displays VEX status per component
- **Related**: `sbom_engine.py` in suite-core

## Data Flow
```
VEX JSON from vendor/NVD/OSV →
parse_openvex(vex_json) →
[VEXStatement(vuln_id='CVE-2021-44228', status='not_affected',
              justification='vulnerable_code_not_in_execute_path', products=['log4j:2.14.1'])] →
sbom_export: embed statements in CycloneDX vulnerabilities section
```

## Referenced Docs
- OpenVEX spec: https://github.com/openvex/spec
- CycloneDX VEX support: https://cyclonedx.org/capabilities/vex/

## Acceptance Criteria
- [ ] Parses valid OpenVEX JSON without error
- [ ] Returns typed VEXStatement list
- [ ] Handles all 4 VEX statuses: affected/not_affected/fixed/under_investigation
- [ ] Handles malformed JSON with clear error
- [ ] Products list preserved per statement
- [ ] Justification field optional

## Effort Estimate
**S** — 1 day (complete)

## Status
**DONE** — SBOM VEX parsing method
