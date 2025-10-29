# FixOps Marketplace

**Status:** Tier 2 (Advanced) - Feature-flagged, disabled by default until trust requirements implemented

The FixOps marketplace curates reusable remediation content, compliance guardrails, and attack simulations. This guide covers contribution, consumption, operations, and legal requirements.

---

## Quick Start

### For Contributors
```bash
# Submit remediation pack
curl -X POST https://fixops.example.com/marketplace/contribute \
  -F "file=@my-pack.json" \
  -F "author=Jane Doe" \
  -F "organization=ACME Corp" \
  -F 'contribution={"name":"PCI Payment Gateway Policy","description":"OPA policies for PCI workloads","content_type":"policy_template","compliance_frameworks":["pci_dss"],"ssdlc_stages":["build","deploy"],"pricing_model":"free","version":"1.0.0"}'
```

### For Consumers
```bash
# Browse marketplace
curl https://fixops.example.com/marketplace/browse?compliance_frameworks=pci_dss,sox

# Purchase/download content
curl -X POST https://fixops.example.com/marketplace/purchase/{item_id} \
  -F "purchaser=John Smith" \
  -F "organization=ACME Corp"
```

---

## API Reference

### Browse Content
**GET** `/marketplace/browse`

**Query Parameters:**
- `content_type`: policy_template | compliance_testset | mitigation_playbook | attack_scenario | pipeline_gate
- `compliance_frameworks`: Comma-separated (pci_dss, sox, hipaa, iso27001, nist_ssdf, mitre_attack)
- `ssdlc_stages`: Comma-separated (requirements, design, code, build, test, deploy, operate)
- `pricing_model`: free | one_time | subscription
- `limit`: Max results (1-100, default 20)

**Response:**
```json
{
  "status": "success",
  "data": {
    "items": [
      {
        "id": "uuid",
        "name": "PCI DSS Payment Gateway Policy Pack",
        "description": "Prebuilt OPA/Rego policies",
        "content_type": "policy_template",
        "compliance_frameworks": ["pci_dss"],
        "pricing_model": "free",
        "rating": 4.8,
        "downloads": 312,
        "qa_status": "passed"
      }
    ],
    "total": 1
  }
}
```

### Contribute Content
**POST** `/marketplace/contribute`

**Form Data:**
- `file`: Artifact payload (JSON, YAML, Rego, etc.)
- `author`: Contributor name
- `organization`: Contributor organization
- `contribution`: JSON manifest (see schema below)

**Contribution Manifest Schema:** See `schemas/marketplace/contribution.schema.json`

**Response:**
```json
{
  "status": "success",
  "data": {
    "content_id": "uuid",
    "qa_status": "passed",
    "qa_summary": "All automated checks passed",
    "quality_checks": {
      "metadata_completeness": {"status": "passed"},
      "artifact_lint": {"status": "passed"},
      "harness_validation": {"status": "passed"}
    }
  }
}
```

### Purchase Content
**POST** `/marketplace/purchase/{item_id}`

**Form Data:**
- `purchaser`: Buyer name
- `organization`: Buyer organization

**Response:**
```json
{
  "purchase_id": "uuid",
  "download_token": "signed-token",
  "license": "free|perpetual|subscription"
}
```

### Download Content
**GET** `/marketplace/download/{token}`

**Response:**
```json
{
  "status": "success",
  "data": {
    "purchase": {...},
    "item": {...},
    "content": {...}
  }
}
```

### Rate Content
**POST** `/marketplace/content/{item_id}/rate`

**Body:**
```json
{
  "rating": 4.5,
  "reviewer": "John Smith"
}
```

### Get Contributors
**GET** `/marketplace/contributors?limit=10`

**Response:** Leaderboard of top contributors by reputation score

### Get Stats
**GET** `/marketplace/stats`

**Response:** Aggregate marketplace metrics (total items, downloads, revenue, quality summary)

---

## Contribution Specification

### Required Fields
- `name`: Human-readable title
- `description`: Detailed explanation
- `content_type`: One of 5 types (see ContentType enum)
- `compliance_frameworks`: Array of frameworks (pci_dss, sox, hipaa, iso27001, nist_ssdf, mitre_attack)
- `ssdlc_stages`: Array of stages (requirements, design, code, build, test, deploy, operate)
- `pricing_model`: free | one_time | subscription
- `version`: SemVer (e.g., "1.0.0")

### Optional Fields
- `price`: Float (required if pricing_model != free)
- `tags`: Array of strings
- `metadata`: Object with additional context

### Automated Quality Gates
1. **Metadata Completeness**: Description, frameworks, and SSDLC stages must be present
2. **Artifact Linting**: Payload must not contain TODO/FIXME/TEMP markers
3. **Harness Detection**: Content should include executable checks (tests, policies, controls)

**QA Status Values:**
- `passed`: All checks passed, content promoted to marketplace
- `warning`: Some checks flagged issues, manual QA recommended
- `failed`: Critical issues, content blocked from marketplace

---

## Trust & Security Requirements

⚠️ **Current Status:** Basic validation only. Advanced trust requirements planned for Tier 1 promotion.

### Planned Requirements (Roadmap)
- **SBOM**: Mandatory for all contributed artifacts
- **Static/Malware Scans**: Automated scanning before promotion
- **Code Signing**: Sigstore/in-toto attestations for provenance
- **Sandbox Execution**: Resource limits, no outbound egress by default

### Current Limitations
- No SBOM enforcement
- No code signing/attestation
- No sandbox execution
- Ratings have no moderation/anti-gaming controls

---

## Licensing & Legal

### Allowed Licenses (Planned)
- Apache-2.0
- MIT
- Proprietary (with explicit terms)

### Current Status
⚠️ **No licensing policy enforced.** Contributors must manually specify license in metadata.

### Disclaimers
1. **QA Status is Heuristic, Not Certification**: "QA passed" indicates automated checks succeeded but does not guarantee security, compliance, or fitness for purpose.
2. **Paid Flows Stubbed**: Pricing models (one_time, subscription) are supported in code but **no payment processing, revenue share, KYC/AML, or tax handling is implemented**. Paid content is OSS mode only.
3. **No Warranties**: Contributed content is provided "as-is" without warranties of any kind.

### Data Protection
- Contributor analytics (submissions, downloads, ratings) are collected
- No DPA or privacy policy currently documented
- Telemetry opt-out not implemented

---

## Operations & Moderation

### Manual Curation (Planned)
- QA queue for items with `warning` or `failed` status
- Manual review SLAs (TBD)
- Escalation to security team for high-risk content

### Takedown/Deprecation (Planned)
- Emergency removal process for malicious/infringing content
- Notification to subscribers
- Grace periods and replacement recommendations

### Current Status
⚠️ **No moderation tooling or playbooks implemented.** Operators must manually query database and update records.

---

## Versioning & Updates

### SemVer Policy (Recommended)
- **MAJOR**: Breaking changes (incompatible API/schema changes)
- **MINOR**: New features (backward-compatible)
- **PATCH**: Bug fixes (backward-compatible)

### Changelog Format (Recommended)
```markdown
## [1.2.0] - 2025-10-28
### Added
- New OPA rule for TLS 1.3 enforcement
### Fixed
- Corrected regex for CIDR validation
```

### Current Status
⚠️ **No versioning enforcement.** Contributors can submit any version string.

---

## Known Limitations

1. **Path Mismatch**: API mounts at `/marketplace` but some docs reference `/api/v1/marketplace`. Verify your deployment's base path.
2. **No Payments**: `PricingModel.one_time` and `subscription` are code stubs. No Stripe/payment rails integrated.
3. **No SBOM/Attestations**: Despite README claims of "SLSA provenance," only RSA-SHA256 local signatures are implemented.
4. **No Moderation**: Ratings and reviews have no spam controls or weighting.
5. **No Authentication**: Download tokens use HMAC but no role-based access control.

---

## Roadmap

### Tier 1 Promotion Requirements
- [ ] Implement SBOM enforcement
- [ ] Add static/malware scanning
- [ ] Integrate Sigstore for code signing
- [ ] Build sandbox execution environment
- [ ] Create moderation tooling and playbooks
- [ ] Document licensing policy
- [ ] Add DPA and privacy policy
- [ ] Implement payment processing (if monetization desired)

### Future Enhancements
- [ ] CLI commands (`fixops marketplace browse/install/update`)
- [ ] Compatibility matrix (FixOps engine version requirements)
- [ ] Dependency resolution
- [ ] Rollback functionality
- [ ] Advanced analytics for contributors

---

## Support

**Issues:** Report bugs or request features via GitHub Issues
**Security:** Report vulnerabilities to security@fixops.local
**Community:** Join discussions in #marketplace Slack channel

---

**Last Updated:** 2025-10-28
**Status:** Tier 2 (Advanced) - Feature-flagged
**Canonical Doc:** This is the single source of truth for marketplace documentation
