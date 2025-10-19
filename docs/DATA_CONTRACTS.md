# FixOps Data Contracts

## Overview

This document defines the minimal data contracts for security facts ingested by FixOps. These contracts ensure deterministic, explainable risk fusion and reproducible evidence generation.

## Design Principles

1. **Determinism**: All inputs must be canonicalized to produce stable outputs
2. **Explainability**: Industry-standard scores (CVSS, EPSS, KEV) must always accompany FixOps scores
3. **Offline-First**: Core processing must work without mandatory network calls
4. **Schema Validation**: Optional strict mode for production deployments
5. **Provenance**: All facts must include source metadata (scanner name+version, timestamps)

## Core Fact Types

### 1. SBOM Facts (facts.sbom.json)

**Purpose**: Software Bill of Materials describing components and their metadata

**Required Fields**:
```json
{
  "metadata": {
    "generated_at": "ISO8601 timestamp",
    "generator": "tool name + version",
    "source_hash": "SHA256 of original SBOM file"
  },
  "components": [
    {
      "name": "string (required)",
      "version": "string (required)",
      "purl": "string (canonical, lowercase)",
      "hashes": {
        "SHA256": "hex string"
      },
      "licenses": ["SPDX-ID or expression"],
      "generators": ["tool1", "tool2"]
    }
  ]
}
```

**Canonicalization Rules**:
- Component names: lowercase, trimmed
- PURLs: lowercase, canonical form
- Licenses: sorted, deduplicated
- Components: sorted by (purl, name, version)
- Hashes: uppercase algorithm names, sorted keys
- Missing fields: default to null (not omitted)

**Validation**:
- Each component must have name + version OR purl
- Hashes must be valid hex strings
- Licenses should be valid SPDX identifiers (warning if not)

### 2. CVE Facts (facts.cve.json)

**Purpose**: Vulnerability data enriched with industry scores

**Required Fields**:
```json
{
  "metadata": {
    "generated_at": "ISO8601 timestamp",
    "source": "feed name (KEV, EPSS, NVD, etc.)",
    "source_version": "feed version or date",
    "source_hash": "SHA256 of original feed file"
  },
  "vulnerabilities": [
    {
      "cve": "CVE-YYYY-NNNNN (uppercase, required)",
      "cvss": {
        "score": 0.0-10.0,
        "vector": "CVSS:3.1/...",
        "severity": "CRITICAL|HIGH|MEDIUM|LOW|NONE"
      },
      "epss": {
        "score": 0.0-1.0,
        "percentile": 0.0-1.0,
        "date": "YYYY-MM-DD"
      },
      "kev": {
        "present": true|false,
        "date_added": "YYYY-MM-DD",
        "due_date": "YYYY-MM-DD",
        "known_ransomware": "Known|Unknown"
      },
      "affects": [
        {
          "purl": "canonical purl",
          "version_range": "semver range"
        }
      ],
      "patched": {
        "available": true|false,
        "fix_version": "semver",
        "fix_date": "ISO8601 timestamp"
      }
    }
  ]
}
```

**Canonicalization Rules**:
- CVE IDs: uppercase, validated format
- Vulnerabilities: sorted by CVE ID
- CVSS scores: rounded to 2 decimal places
- EPSS scores: rounded to 4 decimal places
- Dates: ISO8601 format

**Validation**:
- CVE ID must match CVE-YYYY-NNNNN pattern
- CVSS score must be 0.0-10.0
- EPSS score must be 0.0-1.0
- KEV dates must be valid ISO8601

### 3. SARIF Facts (facts.sarif.json)

**Purpose**: Static analysis findings from security scanners

**Required Fields**:
```json
{
  "metadata": {
    "generated_at": "ISO8601 timestamp",
    "tool": {
      "name": "scanner name",
      "version": "scanner version"
    },
    "source_hash": "SHA256 of original SARIF file"
  },
  "findings": [
    {
      "rule_id": "string (required)",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "category": "security|quality|performance",
      "file_path": "relative path",
      "line_number": 123,
      "message": "finding description",
      "cwe": ["CWE-79", "CWE-89"],
      "cvss": {
        "score": 0.0-10.0,
        "vector": "CVSS:3.1/..."
      }
    }
  ]
}
```

**Canonicalization Rules**:
- File paths: normalized (forward slashes, relative to repo root)
- Severities: uppercase, mapped to standard levels
- Findings: sorted by (rule_id, file_path, line_number)
- CWEs: uppercase, sorted
- Tool names: lowercase

**Validation**:
- Severity must be one of standard levels
- File paths must be relative (no absolute paths)
- Line numbers must be positive integers
- CWEs must match CWE-NNN pattern

## Policy Facts

### 4. Policy Evaluation Facts

**Purpose**: Results of policy rule evaluation for evidence bundles

**Required Fields**:
```json
{
  "metadata": {
    "evaluated_at": "ISO8601 timestamp",
    "policy_version": "semver or hash",
    "engine": "PSL|OPA|custom"
  },
  "facts": {
    "CVSS": {"cve": "CVE-2024-1234", "score": 9.8},
    "EPSS": {"cve": "CVE-2024-1234", "score": 0.95},
    "KEV": {"cve": "CVE-2024-1234", "present": true},
    "Affects": {"component": "log4j", "cve": "CVE-2024-1234"},
    "Patched": {"component": "log4j", "available": true},
    "Coverage": {"percent": 85.5},
    "Provenance": {"attestations": 5},
    "ReproMatch": {"match": true}
  },
  "rules_fired": [
    {
      "rule": "HighCVSS",
      "verdict": "WARN",
      "reason": "CVSS >= 9.0 for CVE-2024-1234",
      "industry_scores": {
        "cvss": 9.8,
        "epss": 0.95,
        "kev": true
      },
      "fixops_reason": "Critical vulnerability with high exploit probability"
    }
  ],
  "policy_status": "PASS|WARN|FAIL",
  "overall_verdict": "APPROVE|NEEDS_REVIEW|REJECT",
  "confidence": 0.0-1.0
}
```

**Canonicalization Rules**:
- Rules fired: sorted by rule name
- Facts: sorted by key
- Timestamps: ISO8601 UTC
- Scores: rounded consistently

**Validation**:
- Policy status must be PASS|WARN|FAIL
- Verdict must be APPROVE|NEEDS_REVIEW|REJECT
- Confidence must be 0.0-1.0
- Industry scores must always be present when available

## Evidence Manifest

### 5. Evidence Bundle Manifest

**Purpose**: Cryptographically-signed manifest of all evidence for a release

**Required Fields**:
```json
{
  "metadata": {
    "tag": "release tag",
    "generated_at": "ISO8601 timestamp",
    "bundle_version": "1.0"
  },
  "inputs": {
    "normalized_sbom": {
      "path": "relative path",
      "sha256": "hex digest"
    },
    "sbom_quality": {
      "path": "relative path",
      "sha256": "hex digest"
    },
    "risk_report": {
      "path": "relative path",
      "sha256": "hex digest"
    },
    "provenance_attestations": [
      {
        "path": "relative path",
        "sha256": "hex digest"
      }
    ],
    "repro_attestation": {
      "path": "relative path",
      "sha256": "hex digest"
    }
  },
  "metrics": {
    "sbom_quality": {
      "coverage_percent": 85.5,
      "license_coverage_percent": 90.0,
      "resolvability_percent": 95.0
    },
    "risk": {
      "max_risk_score": 75.5,
      "component_count": 150,
      "cve_count": 25
    },
    "policy": {
      "status": "PASS|WARN|FAIL",
      "rules_fired": ["HighCVSS", "LikelyExploit"],
      "reasons": [
        "Coverage 85.5% meets threshold",
        "No KEV vulnerabilities present"
      ]
    }
  },
  "evaluations": {
    "overall": "PASS|WARN|FAIL",
    "sbom_quality": "PASS|WARN|FAIL",
    "risk": "PASS|WARN|FAIL",
    "repro": "PASS|WARN|FAIL",
    "provenance": "PASS|WARN|FAIL"
  },
  "signature": {
    "algorithm": "RSA-SHA256|Ed25519",
    "public_key_fingerprint": "SHA256 of public key",
    "signature": "base64 encoded signature",
    "signed_at": "ISO8601 timestamp"
  }
}
```

**Canonicalization Rules**:
- All paths: relative, forward slashes
- All digests: lowercase hex
- All timestamps: ISO8601 UTC
- All arrays: sorted
- All objects: sorted keys

**Validation**:
- All input files must exist and match digests
- Signature must verify against public key
- Policy status must be consistent with rules fired
- Industry scores must be present in metrics

## Determinism Requirements

### Timestamps
- Use `FIXOPS_TEST_SEED` environment variable for reproducible timestamps
- Format: ISO8601 UTC (e.g., "2025-10-19T12:00:00Z")
- All modules must respect this seed

### Sorting
- Components: (purl, name, version)
- Vulnerabilities: (cve)
- Findings: (rule_id, file_path, line_number)
- Rules: (rule_name)
- All JSON keys: alphabetical

### Hashing
- Algorithm: SHA256
- Format: lowercase hex (no prefixes)
- Inputs: canonical JSON (sorted keys, no whitespace)

### JSON Output
- Indent: 2 spaces
- Sort keys: always true
- Trailing newline: always present
- No floating point precision issues (round consistently)

## Schema Validation

### Strict Mode
When `--strict-schema` flag is used:
1. Validate all inputs against JSON schemas
2. Fail on missing required fields
3. Warn on unknown fields
4. Enforce canonical formats

### Lenient Mode (Default)
1. Validate structure but allow missing optional fields
2. Warn on validation errors but continue
3. Log all validation issues for debugging

## Industry Standards Integration

### Always Show Industry Scores
FixOps scores must NEVER hide or replace industry-standard scores:
- CVSS scores from NVD
- EPSS scores from FIRST.org
- KEV status from CISA

### Format
```json
{
  "vulnerability": {
    "cve": "CVE-2024-1234",
    "industry_scores": {
      "cvss": {"score": 9.8, "vector": "CVSS:3.1/..."},
      "epss": {"score": 0.95, "percentile": 0.99},
      "kev": {"present": true, "date_added": "2024-01-15"}
    },
    "fixops_score": 85.5,
    "fixops_reason": "High CVSS + high EPSS + KEV present + internet-exposed"
  }
}
```

## Offline-First Behavior

### Local Feed Fallback
1. Check for local feeds in `data/feeds/`
2. If network unavailable, use local feeds
3. Log single concise warning: "Operating in offline mode with local feeds"
4. Include feed age in metadata

### Feed Staleness Detection
1. Check feed timestamp
2. Warn if > 7 days old
3. Include staleness in evidence manifest
4. Never fail on stale feeds (conservative mode)

## Backward Compatibility

All data contracts are additive:
- Existing fields remain unchanged
- New fields are optional
- Old evidence bundles remain valid
- Schema validation is opt-in

## References

- [SLSA v1 Provenance](https://slsa.dev/spec/v1.0/provenance)
- [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [CycloneDX 1.5](https://cyclonedx.org/docs/1.5/)
- [SPDX 2.3](https://spdx.github.io/spdx-spec/v2.3/)
- [CVSS 3.1](https://www.first.org/cvss/v3.1/specification-document)
- [EPSS](https://www.first.org/epss/)
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
