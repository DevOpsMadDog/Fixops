#!/usr/bin/env python3
"""
Seed 10 SLSA v1.0 provenance attestations for ALdeci FixOps platform.
Writes attestation JSON files directly to the provenance directory
(data/artifacts/attestations/enterprise/) and verifies via the API.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import requests

BASE_URL = "http://localhost:8000"
import os as _os, sys as _sys
API_KEY = _os.environ.get("FIXOPS_API_TOKEN")
if not API_KEY:
    _sys.exit("ERROR: FIXOPS_API_TOKEN environment variable required.")
HEADERS = {"X-API-Key": API_KEY}

# Provenance directory — matches app.py logic:
#   root / "artifacts" / "attestations" / overlay.mode
PROVENANCE_DIR = Path("/home/user/workspace/Fixops/data/artifacts/attestations/enterprise")
PROVENANCE_DIR.mkdir(parents=True, exist_ok=True)

# ─── Realistic SHA256 / commit hashes ──────────────────────────────────────────
# 64-char hex digests (sha256) and 40-char commit hashes
DIGESTS = {
    "aldeci-api-gateway":            "3e7f1a9b2c4d8e6f0a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f",
    "scanner-engine":                "b4c2d6e8f0a1b3c5d7e9f1a3b5c7d9e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2",
    "brain-pipeline":                "9f3a7b1c5d9e3a7b1c5d9e3a7b1c5d9e3a7b1c5d9e3a7b1c5d9e3a7b1c5d9e3a",
    "compliance-engine":             "1a5c9e3b7f2d6a0e4c8b2f6a0e4c8b2f6a0e4c8b2f6a0e4c8b2f6a0e4c8b2f6a",
    "evidence-service":              "2b6d0f4a8c2e6b0f4a8c2e6b0f4a8c2e6b0f4a8c2e6b0f4a8c2e6b0f4a8c2e6b",
    "quantum-signer":                "c7e1a5b9d3f7e1a5b9d3f7e1a5b9d3f7e1a5b9d3f7e1a5b9d3f7e1a5b9d3f7e1",
    "feeds-aggregator":              "d8f2b4a6c0e8f2b4a6c0e8f2b4a6c0e8f2b4a6c0e8f2b4a6c0e8f2b4a6c0e8f2",
    "remediation-orchestrator":      "e9a3c5d7b1e9a3c5d7b1e9a3c5d7b1e9a3c5d7b1e9a3c5d7b1e9a3c5d7b1e9a3",
    "copilot-service":               "f0b4d8a2e6f0b4d8a2e6f0b4d8a2e6f0b4d8a2e6f0b4d8a2e6f0b4d8a2e6f0b4",
    "nerve-center":                  "a1c5e9b3f7a1c5e9b3f7a1c5e9b3f7a1c5e9b3f7a1c5e9b3f7a1c5e9b3f7a1c5",
}

COMMITS = {
    "aldeci-api-gateway":            "f9e3a1c7b4d2e8f0a3c5b7d9e1f2a4c6",
    "scanner-engine":                "3a7c1f9e5b2d8a4c6e0f2b4d8a1c3e5f",
    "brain-pipeline":                "b2d4f6a8c0e2f4a6b8d0e2f4a6b8c0d2",
    "compliance-engine":             "7c9e1f3a5b7d9e1f3a5b7d9e1f3a5b7d",
    "evidence-service":              "4d6f8a0c2e4f6a8b0d2e4f6a8c0e2f4a",
    "quantum-signer":                "9e1f3b5d7a9e1f3b5d7a9e1f3b5d7a9e",
    "feeds-aggregator":              "1f3b5d7e9a1f3b5d7e9a1f3b5d7e9a1f",
    "remediation-orchestrator":      "c0e2f4a6b8c0e2f4a6b8c0e2f4a6b8c0",
    "copilot-service":               "5b7d9e1f3a5b7d9e1f3a5b7d9e1f3a5b",
    "nerve-center":                  "8a0c2e4f6b8a0c2e4f6b8a0c2e4f6b8a",
}

# Base SHA256s for dependency materials
DEP_DIGESTS = {
    "go.sum":          "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12",
    "package-lock":    "12ef34ab56cd12ef34ab56cd12ef34ab56cd12ef34ab56cd12ef34ab56cd12ef",
    "pom.xml":         "cd56ef12ab34cd56ef12ab34cd56ef12ab34cd56ef12ab34cd56ef12ab34cd56",
    "requirements":    "ef90ab12cd34ef90ab12cd34ef90ab12cd34ef90ab12cd34ef90ab12cd34ef90",
    "cargo.lock":      "3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123",
}

BUILDER_GH = "https://github.com/ALdeci/Fixops/actions/workflows/build.yml@refs/heads/main"
BUILDER_CI = "https://ci.aldeci.io/pipelines/secure-build/v2@slsa-l3"
BUILD_TYPE_GH = "https://slsa.dev/container-based-build/v0.1"
BUILD_TYPE_CI = "https://aldeci.io/build-types/secure-pipeline/v1"


def make_attestation(
    artifact: str,
    version: str,
    builder_id: str,
    build_type: str,
    source_repo: str,
    commit: str,
    build_started: str,
    build_finished: str,
    slsa_level: int,
    build_config_ref: str,
    materials: list,
    runner: str,
    build_invocation_id: str,
    deploy_env: str = "production",
) -> dict:
    """Construct a SLSA v1.0-compatible provenance attestation dict."""
    return {
        "slsaVersion": "1.0",
        "builder": {
            "id": builder_id,
            "version": {"runner": runner},
            "builderDependencies": [],
        },
        "buildType": build_type,
        "source": {
            "uri": f"git+{source_repo}@refs/tags/{version}",
            "digest": {"sha1": commit},
        },
        "metadata": {
            "buildStartedOn": build_started,
            "buildFinishedOn": build_finished,
            "reproducible": slsa_level >= 3,
            "buildInvocationId": build_invocation_id,
            "completeness": {
                "parameters": True,
                "environment": slsa_level >= 3,
                "materials": True,
            },
            "slsaLevel": slsa_level,
            "environment": {
                "deployEnv": deploy_env,
                "isolatedBuild": slsa_level >= 3,
                "ephemeralEnv": slsa_level >= 3,
            },
            "configSource": {
                "uri": f"git+{source_repo}@{build_config_ref}",
                "digest": {"sha1": commit},
                "entryPoint": ".github/workflows/build.yml",
            },
        },
        "subject": [
            {
                "name": artifact,
                "digest": {
                    "sha256": DIGESTS[artifact],
                },
            },
        ],
        "materials": materials,
    }


ATTESTATIONS = [
    make_attestation(
        artifact="aldeci-api-gateway",
        version="v2.14.0",
        builder_id=BUILDER_GH,
        build_type=BUILD_TYPE_GH,
        source_repo="https://github.com/ALdeci/api-gateway",
        commit=COMMITS["aldeci-api-gateway"],
        build_started="2026-03-06T01:00:00Z",
        build_finished="2026-03-06T01:12:43Z",
        slsa_level=3,
        build_config_ref="refs/tags/v2.14.0",
        build_invocation_id="gh-actions-run-15621-job-72891",
        runner="ubuntu-22.04",
        materials=[
            {"uri": "git+https://github.com/ALdeci/api-gateway@refs/tags/v2.14.0", "digest": {"sha1": COMMITS["aldeci-api-gateway"]}},
            {"uri": "pkg:npm/lodash@4.17.21", "digest": {"sha256": DEP_DIGESTS["package-lock"]}},
            {"uri": "pkg:npm/express@4.18.2",  "digest": {"sha256": "22ab34cd56ef78ab34cd56ef78ab34cd56ef78ab34cd56ef78ab34cd56ef78ab34"}},
            {"uri": "ghcr.io/aldeci/base-node:18.20-alpine", "digest": {"sha256": "44cd56ef78ab12cd56ef78ab12cd56ef78ab12cd56ef78ab12cd56ef78ab12cd56"}},
        ],
    ),
    make_attestation(
        artifact="scanner-engine",
        version="v3.7.2",
        builder_id=BUILDER_GH,
        build_type=BUILD_TYPE_GH,
        source_repo="https://github.com/ALdeci/scanner-engine",
        commit=COMMITS["scanner-engine"],
        build_started="2026-03-01T04:00:00Z",
        build_finished="2026-03-01T04:18:12Z",
        slsa_level=3,
        build_config_ref="refs/tags/v3.7.2",
        build_invocation_id="gh-actions-run-15344-job-68741",
        runner="ubuntu-22.04",
        materials=[
            {"uri": "git+https://github.com/ALdeci/scanner-engine@refs/tags/v3.7.2", "digest": {"sha1": COMMITS["scanner-engine"]}},
            {"uri": "pkg:golang/github.com/aldeci/scanner-core@v1.4.0", "digest": {"sha256": DEP_DIGESTS["go.sum"]}},
            {"uri": "pkg:pypi/semgrep@1.56.0", "digest": {"sha256": "55ef78ab12cd34ef78ab12cd34ef78ab12cd34ef78ab12cd34ef78ab12cd34ef78"}},
            {"uri": "ghcr.io/aldeci/base-go:1.21-alpine", "digest": {"sha256": "66ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"}},
        ],
    ),
    make_attestation(
        artifact="brain-pipeline",
        version="v1.9.4",
        builder_id=BUILDER_CI,
        build_type=BUILD_TYPE_CI,
        source_repo="https://github.com/ALdeci/brain-pipeline",
        commit=COMMITS["brain-pipeline"],
        build_started="2026-02-28T06:00:00Z",
        build_finished="2026-02-28T06:22:07Z",
        slsa_level=4,
        build_config_ref="refs/tags/v1.9.4",
        build_invocation_id="aldeci-ci-pipeline-run-4421-job-secure-build",
        runner="aldeci-hermetic-runner-v2",
        materials=[
            {"uri": "git+https://github.com/ALdeci/brain-pipeline@refs/tags/v1.9.4", "digest": {"sha1": COMMITS["brain-pipeline"]}},
            {"uri": "pkg:pypi/torch@2.1.2", "digest": {"sha256": "77cd34ef56ab78cd34ef56ab78cd34ef56ab78cd34ef56ab78cd34ef56ab78cd34"}},
            {"uri": "pkg:pypi/transformers@4.37.2", "digest": {"sha256": "88ef56ab78cd12ef56ab78cd12ef56ab78cd12ef56ab78cd12ef56ab78cd12ef56"}},
            {"uri": "pkg:pypi/fastapi@0.109.0", "digest": {"sha256": "99ab78cd12ef34ab78cd12ef34ab78cd12ef34ab78cd12ef34ab78cd12ef34ab78"}},
            {"uri": "ghcr.io/aldeci/base-python:3.11-slim", "digest": {"sha256": "aabb12cd34ef56aabb12cd34ef56aabb12cd34ef56aabb12cd34ef56aabb12cd34"}},
        ],
    ),
    make_attestation(
        artifact="compliance-engine",
        version="v2.3.1",
        builder_id=BUILDER_CI,
        build_type=BUILD_TYPE_CI,
        source_repo="https://github.com/ALdeci/compliance-engine",
        commit=COMMITS["compliance-engine"],
        build_started="2026-02-24T08:00:00Z",
        build_finished="2026-02-24T08:09:54Z",
        slsa_level=4,
        build_config_ref="refs/tags/v2.3.1",
        build_invocation_id="aldeci-ci-pipeline-run-4289-job-secure-build",
        runner="aldeci-hermetic-runner-v2",
        materials=[
            {"uri": "git+https://github.com/ALdeci/compliance-engine@refs/tags/v2.3.1", "digest": {"sha1": COMMITS["compliance-engine"]}},
            {"uri": "pkg:maven/io.aldeci/compliance-core@2.3.1", "digest": {"sha256": DEP_DIGESTS["pom.xml"]}},
            {"uri": "pkg:maven/org.springframework.boot/spring-boot-starter@3.2.0", "digest": {"sha256": "bbcd12ef34ab56cd12ef34ab56cd12ef34ab56cd12ef34ab56cd12ef34ab56cd12"}},
            {"uri": "ghcr.io/aldeci/base-jre:21-slim", "digest": {"sha256": "ccde34ab56cd78de34ab56cd78de34ab56cd78de34ab56cd78de34ab56cd78de34"}},
        ],
    ),
    make_attestation(
        artifact="evidence-service",
        version="v1.6.0",
        builder_id=BUILDER_GH,
        build_type=BUILD_TYPE_GH,
        source_repo="https://github.com/ALdeci/evidence-service",
        commit=COMMITS["evidence-service"],
        build_started="2026-02-20T10:00:00Z",
        build_finished="2026-02-20T10:07:31Z",
        slsa_level=3,
        build_config_ref="refs/tags/v1.6.0",
        build_invocation_id="gh-actions-run-15001-job-65233",
        runner="ubuntu-22.04",
        materials=[
            {"uri": "git+https://github.com/ALdeci/evidence-service@refs/tags/v1.6.0", "digest": {"sha1": COMMITS["evidence-service"]}},
            {"uri": "pkg:pypi/boto3@1.34.14", "digest": {"sha256": "ddef56cd78ef12de56cd78ef12de56cd78ef12de56cd78ef12de56cd78ef12de56"}},
            {"uri": "pkg:pypi/pydantic@2.5.3", "digest": {"sha256": "eef012ab34cd56ef012ab34cd56ef012ab34cd56ef012ab34cd56ef012ab34cd56"}},
            {"uri": "ghcr.io/aldeci/base-python:3.11-slim", "digest": {"sha256": "aabb12cd34ef56aabb12cd34ef56aabb12cd34ef56aabb12cd34ef56aabb12cd34"}},
        ],
    ),
    make_attestation(
        artifact="quantum-signer",
        version="v0.4.1",
        builder_id=BUILDER_CI,
        build_type=BUILD_TYPE_CI,
        source_repo="https://github.com/ALdeci/quantum-signer",
        commit=COMMITS["quantum-signer"],
        build_started="2026-02-15T12:00:00Z",
        build_finished="2026-02-15T12:14:58Z",
        slsa_level=4,
        build_config_ref="refs/tags/v0.4.1",
        build_invocation_id="aldeci-ci-pipeline-run-4101-job-secure-build",
        runner="aldeci-hermetic-runner-v2",
        materials=[
            {"uri": "git+https://github.com/ALdeci/quantum-signer@refs/tags/v0.4.1", "digest": {"sha1": COMMITS["quantum-signer"]}},
            {"uri": "pkg:cargo/openssl@0.10.62", "digest": {"sha256": DEP_DIGESTS["cargo.lock"]}},
            {"uri": "pkg:cargo/rustls@0.23.0", "digest": {"sha256": "ff12ab34cd56ef12ab34cd56ef12ab34cd56ef12ab34cd56ef12ab34cd56ef12ab"}},
            {"uri": "ghcr.io/aldeci/base-rust:1.75-slim", "digest": {"sha256": "1122cd34ef56ab1122cd34ef56ab1122cd34ef56ab1122cd34ef56ab1122cd34ef"}},
        ],
        deploy_env="production",
    ),
    make_attestation(
        artifact="feeds-aggregator",
        version="v4.2.0",
        builder_id=BUILDER_GH,
        build_type=BUILD_TYPE_GH,
        source_repo="https://github.com/ALdeci/feeds-aggregator",
        commit=COMMITS["feeds-aggregator"],
        build_started="2026-02-10T14:00:00Z",
        build_finished="2026-02-10T14:11:22Z",
        slsa_level=3,
        build_config_ref="refs/tags/v4.2.0",
        build_invocation_id="gh-actions-run-14872-job-61002",
        runner="ubuntu-22.04",
        materials=[
            {"uri": "git+https://github.com/ALdeci/feeds-aggregator@refs/tags/v4.2.0", "digest": {"sha1": COMMITS["feeds-aggregator"]}},
            {"uri": "pkg:golang/github.com/aldeci/feeds-core@v4.2.0", "digest": {"sha256": DEP_DIGESTS["go.sum"]}},
            {"uri": "pkg:golang/github.com/gorilla/mux@v1.8.1", "digest": {"sha256": "2233ef56ab78cd2233ef56ab78cd2233ef56ab78cd2233ef56ab78cd2233ef56ab"}},
            {"uri": "ghcr.io/aldeci/base-go:1.21-alpine", "digest": {"sha256": "66ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"}},
        ],
    ),
    make_attestation(
        artifact="remediation-orchestrator",
        version="v2.8.3",
        builder_id=BUILDER_CI,
        build_type=BUILD_TYPE_CI,
        source_repo="https://github.com/ALdeci/remediation-orchestrator",
        commit=COMMITS["remediation-orchestrator"],
        build_started="2026-02-06T16:00:00Z",
        build_finished="2026-02-06T16:08:49Z",
        slsa_level=3,
        build_config_ref="refs/tags/v2.8.3",
        build_invocation_id="aldeci-ci-pipeline-run-3987-job-secure-build",
        runner="aldeci-hermetic-runner-v2",
        materials=[
            {"uri": "git+https://github.com/ALdeci/remediation-orchestrator@refs/tags/v2.8.3", "digest": {"sha1": COMMITS["remediation-orchestrator"]}},
            {"uri": "pkg:pypi/celery@5.3.6", "digest": {"sha256": "3344ab78cd12ef3344ab78cd12ef3344ab78cd12ef3344ab78cd12ef3344ab78cd"}},
            {"uri": "pkg:pypi/redis@5.0.1", "digest": {"sha256": DEP_DIGESTS["requirements"]}},
            {"uri": "ghcr.io/aldeci/base-python:3.11-slim", "digest": {"sha256": "aabb12cd34ef56aabb12cd34ef56aabb12cd34ef56aabb12cd34ef56aabb12cd34"}},
        ],
    ),
    make_attestation(
        artifact="copilot-service",
        version="v1.3.7",
        builder_id=BUILDER_GH,
        build_type=BUILD_TYPE_GH,
        source_repo="https://github.com/ALdeci/copilot-service",
        commit=COMMITS["copilot-service"],
        build_started="2026-02-03T09:00:00Z",
        build_finished="2026-02-03T09:16:05Z",
        slsa_level=3,
        build_config_ref="refs/tags/v1.3.7",
        build_invocation_id="gh-actions-run-14588-job-58901",
        runner="ubuntu-22.04",
        materials=[
            {"uri": "git+https://github.com/ALdeci/copilot-service@refs/tags/v1.3.7", "digest": {"sha1": COMMITS["copilot-service"]}},
            {"uri": "pkg:npm/openai@4.24.7", "digest": {"sha256": "4455cd12ef34ab4455cd12ef34ab4455cd12ef34ab4455cd12ef34ab4455cd12ef"}},
            {"uri": "pkg:npm/lodash@4.17.21", "digest": {"sha256": DEP_DIGESTS["package-lock"]}},
            {"uri": "pkg:npm/express@4.18.2", "digest": {"sha256": "22ab34cd56ef78ab34cd56ef78ab34cd56ef78ab34cd56ef78ab34cd56ef78ab34"}},
            {"uri": "ghcr.io/aldeci/base-node:18.20-alpine", "digest": {"sha256": "44cd56ef78ab12cd56ef78ab12cd56ef78ab12cd56ef78ab12cd56ef78ab12cd56"}},
        ],
    ),
    make_attestation(
        artifact="nerve-center",
        version="v5.1.0",
        builder_id=BUILDER_CI,
        build_type=BUILD_TYPE_CI,
        source_repo="https://github.com/ALdeci/nerve-center",
        commit=COMMITS["nerve-center"],
        build_started="2026-01-30T11:00:00Z",
        build_finished="2026-01-30T11:25:38Z",
        slsa_level=4,
        build_config_ref="refs/tags/v5.1.0",
        build_invocation_id="aldeci-ci-pipeline-run-3872-job-secure-build",
        runner="aldeci-hermetic-runner-v2",
        materials=[
            {"uri": "git+https://github.com/ALdeci/nerve-center@refs/tags/v5.1.0", "digest": {"sha1": COMMITS["nerve-center"]}},
            {"uri": "pkg:golang/github.com/aldeci/nerve-core@v5.1.0", "digest": {"sha256": DEP_DIGESTS["go.sum"]}},
            {"uri": "pkg:golang/google.golang.org/grpc@v1.60.1", "digest": {"sha256": "5566ef34ab56cd5566ef34ab56cd5566ef34ab56cd5566ef34ab56cd5566ef34ab"}},
            {"uri": "pkg:golang/github.com/prometheus/client_golang@v1.18.0", "digest": {"sha256": "6677ab56cd78ef6677ab56cd78ef6677ab56cd78ef6677ab56cd78ef6677ab56cd"}},
            {"uri": "ghcr.io/aldeci/base-go:1.21-alpine", "digest": {"sha256": "66ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"}},
        ],
    ),
]

ARTIFACT_NAMES = [
    "aldeci-api-gateway",
    "scanner-engine",
    "brain-pipeline",
    "compliance-engine",
    "evidence-service",
    "quantum-signer",
    "feeds-aggregator",
    "remediation-orchestrator",
    "copilot-service",
    "nerve-center",
]


def write_attestation(artifact_name: str, payload: dict) -> Path:
    """Write attestation JSON to the provenance directory."""
    dest = PROVENANCE_DIR / f"{artifact_name}.json"
    dest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return dest


def verify_via_api() -> list:
    """Query the provenance API and return the list of attestation filenames."""
    resp = requests.get(
        f"{BASE_URL}/api/v1/provenance/",
        headers=HEADERS,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def main():
    print(f"Writing {len(ATTESTATIONS)} SLSA v1.0 provenance attestations to:\n  {PROVENANCE_DIR}\n")

    written = 0
    for artifact_name, attestation in zip(ARTIFACT_NAMES, ATTESTATIONS):
        dest = write_attestation(artifact_name, attestation)
        slsa_level = attestation["metadata"]["slsaLevel"]
        version = attestation["subject"][0]["digest"]["sha256"][:12]
        print(f"  ✓ {artifact_name:<30} SLSA L{slsa_level} | digest prefix: {version}... | {dest.name}")
        written += 1

    print(f"\nWrote {written} attestation files.\n")

    # Verify via the live API
    print("Verifying via API ...")
    files = verify_via_api()
    print(f"  API returned {len(files)} attestation(s):")
    for f in sorted(files):
        print(f"    - {f}")

    # Also do a spot-check — fetch one attestation and validate structure
    print("\nSpot-check: fetching 'aldeci-api-gateway' attestation via API ...")
    resp = requests.get(
        f"{BASE_URL}/api/v1/provenance/aldeci-api-gateway",
        headers=HEADERS,
        timeout=10,
    )
    resp.raise_for_status()
    att = resp.json()
    assert att["slsaVersion"] == "1.0", f"Unexpected slsaVersion: {att['slsaVersion']}"
    assert att["builder"]["id"].startswith("https://"), f"Unexpected builder.id: {att['builder']['id']}"
    print(f"  ✓ slsaVersion: {att['slsaVersion']}")
    print(f"  ✓ builder.id: {att['builder']['id']}")
    print(f"  ✓ subject[0].name: {att['subject'][0]['name']}")
    print(f"  ✓ SLSA level: {att['metadata']['slsaLevel']}")
    print(f"  ✓ {len(att.get('materials', []))} build materials")
    print(f"\nDone — {len(files)} attestations available in the provenance store.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
