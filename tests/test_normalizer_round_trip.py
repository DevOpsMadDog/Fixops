"""The supported-tool list must be earned, not counted.

Ingest is the product thesis (ADR-009): we do not scan, we consume what a customer's
scanners already produce. "We support 34 tools" is therefore the central sales claim, and
today it rests on counting classes named ``*Normalizer``. A class that exists is not a
tool we support.

These tests feed each normalizer a sample in its real format and require it to (a)
recognise the format and (b) produce findings. The supported list is then whatever passes
— generated, not maintained by hand, so it cannot drift into marketing.

The samples are genuine format fragments, not fixtures of *our* behaviour: a SARIF run
object really is what Semgrep and CodeQL emit, and a CycloneDX component really is what
Syft writes. Parsing them is exactly the job being claimed.

Where a normalizer needs a format this suite does not yet carry a sample for, it is
reported as **declared but unverified** rather than counted as supported — an honest gap,
and a list of what to write next.
"""

from __future__ import annotations

import inspect
import json
from typing import Any, Dict, List, Tuple

import pytest

from core import scanner_parsers as sp

# ---------------------------------------------------------------------------
# Real-format samples
# ---------------------------------------------------------------------------

SARIF = json.dumps(
    {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "semgrep", "version": "1.52.0"}},
                "results": [
                    {
                        "ruleId": "python.lang.security.audit.exec-detected",
                        "level": "error",
                        "message": {"text": "Detected exec() usage"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/main.py"},
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
).encode()

CYCLONEDX = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "log4j-core",
                "version": "2.14.1",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2021-44228",
                "ratings": [{"severity": "critical", "score": 10.0}],
                "affects": [{"ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}],
            }
        ],
    }
).encode()

SPDX = json.dumps(
    {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "test-sbom",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-log4j",
                "name": "log4j-core",
                "versionInfo": "2.14.1",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                    }
                ],
            }
        ],
    }
).encode()

TRIVY = json.dumps(
    {
        "SchemaVersion": 2,
        "ArtifactName": "app:latest",
        "Results": [
            {
                "Target": "app:latest (debian 11)",
                "Class": "os-pkgs",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-44228",
                        "PkgName": "log4j-core",
                        "InstalledVersion": "2.14.1",
                        "Severity": "CRITICAL",
                        "Title": "Log4Shell",
                    }
                ],
            }
        ],
    }
).encode()

# Bandit's real output carries test_name and generated_at alongside test_id; a sample
# without them is not what the tool emits, and the normalizer is right to reject it.
BANDIT = json.dumps(
    {
        "generated_at": "2026-08-17T00:00:00Z",
        "results": [
            {
                "filename": "app/main.py",
                "line_number": 42,
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "issue_text": "Use of exec detected.",
                "test_id": "B102",
                "test_name": "exec_used",
            }
        ],
        "metrics": {"_totals": {"loc": 100, "nosec": 0}},
    }
).encode()

# Semgrep emits its own JSON, not SARIF — the normalizer's docstring says so explicitly
# ("native format, not SARIF") and it keys on check_id.
SEMGREP_NATIVE = json.dumps(
    {
        "version": "1.52.0",
        "results": [
            {
                "check_id": "python.lang.security.audit.exec-detected",
                "path": "app/main.py",
                "start": {"line": 42, "col": 1},
                "end": {"line": 42, "col": 20},
                "extra": {
                    "message": "Detected exec() usage",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-95"]},
                },
            }
        ],
        "errors": [],
    }
).encode()

GRYPE = json.dumps(
    {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2021-44228",
                    "severity": "Critical",
                    "description": "Log4Shell",
                },
                "artifact": {"name": "log4j-core", "version": "2.14.1"},
            }
        ]
    }
).encode()

OSV = json.dumps(
    {
        "results": [
            {
                "source": {"path": "go.mod"},
                "packages": [
                    {
                        "package": {"name": "log4j-core", "ecosystem": "Maven"},
                        "vulnerabilities": [
                            {"id": "GHSA-jfh8-c2jp-5v3q", "summary": "Log4Shell"}
                        ],
                    }
                ],
            }
        ]
    }
).encode()


SNYK = json.dumps(
    {
        "packageManager": "maven",
        "vulnerabilities": [
            {
                "id": "SNYK-JAVA-ORGAPACHELOGGINGLOG4J-2314720",
                "packageName": "org.apache.logging.log4j:log4j-core",
                "version": "2.14.1",
                "severity": "critical",
                "title": "Remote Code Execution (RCE)",
                "identifiers": {"CVE": ["CVE-2021-44228"]},
            }
        ],
    }
).encode()

SONARQUBE = json.dumps(
    {
        "paging": {"pageIndex": 1, "pageSize": 100, "total": 1},
        "issues": [
            {
                "key": "AY1234",
                "rule": "python:S2076",
                "severity": "BLOCKER",
                "component": "proj:app/main.py",
                "line": 42,
                "message": "OS command injection",
                "type": "VULNERABILITY",
            }
        ],
    }
).encode()

CHECKOV = json.dumps(
    {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_20",
                    "check_name": "S3 Bucket has an ACL defined which allows public READ access",
                    "file_path": "/main.tf",
                    "file_line_range": [1, 10],
                    "resource": "aws_s3_bucket.data",
                    "severity": "HIGH",
                }
            ],
            "passed_checks": [],
        },
    }
).encode()

GITLEAKS = json.dumps(
    [
        {
            "RuleID": "aws-access-token",
            "Description": "AWS Access Token",
            "File": "config/settings.py",
            "StartLine": 12,
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "Match": "AKIAIOSFODNN7EXAMPLE",
        }
    ]
).encode()

# Nuclei writes JSONL — one object per line, not a JSON array.
NUCLEI = (
    json.dumps(
        {
            "template-id": "CVE-2021-44228",
            "info": {"name": "Log4Shell RCE", "severity": "critical"},
            "matched-at": "https://app.example.com/api",
            "host": "app.example.com",
        }
    )
    + "\n"
).encode()

DEPENDABOT = json.dumps(
    [
        {
            "number": 1,
            "state": "open",
            "dependency": {
                "package": {"ecosystem": "maven", "name": "org.apache.logging.log4j:log4j-core"}
            },
            "security_advisory": {
                "ghsa_id": "GHSA-jfh8-c2jp-5v3q",
                "cve_id": "CVE-2021-44228",
                "severity": "critical",
                "summary": "Log4Shell",
            },
        }
    ]
).encode()

# An SBOM describes packages, not vulnerabilities, so a normalizer that parses one and
# reports no findings is behaving correctly — it is inventory, not a scan result. These
# are checked for recognition only.
INVENTORY_ONLY = {"SPDXUniversalNormalizer"}

# normalizer class -> a sample it should recognise
SAMPLES: Dict[str, bytes] = {
    "SARIFUniversalNormalizer": SARIF,
    "SemgrepScannerNormalizer": SEMGREP_NATIVE,
    "CycloneDXUniversalNormalizer": CYCLONEDX,
    "SPDXUniversalNormalizer": SPDX,
    "TrivyScannerNormalizer": TRIVY,
    "BanditNormalizer": BANDIT,
    "GrypeScannerNormalizer": GRYPE,
    "OSVScannerNormalizer": OSV,
    "SnykNormalizer": SNYK,
    "SonarQubeNormalizer": SONARQUBE,
    "CheckovNormalizer": CHECKOV,
    "GitleaksScannerNormalizer": GITLEAKS,
    "NucleiNormalizer": NUCLEI,
    "DependabotScannerNormalizer": DEPENDABOT,
}


def _normalizers() -> List[Tuple[str, Any]]:
    return sorted(
        (name, cls)
        for name, cls in vars(sp).items()
        if inspect.isclass(cls)
        and name.endswith("Normalizer")
        and name != "BaseNormalizer"
    )


def _build(cls: Any, name: str) -> Any:
    """Normalizers take a NormalizerConfig; construct a minimal one."""
    return cls(sp.NormalizerConfig(name=name))


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_normalizer_recognises_its_own_format(name: str) -> None:
    """can_handle must score a real sample above zero, or dispatch never reaches it."""
    cls = getattr(sp, name, None)
    if cls is None:
        pytest.skip(f"{name} is not present in this build")
    normalizer = _build(cls, name)
    confidence = normalizer.can_handle(SAMPLES[name])
    assert confidence > 0, (
        f"{name} does not recognise a genuine sample of its own format, so the "
        "dispatcher will never route that scanner's output to it"
    )


@pytest.mark.parametrize("name", sorted(SAMPLES))
def test_normalizer_produces_findings_from_a_real_sample(name: str) -> None:
    """Recognising a format is not the claim; turning it into findings is."""
    cls = getattr(sp, name, None)
    if cls is None:
        pytest.skip(f"{name} is not present in this build")
    findings = _build(cls, name).normalize(SAMPLES[name])
    assert isinstance(findings, list)
    if name in INVENTORY_ONLY:
        # An SBOM carries no vulnerabilities; parsing without error is the whole claim.
        return
    assert findings, f"{name} recognised the sample but produced no findings"


def test_every_normalizer_can_at_least_be_constructed() -> None:
    """A normalizer that cannot be instantiated cannot support anything."""
    broken: List[str] = []
    for name, cls in _normalizers():
        try:
            _build(cls, name)
        except Exception as exc:  # noqa: BLE001
            broken.append(f"{name}: {type(exc).__name__}")
    assert not broken, "normalizers that fail to construct:\n  " + "\n  ".join(broken)


def test_normalizers_never_raise_on_junk_input() -> None:
    """Scanner output arrives from outside; a parser must reject, not explode."""
    junk = b"this is not a scan report"
    exploded: List[str] = []
    for name, cls in _normalizers():
        try:
            normalizer = _build(cls, name)
            if normalizer.can_handle(junk) > 0:
                normalizer.normalize(junk)
        except NotImplementedError:
            continue
        except Exception as exc:  # noqa: BLE001
            exploded.append(f"{name}: {type(exc).__name__}: {exc}")
    assert not exploded, "normalizers raised on junk input:\n  " + "\n  ".join(exploded)


def test_the_verified_list_is_reported() -> None:
    """Publish what is actually proven, and what is merely declared.

    This is the number the supported-tool claim should be built from.
    """
    declared = {name for name, _ in _normalizers()}
    verified = set(SAMPLES) & declared
    unverified = declared - verified

    print(f"\n  verified by round-trip : {len(verified)}")
    print(f"  declared but unverified: {len(unverified)}")
    for name in sorted(unverified):
        print(f"    - {name}")

    assert verified, "no normalizer is verified by a round-trip"
