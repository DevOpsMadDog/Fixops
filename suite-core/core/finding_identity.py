"""One derivation of a finding's correlation key, used by every writer.

A finding reaches the store by two different paths — scanner ingest promotes it,
and the brain pipeline mirrors it after computing a verdict — and each built its
own correlation key:

    ingest   {scanner}|{rule_or_cve}|{file:line  OR  package@version}
    mirror   {scanner}|{rule_or_cve}|{asset_id}

The third component differs, so the two rows never matched. Observed on a clean
tenant: a **96-finding scan produced 192 rows**, half of them carrying the
verdict and half carrying none. The customer's queue was doubled by the very
system that sells noise reduction, and every second row looked un-triaged.

The ingest side had been deliberately improved — its comment explains that
``asset_id`` is often an app-level identifier shared by hundreds of real
findings, so location granularity is required — and the mirror was never brought
along. That is the failure mode this module exists to prevent: two correct
implementations of the same idea, drifting.

Any new writer must call ``correlation_key`` rather than building its own.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

__all__ = ["advisory_id", "correlation_key", "location_key"]


ADVISORY_ID_RE = re.compile(
    r"\b(?:CVE-\d{4}-\d{4,}"
    r"|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}"
    r"|PYSEC-\d{4}-\d+"
    r"|OSV-\d{4}-\d+"
    r"|GO-\d{4}-\d+"
    r"|RUSTSEC-\d{4}-\d+"
    r"|DSA-\d+-\d+|USN-\d+-\d+|RHSA-\d{4}:\d+"
    r"|SNYK-[A-Z0-9]+-[A-Z0-9]+-\d+)\b",
    re.IGNORECASE,
)


def advisory_id(finding: Dict[str, Any]) -> str:
    """The vulnerability identifier, wherever the normaliser actually put it.

    Scanner ingest wrote ``cve_id`` from ``cve_id``/``cve`` only, and the SARIF
    normaliser puts the advisory in ``rule_id``. So a SARIF result for a real
    CVE was stored with an EMPTY cve_id, and every downstream join — EPSS, KEV,
    exploitability, reachability — had nothing to match on.

    Observed end to end: a finding whose correlation key was
    ``semgrep|CVE-2002-0367|app/handler.py:12`` (a CVE that IS in our 1,568-row
    KEV table) stored as::

        cve_id     = ''
        epss_score = None
        kev_listed = None
        exploitability = 'insufficient_evidence'   confidence 'none'

    The identifier was known at ingest and thrown away one field later. Same
    defect as the pipeline gating on ``cve_id`` while SARIF wrote ``rule_id``,
    which showed "Assessed: 0" on 2,344 findings.

    ONLY returns a value that LOOKS like an advisory id. A SARIF ruleId is
    frequently not one — "sql-injection", "hardcoded-secret" — and writing that
    into ``cve_id`` would invent a CVE that does not exist, which is worse than
    the empty field it replaced.
    """
    for field in ("cve_id", "cve", "rule_id", "vulnerability_id", "advisory_id"):
        value = str(finding.get(field) or "").strip()
        if not value:
            continue
        match = ADVISORY_ID_RE.search(value)
        if match:
            found = match.group(0)
            # CVE ids are conventionally upper-case and scanners emit both, so
            # normalise those. GHSA/PYSEC and friends are NOT upper-cased: a
            # GHSA id is lower-case by convention and our feed tables store it
            # that way, so shouting it would miss the very lookup this exists
            # to enable.
            return found.upper() if found[:3].lower() == "cve" else found
    return ""


# File FORMATS, not tools. SARIF, CycloneDX and friends are envelopes that carry
# another tool's output; the driver inside names the scanner that actually found
# the issue.
_CONTAINER_FORMATS = frozenset({
    "sarif", "cyclonedx", "cyclone_dx", "spdx", "vex", "json", "xml",
    "sbom", "generic", "unknown", "auto",
})


def _tool_identity(finding: Dict[str, Any], scanner: str = "") -> str:
    """Which tool found this, preferring the scanner over the file format.

    The two writers disagreed here and it doubled the queue a second time.
    Scanner ingest passed the DETECTED FILE FORMAT while the pipeline mirror
    passed the finding's own ``source_tool``, so one upload produced:

        sarif|hardcoded-secret|app/config.py      <- ingest, no verdict
        semgrep|hardcoded-secret|app/config.py    <- mirror, carries the verdict

    Six rows from a three-finding SARIF, and the three a customer sees first are
    the ones with no verdict on them.

    "sarif" is not a scanner — it is an envelope around one. The same semgrep
    finding delivered as SARIF and as semgrep's native JSON is the same finding,
    so identity follows the DRIVER. A format is used only when nothing better is
    known, which keeps some identity rather than falling to "unknown_tool".
    """
    explicit = (scanner or "").strip()
    if explicit and explicit.lower() not in _CONTAINER_FORMATS:
        return explicit

    for field in ("source_tool", "scanner", "source"):
        value = str(finding.get(field) or "").strip()
        if value and value.lower() not in _CONTAINER_FORMATS:
            return value

    return explicit or "unknown_tool"


def location_key(finding: Dict[str, Any]) -> str:
    """Where the finding is, at the granularity that keeps distinct issues apart.

    ``asset_id`` alone is too coarse: it is frequently an application-level id
    like "aldeci-self" shared by hundreds of findings, so keying on it collapses
    unrelated vulnerabilities into one row.
    """
    path = finding.get("file_path")
    line = finding.get("line_number")
    if path and line is not None:
        return f"{path}:{line}"

    package = finding.get("package_name")
    if package:
        version = finding.get("package_version") or finding.get("version") or ""
        return f"{package}@{version}"

    return str(
        path
        or finding.get("asset_id")
        or finding.get("resource_ref")
        or "unknown_asset"
    )


def correlation_key(finding: Dict[str, Any], scanner: str = "") -> str:
    """The stable identity of a vulnerability at a location, across runs.

    An explicit ``correlation_key`` on the finding always wins — a caller that
    has a better identity than we can derive should keep it.

    ``rule_id`` is consulted before ``cve_id`` because SARIF puts the advisory
    there and leaves cve_id unset; keying on cve_id alone made PYSEC and GHSA
    findings indistinguishable from one another.
    """
    existing = finding.get("correlation_key")
    if existing:
        return str(existing)

    tool = _tool_identity(finding, scanner)
    identity = (
        finding.get("rule_id")
        or finding.get("cve_id")
        or finding.get("vulnerability_id")
        or finding.get("title")
        or "unknown"
    )
    return f"{tool}|{identity}|{location_key(finding)}"
