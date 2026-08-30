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

from typing import Any, Dict

__all__ = ["correlation_key", "location_key"]


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

    tool = (
        scanner
        or finding.get("source_tool")
        or finding.get("scanner")
        or finding.get("source")
        or "unknown_tool"
    )
    identity = (
        finding.get("rule_id")
        or finding.get("cve_id")
        or finding.get("vulnerability_id")
        or finding.get("title")
        or "unknown"
    )
    return f"{tool}|{identity}|{location_key(finding)}"
