"""Upgrade Path Resolver Engine — ALDECI (GAP-007).

Given a pURL (`pkg:npm/lodash@4.17.19`) + list of CVE IDs, return the lowest
version-bump that resolves all CVEs, per ecosystem (npm, pypi, maven).

Capabilities:
  - EcosystemAdapter protocol for npm, pypi, maven (static catalog v0)
  - Version walk: find lowest version ≥ current where every CVE is fixed
  - Breaking-change risk: low (patch), medium (minor), high (major)
  - Yanked-version skip
  - Bulk resolve for findings page
  - Vuln catalog upsert API for admin ingestion
  - Multi-tenant via org_id, thread-safe via RLock, WAL-mode SQLite

No external deps (no `packaging`, no `semantic-version`). Pure stdlib.
TODO(live-registry): v1 will replace static catalog with registry.npmjs.org,
pypi.org/pypi/{pkg}/json, and Maven Central REST calls.

Compliance: CWE-1104, EO 14028 (SBOM remediation guidance).
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Tuple

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:  # pragma: no cover - bus optional in isolated tests
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

# --------------------------------------------------------------------------
# Version comparison (small internal helper; no `packaging` dep)
# --------------------------------------------------------------------------

_VERSION_TOKEN_RE = re.compile(r"(\d+)|([a-zA-Z]+)")


def _tokenize(version: str) -> List[Any]:
    """Tokenize a version string into comparable parts.

    Splits on `.`, `-`, `+`, `_`. Numeric chunks become ints. Alpha chunks
    (alpha, beta, rc, final, ga, release) become strings with a precedence rule:
    any pre-release tag makes the version lower than a version without it.
    """
    if not version:
        return []
    # Strip build metadata after '+' (SemVer: build metadata is not compared)
    base = version.split("+", 1)[0]
    parts: List[Any] = []
    # Split on the usual separators but preserve numeric/alpha structure
    for chunk in re.split(r"[.\-_]", base):
        if not chunk:
            continue
        # A single chunk may mix digits and letters (e.g. "1rc1"); tokenize
        for m in _VERSION_TOKEN_RE.finditer(chunk):
            num, alpha = m.group(1), m.group(2)
            if num is not None:
                parts.append(int(num))
            elif alpha:
                parts.append(alpha.lower())
    return parts


# Relative precedence for common pre-release / release tags.
# Lower value => earlier version. Unknown tags default to -1 (earlier than
# a plain numeric release that has no tag).
_TAG_ORDER = {
    "dev": -5,
    "a": -4,
    "alpha": -4,
    "b": -3,
    "beta": -3,
    "pre": -2,
    "rc": -2,
    "m": -2,
    "milestone": -2,
    "snapshot": -1,
    "cr": -1,
    "ga": 0,
    "final": 0,
    "release": 0,
    "sp": 1,  # service-pack tags sort higher
}


def _cmp_token(a: Any, b: Any) -> int:
    """Return -1 / 0 / 1 comparing two tokens."""
    if isinstance(a, int) and isinstance(b, int):
        return (a > b) - (a < b)
    if isinstance(a, int) and isinstance(b, str):
        # Numeric release > alpha pre-release (1 > rc)
        return 1 if _TAG_ORDER.get(b, -1) < 0 else -1
    if isinstance(a, str) and isinstance(b, int):
        return -1 if _TAG_ORDER.get(a, -1) < 0 else 1
    # both strings
    oa = _TAG_ORDER.get(a, -1)
    ob = _TAG_ORDER.get(b, -1)
    if oa != ob:
        return (oa > ob) - (oa < ob)
    return (a > b) - (a < b)


def compare_versions(a: str, b: str) -> int:
    """Return -1 if a < b, 0 if equal, 1 if a > b.

    Handles SemVer, PEP 440-ish, and Maven-style versions well enough for
    typical package versions seen in npm/pypi/maven registries.
    """
    if a == b:
        return 0
    ta = _tokenize(a)
    tb = _tokenize(b)
    for i in range(max(len(ta), len(tb))):
        if i >= len(ta):
            # a ran out first. If b's remaining tokens are all numeric zeros,
            # the versions are semantically equal ("1.2" == "1.2.0"). If a
            # pre-release tag follows, a > b (release > pre-release). Else a < b.
            nxt = tb[i]
            if isinstance(nxt, int):
                # All remaining tokens zero? → equal at this point
                if all(isinstance(t, int) and t == 0 for t in tb[i:]):
                    return 0
                return -1
            return 1 if _TAG_ORDER.get(nxt, -1) < 0 else -1
        if i >= len(tb):
            nxt = ta[i]
            if isinstance(nxt, int):
                if all(isinstance(t, int) and t == 0 for t in ta[i:]):
                    return 0
                return 1
            return -1 if _TAG_ORDER.get(nxt, -1) < 0 else 1
        r = _cmp_token(ta[i], tb[i])
        if r != 0:
            return r
    return 0


def _major(version: str) -> Optional[int]:
    toks = _tokenize(version)
    for t in toks:
        if isinstance(t, int):
            return t
    return None


def _minor(version: str) -> Optional[int]:
    toks = _tokenize(version)
    nums = [t for t in toks if isinstance(t, int)]
    return nums[1] if len(nums) >= 2 else None


def _is_major_bump(from_v: str, to_v: str) -> bool:
    fm, tm = _major(from_v), _major(to_v)
    if fm is None or tm is None:
        return False
    return tm > fm


def _is_minor_bump(from_v: str, to_v: str) -> bool:
    if _is_major_bump(from_v, to_v):
        return False
    fmn, tmn = _minor(from_v), _minor(to_v)
    if fmn is None or tmn is None:
        return False
    return tmn > fmn


# --------------------------------------------------------------------------
# pURL parsing
# --------------------------------------------------------------------------


_PURL_RE = re.compile(
    r"^pkg:(?P<ecosystem>[a-zA-Z0-9_.\-]+)/"
    r"(?P<name>[^@]+)"
    r"(?:@(?P<version>[^?#]+))?"
    r"(?:[?#].*)?$"
)


def parse_purl(purl: str) -> Dict[str, str]:
    """Parse `pkg:npm/lodash@4.17.19` → {ecosystem, name, version}.

    Raises ValueError on malformed input.
    """
    if not purl or not isinstance(purl, str):
        raise ValueError(f"purl must be a non-empty string, got {purl!r}")
    m = _PURL_RE.match(purl.strip())
    if not m:
        raise ValueError(f"invalid pURL: {purl!r}")
    eco = m.group("ecosystem").lower()
    name = m.group("name").strip()
    ver = (m.group("version") or "").strip()
    if not name:
        raise ValueError(f"pURL has empty package name: {purl!r}")
    # For Maven, name comes as groupId/artifactId; we accept it as-is for v0
    return {"ecosystem": eco, "name": name, "version": ver}


# --------------------------------------------------------------------------
# EcosystemAdapter protocol + static-catalog implementations
# --------------------------------------------------------------------------


VersionRow = Tuple[str, str, bool]  # (version, release_date ISO, yanked)


class EcosystemAdapter(Protocol):
    """Protocol every ecosystem adapter implements."""

    ecosystem: str

    def list_versions(self, package_name: str) -> List[VersionRow]:
        """Return [(version, release_date, yanked)] ascending-ordered by version."""

    def is_major_bump(self, from_v: str, to_v: str) -> bool:
        """Return True if to_v is a major-version bump vs. from_v."""


def _iso(d: str) -> str:
    """Normalize date; accept ISO, yyyy-mm-dd, or 'unknown'."""
    if not d:
        return ""
    return d


# Static v0 catalogs. Real-known versions for ~20 packages per ecosystem.
# Versions MUST be listed in ascending order.
# TODO(live-registry): replace with live registry calls in v1.

_NPM_CATALOG: Dict[str, List[VersionRow]] = {
    "lodash": [
        ("3.10.1", "2015-08-17", False),
        ("4.0.0", "2016-01-12", False),
        ("4.17.0", "2016-12-13", False),
        ("4.17.11", "2018-10-25", False),
        ("4.17.12", "2019-06-10", False),
        ("4.17.15", "2019-07-10", False),
        ("4.17.19", "2020-07-08", False),
        ("4.17.20", "2020-08-13", False),
        ("4.17.21", "2021-02-20", False),  # fixes CVE-2020-8203 + CVE-2021-23337
    ],
    "minimist": [
        ("0.0.8", "2014-06-25", False),
        ("1.2.0", "2018-04-12", False),
        ("1.2.3", "2020-03-11", False),
        ("1.2.5", "2020-03-11", False),
        ("1.2.6", "2022-03-21", False),  # fixes CVE-2021-44906
        ("1.2.7", "2022-10-10", False),
        ("1.2.8", "2022-12-07", False),
    ],
    "express": [
        ("3.0.0", "2012-10-23", False),
        ("4.0.0", "2014-04-09", False),
        ("4.16.0", "2017-09-28", False),
        ("4.17.0", "2019-05-16", False),
        ("4.17.1", "2019-05-25", False),
        ("4.17.3", "2022-02-28", False),
        ("4.18.0", "2022-04-25", False),
        ("4.18.2", "2022-10-08", False),
        ("4.19.0", "2024-03-20", False),  # fixes CVE-2024-29041
        ("4.19.2", "2024-03-25", False),
    ],
    "axios": [
        ("0.18.0", "2018-05-09", False),
        ("0.19.0", "2019-05-30", False),
        ("0.21.0", "2020-10-23", False),
        ("0.21.1", "2020-12-21", False),
        ("0.21.2", "2021-10-01", False),  # fixes CVE-2021-3749
        ("0.21.4", "2021-08-31", False),
        ("0.22.0", "2021-10-01", False),
        ("1.0.0", "2022-10-04", False),
        ("1.6.0", "2023-10-26", False),
        ("1.6.8", "2024-03-29", False),  # fixes CVE-2024-28849
    ],
    "marked": [
        ("0.3.0", "2014-05-05", False),
        ("0.6.0", "2019-02-02", False),
        ("0.7.0", "2019-09-01", False),
        ("0.8.0", "2019-12-24", False),
        ("1.0.0", "2020-04-26", False),
        ("4.0.10", "2022-01-18", False),
        ("4.0.12", "2022-02-01", False),  # fixes CVE-2022-21680
    ],
    "moment": [
        ("2.18.0", "2017-03-22", False),
        ("2.19.1", "2017-10-06", False),
        ("2.24.0", "2019-01-21", False),
        ("2.29.1", "2020-09-07", False),
        ("2.29.2", "2022-04-04", False),  # fixes CVE-2022-24785
        ("2.29.4", "2022-07-06", False),  # fixes CVE-2022-31129
    ],
    "node-fetch": [
        ("1.7.0", "2017-06-23", False),
        ("2.0.0", "2018-03-06", False),
        ("2.6.0", "2020-02-10", False),
        ("2.6.1", "2020-09-10", False),
        ("2.6.7", "2022-01-17", False),  # fixes CVE-2022-0235
        ("3.0.0", "2021-05-28", False),
    ],
    "tar": [
        ("4.4.0", "2018-03-20", False),
        ("4.4.18", "2021-08-31", False),  # fixes CVE-2021-37701/3/4
        ("6.0.0", "2020-06-16", False),
        ("6.1.9", "2021-08-31", False),
    ],
    "yargs-parser": [
        ("13.1.1", "2019-06-21", False),
        ("13.1.2", "2020-03-16", False),  # fixes CVE-2020-7608
        ("15.0.1", "2020-03-16", False),
        ("18.1.2", "2020-03-16", False),
    ],
    "ini": [
        ("1.3.5", "2019-07-22", False),
        ("1.3.6", "2020-03-22", False),
        ("1.3.8", "2020-12-10", False),  # fixes CVE-2020-7788
        ("2.0.0", "2021-05-18", False),
    ],
    "glob-parent": [
        ("5.1.1", "2021-03-14", False),
        ("5.1.2", "2021-06-03", False),  # fixes CVE-2020-28469
        ("6.0.0", "2021-06-03", False),
    ],
    "handlebars": [
        ("4.0.0", "2015-09-06", False),
        ("4.5.2", "2019-11-06", False),
        ("4.7.6", "2020-04-27", False),
        ("4.7.7", "2021-04-13", False),  # fixes CVE-2021-23369
    ],
    "json5": [
        ("1.0.1", "2018-05-30", False),
        ("1.0.2", "2022-12-24", False),  # fixes CVE-2022-46175
        ("2.2.0", "2020-10-28", False),
        ("2.2.2", "2022-12-24", False),
    ],
    "semver": [
        ("5.5.0", "2018-02-13", False),
        ("5.7.2", "2023-06-15", False),  # fixes CVE-2022-25883
        ("6.3.0", "2019-04-19", False),
        ("6.3.1", "2023-06-15", False),
        ("7.5.2", "2023-06-15", False),
    ],
    "minimatch": [
        ("3.0.4", "2018-07-02", False),
        ("3.1.2", "2022-11-18", False),  # fixes CVE-2022-3517
        ("5.0.0", "2022-03-17", False),
    ],
}


_PYPI_CATALOG: Dict[str, List[VersionRow]] = {
    "requests": [
        ("2.0.0", "2013-09-24", False),
        ("2.19.0", "2018-06-14", False),
        ("2.20.0", "2018-10-18", False),
        ("2.22.0", "2019-05-15", False),
        ("2.25.0", "2020-11-11", False),
        ("2.27.0", "2022-01-03", False),
        ("2.31.0", "2023-05-22", False),  # fixes CVE-2023-32681
        ("2.32.0", "2024-05-20", False),  # fixes CVE-2024-35195
        ("2.32.3", "2024-05-29", False),
    ],
    "urllib3": [
        ("1.24.0", "2018-10-16", False),
        ("1.24.2", "2019-04-17", False),  # fixes CVE-2019-11236
        ("1.25.0", "2019-04-29", False),
        ("1.26.0", "2020-10-29", False),
        ("1.26.5", "2021-05-26", False),  # fixes CVE-2021-33503
        ("1.26.17", "2023-10-02", False),  # fixes CVE-2023-43804
        ("1.26.18", "2023-10-17", False),  # fixes CVE-2023-45803
        ("2.0.0", "2023-04-26", False),
        ("2.0.7", "2023-10-17", False),
        ("2.2.2", "2024-06-17", False),
    ],
    "django": [
        ("2.2.0", "2019-04-01", False),
        ("3.0.0", "2019-12-02", False),
        ("3.2.0", "2021-04-06", False),
        ("3.2.24", "2024-02-06", False),  # fixes CVE-2024-24680
        ("4.0.0", "2021-12-07", False),
        ("4.2.0", "2023-04-03", False),
        ("4.2.10", "2024-02-06", False),
        ("4.2.11", "2024-03-04", False),  # fixes CVE-2024-27351
        ("5.0.3", "2024-03-04", False),
    ],
    "flask": [
        ("1.0.0", "2018-04-26", False),
        ("1.1.1", "2019-07-08", False),
        ("1.1.4", "2021-05-13", False),
        ("2.0.0", "2021-05-11", False),
        ("2.2.5", "2023-05-02", False),  # fixes CVE-2023-30861
        ("2.3.2", "2023-05-01", False),
        ("3.0.0", "2023-09-30", False),
    ],
    "pyyaml": [
        ("3.13", "2018-07-05", False),
        ("5.1", "2019-03-13", False),  # fixes CVE-2017-18342
        ("5.3", "2020-01-06", False),
        ("5.3.1", "2020-03-18", False),  # fixes CVE-2020-1747
        ("5.4", "2021-01-19", False),  # fixes CVE-2020-14343
        ("6.0", "2021-10-13", False),
    ],
    "jinja2": [
        ("2.10.0", "2017-11-08", False),
        ("2.10.1", "2019-04-06", False),  # fixes CVE-2019-10906
        ("2.11.0", "2020-01-27", False),
        ("2.11.3", "2021-01-31", False),  # fixes CVE-2020-28493
        ("3.0.0", "2021-05-11", False),
        ("3.1.0", "2022-03-24", False),
        ("3.1.3", "2024-01-10", False),  # fixes CVE-2024-22195
        ("3.1.4", "2024-05-05", False),
    ],
    "cryptography": [
        ("2.3", "2018-07-18", False),
        ("3.2", "2020-10-25", False),  # fixes CVE-2020-25659
        ("3.3.2", "2021-02-08", False),  # fixes CVE-2020-36242
        ("3.4.0", "2021-02-07", False),
        ("39.0.1", "2023-02-07", False),  # fixes CVE-2023-0286
        ("41.0.6", "2023-11-29", False),  # fixes CVE-2023-49083
        ("42.0.0", "2024-01-22", False),
        ("42.0.4", "2024-02-21", False),  # fixes CVE-2024-26130
    ],
    "werkzeug": [
        ("0.15.0", "2019-03-04", False),
        ("1.0.0", "2020-02-06", False),
        ("2.0.0", "2021-05-11", False),
        ("2.2.3", "2023-02-14", False),  # fixes CVE-2023-23934
        ("3.0.0", "2023-09-30", False),
        ("3.0.1", "2023-10-24", False),  # fixes CVE-2023-46136
        ("3.0.3", "2024-05-05", False),  # fixes CVE-2024-34069
    ],
    "sqlparse": [
        ("0.3.0", "2019-04-11", False),
        ("0.4.2", "2021-09-19", False),  # fixes CVE-2021-32839
        ("0.4.4", "2023-04-12", False),  # fixes CVE-2023-30608
        ("0.5.0", "2024-05-06", False),
    ],
    "setuptools": [
        ("40.0.0", "2018-07-08", False),
        ("58.0.0", "2021-09-08", False),
        ("65.5.1", "2022-11-05", False),  # fixes CVE-2022-40897
        ("70.0.0", "2024-05-20", False),  # fixes CVE-2024-6345
    ],
    "pillow": [
        ("6.0.0", "2019-04-01", False),
        ("7.0.0", "2020-01-02", False),
        ("8.1.1", "2021-03-01", False),  # fixes CVE-2021-25289
        ("9.0.0", "2022-01-02", False),
        ("9.3.0", "2022-10-29", False),  # fixes CVE-2022-45198
        ("10.0.1", "2023-09-15", False),  # fixes CVE-2023-44271
        ("10.2.0", "2024-01-02", False),  # fixes CVE-2023-50447
        ("10.3.0", "2024-04-01", False),
    ],
    "numpy": [
        ("1.21.0", "2021-06-22", False),
        ("1.22.0", "2021-12-31", False),  # fixes CVE-2021-41496
        ("1.26.0", "2023-09-16", False),
        ("2.0.0", "2024-06-16", False),
    ],
    "pip": [
        ("20.0.0", "2020-01-21", False),
        ("21.1.0", "2021-04-24", False),  # fixes CVE-2021-3572
        ("22.0.0", "2022-01-30", False),
        ("23.3.0", "2023-10-15", False),  # fixes CVE-2023-5752
        ("23.3.1", "2023-10-22", False),
    ],
    "certifi": [
        ("2021.5.30", "2021-05-30", False),
        ("2022.12.07", "2022-12-07", False),  # fixes CVE-2022-23491
        ("2023.7.22", "2023-07-22", False),  # fixes CVE-2023-37920
        ("2024.2.2", "2024-02-02", False),
    ],
    "lxml": [
        ("4.5.0", "2020-01-29", False),
        ("4.6.3", "2021-03-21", False),  # fixes CVE-2021-28957
        ("4.6.5", "2021-12-12", False),  # fixes CVE-2021-43818
        ("4.9.1", "2022-07-01", False),  # fixes CVE-2022-2309
        ("5.0.0", "2023-12-29", False),
    ],
}


_MAVEN_CATALOG: Dict[str, List[VersionRow]] = {
    "com.fasterxml.jackson.core/jackson-databind": [
        ("2.9.0", "2017-07-30", False),
        ("2.9.10", "2019-09-26", False),
        ("2.9.10.7", "2020-12-06", False),
        ("2.9.10.8", "2021-01-06", False),  # fixes CVE-2020-36518
        ("2.10.0", "2019-09-26", False),
        ("2.12.0", "2020-11-29", False),
        ("2.12.7.1", "2022-08-15", False),
        ("2.13.0", "2021-09-30", False),
        ("2.13.4.2", "2022-10-13", False),  # fixes CVE-2022-42003 + CVE-2022-42004
        ("2.14.0", "2022-11-05", False),
        ("2.14.3", "2023-05-05", False),
        ("2.15.0", "2023-04-23", False),
        ("2.15.4", "2024-02-15", False),
        ("2.16.0", "2023-11-15", False),
        ("2.17.0", "2024-03-14", False),
    ],
    "org.apache.logging.log4j/log4j-core": [
        ("2.8.0", "2017-01-11", False),
        ("2.11.0", "2018-07-19", False),
        ("2.14.0", "2020-11-04", False),
        ("2.15.0", "2021-12-07", False),  # fixes CVE-2021-44228 (Log4Shell) partial
        ("2.16.0", "2021-12-14", False),  # fixes CVE-2021-45046
        ("2.17.0", "2021-12-18", False),  # fixes CVE-2021-45105
        ("2.17.1", "2021-12-28", False),  # fixes CVE-2021-44832
        ("2.18.0", "2022-05-28", False),
        ("2.20.0", "2023-02-19", False),
        ("2.23.0", "2024-02-19", False),
    ],
    "org.springframework/spring-core": [
        ("5.2.0", "2019-09-30", False),
        ("5.2.20", "2022-03-31", False),
        ("5.3.18", "2022-03-31", False),  # fixes CVE-2022-22965 (Spring4Shell)
        ("5.3.19", "2022-04-13", False),
        ("5.3.21", "2022-06-15", False),
        ("6.0.0", "2022-11-16", False),
        ("6.0.8", "2023-03-23", False),
        ("6.1.0", "2023-11-16", False),
    ],
    "org.springframework.boot/spring-boot": [
        ("2.1.0", "2018-10-30", False),
        ("2.3.12", "2021-06-15", False),
        ("2.5.14", "2022-05-19", False),
        ("2.6.6", "2022-04-01", False),  # fixes CVE-2022-22965
        ("2.7.0", "2022-05-19", False),
        ("3.0.0", "2022-11-24", False),
        ("3.1.0", "2023-05-18", False),
        ("3.2.0", "2023-11-23", False),
    ],
    "commons-collections/commons-collections": [
        ("3.2.1", "2008-04-15", False),
        ("3.2.2", "2015-11-12", False),  # fixes CVE-2015-6420
    ],
    "org.apache.commons/commons-collections4": [
        ("4.0", "2013-11-26", False),
        ("4.1", "2015-11-12", False),  # fixes CVE-2015-7501
        ("4.4", "2019-07-05", False),
    ],
    "org.apache.struts/struts2-core": [
        ("2.5.20", "2020-02-01", False),
        ("2.5.26", "2020-12-08", False),  # fixes CVE-2020-17530
        ("2.5.31", "2023-05-10", False),
        ("6.0.0", "2022-04-19", False),
        ("6.3.0", "2023-12-07", False),  # fixes CVE-2023-50164
    ],
    "org.apache.tomcat/tomcat-catalina": [
        ("8.5.50", "2019-11-05", False),
        ("9.0.50", "2021-06-25", False),
        ("9.0.65", "2022-08-16", False),  # fixes CVE-2022-34305
        ("10.1.0", "2022-09-05", False),
        ("10.1.8", "2023-05-10", False),  # fixes CVE-2023-28708
    ],
    "io.netty/netty-all": [
        ("4.1.50", "2020-05-28", False),
        ("4.1.68", "2021-09-09", False),  # fixes CVE-2021-37136
        ("4.1.77", "2022-04-12", False),
        ("4.1.86", "2022-12-13", False),  # fixes CVE-2022-41881
        ("4.1.100", "2023-10-16", False),  # fixes CVE-2023-44487
    ],
    "org.apache.shiro/shiro-core": [
        ("1.4.0", "2018-02-13", False),
        ("1.7.0", "2020-10-20", False),  # fixes CVE-2020-17510
        ("1.8.0", "2021-08-23", False),
        ("1.9.1", "2022-06-21", False),  # fixes CVE-2022-32532
        ("1.13.0", "2023-11-27", False),
    ],
    "com.google.guava/guava": [
        ("28.0-jre", "2019-07-08", False),
        ("30.0-jre", "2020-10-14", False),
        ("32.0.0-jre", "2023-05-25", False),  # fixes CVE-2023-2976
        ("32.0.1-jre", "2023-06-14", False),
        ("33.0.0-jre", "2024-01-24", False),
    ],
    "org.yaml/snakeyaml": [
        ("1.26", "2020-03-09", False),  # fixes CVE-2017-18640
        ("1.32", "2022-09-17", False),
        ("1.33", "2022-10-27", False),  # fixes CVE-2022-41854
        ("2.0", "2023-02-23", False),  # fixes CVE-2022-1471
        ("2.2", "2023-08-11", False),
    ],
    "org.hibernate/hibernate-validator": [
        ("5.4.3", "2019-04-04", False),
        ("6.1.7", "2020-10-14", False),  # fixes CVE-2019-10219
        ("6.2.0", "2021-07-20", False),
        ("7.0.0", "2021-02-04", False),
        ("8.0.0", "2022-09-15", False),
    ],
    "org.apache.httpcomponents/httpclient": [
        ("4.5.10", "2019-10-01", False),
        ("4.5.13", "2020-10-06", False),  # fixes CVE-2020-13956
        ("4.5.14", "2022-12-19", False),
        ("5.0.0", "2020-02-05", False),
        ("5.2.1", "2023-01-30", False),
    ],
}


class _StaticCatalogAdapter:
    """Base class for v0 static-catalog adapters (npm/pypi/maven)."""

    ecosystem: str = ""
    _catalog: Dict[str, List[VersionRow]] = {}

    def list_versions(self, package_name: str) -> List[VersionRow]:
        key = (package_name or "").strip()
        return list(self._catalog.get(key, []))

    def is_major_bump(self, from_v: str, to_v: str) -> bool:
        return _is_major_bump(from_v, to_v)


# --------------------------------------------------------------------------
# Live registry adapters (npm, pypi, maven)
# --------------------------------------------------------------------------


class NpmLiveAdapter:
    """Fetch versions from registry.npmjs.org."""

    def get_versions(self, package_name: str) -> list:
        try:
            import requests

            r = requests.get(
                f"https://registry.npmjs.org/{package_name}",
                timeout=10,
                headers={"Accept": "application/vnd.npm.install-v1+json"},
            )
            return list(r.json().get("versions", {}).keys())
        except Exception:
            return []


class PyPILiveAdapter:
    """Fetch versions from pypi.org."""

    def get_versions(self, package_name: str) -> list:
        try:
            import requests

            r = requests.get(
                f"https://pypi.org/pypi/{package_name}/json", timeout=10
            )
            return list(r.json().get("releases", {}).keys())
        except Exception:
            return []


class MavenLiveAdapter:
    """Fetch versions from search.maven.org."""

    def get_versions(self, package_name: str) -> list:
        try:
            import requests

            group, artifact = (
                package_name.split(":", 1)
                if ":" in package_name
                else (package_name, package_name)
            )
            r = requests.get(
                "https://search.maven.org/solrsearch/select",
                params={
                    "q": f"g:{group} AND a:{artifact}",
                    "rows": 50,
                    "wt": "json",
                },
                timeout=10,
            )
            docs = r.json().get("response", {}).get("docs", [])
            return [d.get("latestVersion", "") for d in docs if d.get("latestVersion")]
        except Exception:
            return []


class OfflineRegistryAdapter:
    """Read versions from local JSON imported via USB.

    Set ALDECI_OFFLINE_REGISTRY_PATH=/path/to/registry.json.
    Format: {"<ecosystem>": {"<package>": ["<version>", ...]}}
    """

    def __init__(self):
        self._cache = None
        path = os.environ.get("ALDECI_OFFLINE_REGISTRY_PATH")
        if path and os.path.exists(path):
            try:
                with open(path) as f:
                    self._cache = json.load(f)
            except Exception:
                self._cache = None

    def get_versions(self, ecosystem: str, package_name: str) -> list:
        if not self._cache:
            return []
        return self._cache.get(ecosystem, {}).get(package_name, [])


# --------------------------------------------------------------------------
# Per-ecosystem adapter: live → static → offline chain w/ 1h TTL cache
# --------------------------------------------------------------------------


_LIVE_CACHE_TTL_SECONDS = 3600
_LIVE_CACHE: Dict[Tuple[str, str], Tuple[float, List[VersionRow]]] = {}
_LIVE_CACHE_LOCK = threading.Lock()


def _cache_get(key: Tuple[str, str]) -> Optional[List[VersionRow]]:
    with _LIVE_CACHE_LOCK:
        entry = _LIVE_CACHE.get(key)
        if not entry:
            return None
        ts, rows = entry
        if time.time() - ts > _LIVE_CACHE_TTL_SECONDS:
            _LIVE_CACHE.pop(key, None)
            return None
        return list(rows)


def _cache_put(key: Tuple[str, str], rows: List[VersionRow]) -> None:
    with _LIVE_CACHE_LOCK:
        _LIVE_CACHE[key] = (time.time(), list(rows))


def _versions_to_rows(versions: List[str]) -> List[VersionRow]:
    out: List[VersionRow] = []
    for v in versions:
        if not v or not isinstance(v, str):
            continue
        out.append((v, "", False))
    return out


class _ChainedCatalogAdapter:
    """Dispatch chain: live → static catalog → offline registry.

    Cached for 1h per (ecosystem, package_name) to avoid hammering registries.
    Network failures NEVER raise — return [].
    """

    ecosystem: str = ""
    _catalog: Dict[str, List[VersionRow]] = {}
    _live: Optional[Any] = None  # NpmLiveAdapter / PyPILiveAdapter / MavenLiveAdapter

    def __init__(self) -> None:
        self._offline = OfflineRegistryAdapter()

    def get_versions(self, package_name: str) -> List[str]:
        rows = self.list_versions(package_name)
        return [r[0] for r in rows]

    def list_versions(self, package_name: str) -> List[VersionRow]:
        key = (self.ecosystem, (package_name or "").strip())
        cached = _cache_get(key)
        if cached is not None:
            return cached

        result: List[VersionRow] = []

        # 1. Try live
        if self._live is not None:
            try:
                live_versions = self._live.get_versions(package_name) or []
            except Exception:
                live_versions = []
            if live_versions:
                result = _versions_to_rows(live_versions)

        # 2. Fall back to static catalog
        if not result:
            static_rows = list(self._catalog.get((package_name or "").strip(), []))
            if static_rows:
                result = static_rows

        # 3. Fall back to offline registry
        if not result:
            try:
                offline_versions = self._offline.get_versions(
                    self.ecosystem, package_name
                ) or []
            except Exception:
                offline_versions = []
            if offline_versions:
                result = _versions_to_rows(offline_versions)

        _cache_put(key, result)
        return result

    def is_major_bump(self, from_v: str, to_v: str) -> bool:
        return _is_major_bump(from_v, to_v)


class NpmAdapter(_ChainedCatalogAdapter):
    ecosystem = "npm"
    _catalog = _NPM_CATALOG
    _live = NpmLiveAdapter()


class PypiAdapter(_ChainedCatalogAdapter):
    ecosystem = "pypi"
    _catalog = _PYPI_CATALOG
    _live = PyPILiveAdapter()


class MavenAdapter(_ChainedCatalogAdapter):
    ecosystem = "maven"
    _catalog = _MAVEN_CATALOG
    _live = MavenLiveAdapter()


def _default_adapters() -> Dict[str, EcosystemAdapter]:
    return {
        "npm": NpmAdapter(),
        "pypi": PypiAdapter(),
        "maven": MavenAdapter(),
    }


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


_VALID_RISK = {"low", "medium", "high"}


class UpgradePathResolverEngine:
    """Resolve CVE-aware upgrade paths for dependencies.

    Thread-safe via RLock. Multi-tenant via org_id on query records +
    ecosystem-global vuln catalog. Adapters are pluggable via the
    `EcosystemAdapter` protocol.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        adapters: Optional[Dict[str, EcosystemAdapter]] = None,
    ) -> None:
        if db_path is None:
            _DATA_DIR.mkdir(parents=True, exist_ok=True)
            db_path = str(_DATA_DIR / "upgrade_path_resolver.db")
        self._db_path = db_path
        self._lock = threading.RLock()
        self._adapters: Dict[str, EcosystemAdapter] = adapters or _default_adapters()
        self.ensure_schema()
        self._seed_known_vulns()

    # ----- DB plumbing -----
    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=5.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
        except sqlite3.DatabaseError:
            pass
        return conn

    def ensure_schema(self) -> None:
        with self._lock, self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS package_versions (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    ecosystem     TEXT NOT NULL,
                    package_name  TEXT NOT NULL,
                    version       TEXT NOT NULL,
                    release_date  TEXT,
                    yanked        INTEGER NOT NULL DEFAULT 0,
                    created_at    TEXT NOT NULL,
                    UNIQUE(org_id, ecosystem, package_name, version)
                );
                CREATE INDEX IF NOT EXISTS ix_pkgv_lookup
                    ON package_versions(ecosystem, package_name);

                CREATE TABLE IF NOT EXISTS version_vulnerabilities (
                    id                        TEXT PRIMARY KEY,
                    ecosystem                 TEXT NOT NULL,
                    package_name              TEXT NOT NULL,
                    version                   TEXT NOT NULL,
                    cve_id                    TEXT NOT NULL,
                    vuln_fixed_in_version     TEXT NOT NULL,
                    created_at                TEXT NOT NULL,
                    UNIQUE(ecosystem, package_name, version, cve_id)
                );
                CREATE INDEX IF NOT EXISTS ix_vv_pkg
                    ON version_vulnerabilities(ecosystem, package_name);
                CREATE INDEX IF NOT EXISTS ix_vv_cve
                    ON version_vulnerabilities(cve_id);

                CREATE TABLE IF NOT EXISTS upgrade_queries (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    purl                    TEXT NOT NULL,
                    cve_ids_json            TEXT NOT NULL,
                    recommended_version     TEXT,
                    breaking_change_risk    TEXT,
                    computed_at             TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_uq_org
                    ON upgrade_queries(org_id, computed_at DESC);
                """
            )

    # ----- seed (real-known CVEs) -----
    _SEEDS: List[Tuple[str, str, str, str, str]] = [
        # (ecosystem, package, affected_version, cve_id, fixed_in)
        ("npm", "lodash", "4.17.19", "CVE-2020-8203", "4.17.20"),
        ("npm", "lodash", "4.17.20", "CVE-2021-23337", "4.17.21"),
        ("npm", "minimist", "1.2.5", "CVE-2021-44906", "1.2.6"),
        ("npm", "express", "4.18.2", "CVE-2024-29041", "4.19.0"),
        ("npm", "marked", "4.0.10", "CVE-2022-21680", "4.0.12"),
        ("npm", "axios", "0.21.1", "CVE-2021-3749", "0.21.2"),
        ("pypi", "requests", "2.30.0", "CVE-2023-32681", "2.31.0"),
        ("pypi", "urllib3", "1.26.4", "CVE-2021-33503", "1.26.5"),
        ("pypi", "urllib3", "1.26.16", "CVE-2023-43804", "1.26.17"),
        ("pypi", "django", "4.2.9", "CVE-2024-24680", "3.2.24"),
        ("pypi", "pyyaml", "5.2.0", "CVE-2020-1747", "5.3.1"),
        ("pypi", "jinja2", "3.1.2", "CVE-2024-22195", "3.1.3"),
        (
            "maven",
            "com.fasterxml.jackson.core/jackson-databind",
            "2.12.6",
            "CVE-2020-36518",
            "2.9.10.8",
        ),
        (
            "maven",
            "com.fasterxml.jackson.core/jackson-databind",
            "2.13.3",
            "CVE-2022-42003",
            "2.13.4.2",
        ),
        (
            "maven",
            "org.apache.logging.log4j/log4j-core",
            "2.14.0",
            "CVE-2021-44228",
            "2.15.0",
        ),
        (
            "maven",
            "org.apache.logging.log4j/log4j-core",
            "2.15.0",
            "CVE-2021-45046",
            "2.16.0",
        ),
        (
            "maven",
            "org.apache.logging.log4j/log4j-core",
            "2.16.0",
            "CVE-2021-45105",
            "2.17.0",
        ),
        (
            "maven",
            "org.springframework/spring-core",
            "5.2.20",
            "CVE-2022-22965",
            "5.3.18",
        ),
    ]

    def _seed_known_vulns(self) -> None:
        """Seed the catalog with real-known CVEs (idempotent)."""
        with self._lock, self._conn() as conn:
            cur = conn.execute("SELECT COUNT(*) FROM version_vulnerabilities")
            existing = cur.fetchone()[0] or 0
            if existing >= len(self._SEEDS):
                return
            for eco, pkg, ver, cve, fixed in self._SEEDS:
                conn.execute(
                    """INSERT OR IGNORE INTO version_vulnerabilities
                       (id, ecosystem, package_name, version, cve_id,
                        vuln_fixed_in_version, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        str(uuid.uuid4()),
                        eco,
                        pkg,
                        ver,
                        cve,
                        fixed,
                        _now_iso(),
                    ),
                )

    # ----- ingest API -----
    def ingest_vuln(
        self,
        ecosystem: str,
        package_name: str,
        version: str,
        cve_id: str,
        fixed_in: str,
    ) -> Dict[str, Any]:
        """Upsert a vuln catalog entry (admin-only API)."""
        if not ecosystem or not package_name or not cve_id or not fixed_in:
            raise ValueError(
                "ecosystem, package_name, cve_id, fixed_in are required"
            )
        eco = ecosystem.lower().strip()
        with self._lock, self._conn() as conn:
            rid = str(uuid.uuid4())
            conn.execute(
                """INSERT OR IGNORE INTO version_vulnerabilities
                   (id, ecosystem, package_name, version, cve_id,
                    vuln_fixed_in_version, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (rid, eco, package_name, version, cve_id, fixed_in, _now_iso()),
            )
        self._emit(
            "VULN_INGESTED",
            {"ecosystem": eco, "package_name": package_name, "cve_id": cve_id},
        )
        return {
            "id": rid,
            "ecosystem": eco,
            "package_name": package_name,
            "version": version,
            "cve_id": cve_id,
            "vuln_fixed_in_version": fixed_in,
        }

    def add_package_version(
        self,
        org_id: str,
        ecosystem: str,
        package_name: str,
        version: str,
        release_date: str = "",
        yanked: bool = False,
    ) -> Dict[str, Any]:
        """Insert a package version into the local cache (optional)."""
        with self._lock, self._conn() as conn:
            rid = str(uuid.uuid4())
            conn.execute(
                """INSERT OR IGNORE INTO package_versions
                   (id, org_id, ecosystem, package_name, version, release_date,
                    yanked, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    rid,
                    org_id,
                    ecosystem.lower().strip(),
                    package_name,
                    version,
                    release_date,
                    1 if yanked else 0,
                    _now_iso(),
                ),
            )
        return {
            "id": rid,
            "org_id": org_id,
            "ecosystem": ecosystem.lower().strip(),
            "package_name": package_name,
            "version": version,
            "yanked": bool(yanked),
        }

    # ----- resolve -----
    def _lookup_fixed_in(
        self, ecosystem: str, package_name: str, cve_id: str
    ) -> Optional[str]:
        """Return the `fixed_in` version for a given CVE on a package.

        If multiple rows exist (multiple "affected" tuples), return the
        highest fixed_in so the recommended version covers all vulnerable
        ranges.
        """
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                """SELECT vuln_fixed_in_version FROM version_vulnerabilities
                   WHERE ecosystem = ? AND package_name = ? AND cve_id = ?""",
                (ecosystem, package_name, cve_id),
            )
            fixes = [r[0] for r in cur.fetchall() if r and r[0]]
        if not fixes:
            return None
        best = fixes[0]
        for f in fixes[1:]:
            if compare_versions(f, best) > 0:
                best = f
        return best

    def _versions_for(
        self, ecosystem: str, package_name: str
    ) -> List[VersionRow]:
        adapter = self._adapters.get(ecosystem)
        if adapter is None:
            return []
        rows = adapter.list_versions(package_name)
        # Ensure ascending order (defensive; catalogs are already ordered)
        rows_sorted = sorted(rows, key=lambda r: _tokenize(r[0]))
        return rows_sorted

    def _risk(self, from_v: str, to_v: str) -> str:
        if not from_v or not to_v:
            return "medium"
        if _is_major_bump(from_v, to_v):
            return "high"
        if _is_minor_bump(from_v, to_v):
            return "medium"
        return "low"

    def resolve_upgrade(
        self,
        org_id: str,
        purl: str,
        cve_ids: List[str],
    ) -> Dict[str, Any]:
        """Resolve the lowest safe version that fixes ALL given CVEs.

        Returns a dict:
          {
            "purl": str,
            "ecosystem": str,
            "package_name": str,
            "current_version": str,
            "cve_ids": [...],
            "recommended_version": str | None,
            "breaking_change_risk": "low"|"medium"|"high",
            "alternate_paths": [ {version, risk, release_date, skipped_yanked} ],
            "unresolved_cves": [...],
            "reason": str,
          }
        """
        if not org_id:
            raise ValueError("org_id is required")
        if not cve_ids or not isinstance(cve_ids, list):
            raise ValueError("cve_ids must be a non-empty list")
        # Normalize
        cves = [c.strip().upper() for c in cve_ids if c and isinstance(c, str)]
        if not cves:
            raise ValueError("cve_ids must contain at least one non-empty CVE")

        parsed = parse_purl(purl)
        eco = parsed["ecosystem"]
        pkg = parsed["name"]
        current = parsed["version"]
        if not current:
            raise ValueError(f"pURL must include @version: {purl!r}")

        # Build the target floor: for each CVE, pick its fixed_in version.
        # The final recommendation must be >= all target floors.
        cve_fixes: Dict[str, Optional[str]] = {
            c: self._lookup_fixed_in(eco, pkg, c) for c in cves
        }
        unresolved = [c for c, f in cve_fixes.items() if not f]
        fixes_known = {c: f for c, f in cve_fixes.items() if f}

        versions = self._versions_for(eco, pkg)

        reason = ""
        recommended: Optional[str] = None
        alternates: List[Dict[str, Any]] = []

        if not versions:
            reason = f"no version catalog available for {eco}:{pkg}"
        elif unresolved and not fixes_known:
            reason = "no fix information available for any of the given CVEs"
        else:
            # Compute the max floor version across all known CVE fixes
            floor: Optional[str] = None
            for f in fixes_known.values():
                if floor is None or compare_versions(f, floor) > 0:
                    floor = f

            # Walk versions ascending; pick the first non-yanked version that
            # is >= floor AND > current (so it's a true upgrade).
            candidate_rows: List[VersionRow] = []
            for ver, rel, yanked in versions:
                if compare_versions(ver, current) <= 0:
                    continue
                if floor is not None and compare_versions(ver, floor) < 0:
                    continue
                candidate_rows.append((ver, rel, yanked))

            chosen: Optional[VersionRow] = None
            for row in candidate_rows:
                if row[2]:  # yanked
                    alternates.append(
                        {
                            "version": row[0],
                            "risk": self._risk(current, row[0]),
                            "release_date": row[1],
                            "skipped_yanked": True,
                        }
                    )
                    continue
                if chosen is None:
                    chosen = row
                else:
                    alternates.append(
                        {
                            "version": row[0],
                            "risk": self._risk(current, row[0]),
                            "release_date": row[1],
                            "skipped_yanked": False,
                        }
                    )

            if chosen is not None:
                recommended = chosen[0]
                reason = (
                    f"upgrade from {current} to {recommended} fixes "
                    f"{len(fixes_known)}/{len(cves)} CVEs"
                )
                if unresolved:
                    reason += f"; {len(unresolved)} CVEs have no known fix"
            else:
                if floor is not None:
                    reason = (
                        f"no catalog version >= {floor} and > {current}; "
                        f"may require new major release"
                    )
                else:
                    reason = "no candidate version found in catalog"

        risk = self._risk(current, recommended) if recommended else "high"

        # Persist query record
        rid = str(uuid.uuid4())
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO upgrade_queries
                   (id, org_id, purl, cve_ids_json, recommended_version,
                    breaking_change_risk, computed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    rid,
                    org_id,
                    purl,
                    json.dumps(cves),
                    recommended,
                    risk,
                    _now_iso(),
                ),
            )

        result = {
            "id": rid,
            "org_id": org_id,
            "purl": purl,
            "ecosystem": eco,
            "package_name": pkg,
            "current_version": current,
            "cve_ids": cves,
            "recommended_version": recommended,
            "breaking_change_risk": risk,
            "alternate_paths": alternates,
            "unresolved_cves": unresolved,
            "reason": reason,
        }
        self._emit("UPGRADE_PATH_RESOLVED", result)
        return result

    def bulk_resolve(
        self,
        org_id: str,
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Resolve upgrade paths for a batch of findings.

        Each finding: `{purl: str, cve_ids: List[str]}`.
        """
        if not isinstance(findings, list):
            raise ValueError("findings must be a list")
        results: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []
        for idx, f in enumerate(findings):
            try:
                purl = f["purl"]
                cves = f["cve_ids"]
            except (KeyError, TypeError) as exc:
                errors.append({"index": idx, "error": f"missing field: {exc}"})
                continue
            try:
                results.append(self.resolve_upgrade(org_id, purl, cves))
            except ValueError as exc:
                errors.append({"index": idx, "purl": f.get("purl"), "error": str(exc)})

        resolved = sum(1 for r in results if r.get("recommended_version"))
        return {
            "org_id": org_id,
            "total": len(findings),
            "resolved": resolved,
            "unresolvable": len(findings) - resolved - len(errors),
            "errors": errors,
            "results": results,
        }

    # ----- stats / inspection -----
    def stats(self, org_id: Optional[str] = None) -> Dict[str, Any]:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "SELECT COUNT(*) FROM version_vulnerabilities"
            )
            vuln_total = cur.fetchone()[0] or 0

            params: Tuple[Any, ...] = ()
            where = ""
            if org_id:
                where = " WHERE org_id = ?"
                params = (org_id,)
            cur = conn.execute(
                f"SELECT COUNT(*) FROM upgrade_queries{where}", params
            )
            query_total = cur.fetchone()[0] or 0

            cur = conn.execute(
                f"""SELECT
                        SUM(CASE WHEN recommended_version IS NOT NULL THEN 1 ELSE 0 END) AS resolved,
                        SUM(CASE WHEN breaking_change_risk='high' THEN 1 ELSE 0 END) AS high_risk
                    FROM upgrade_queries{where}""",
                params,
            )
            row = cur.fetchone() or (0, 0)
            resolved = row[0] or 0
            high_risk = row[1] or 0

            cur = conn.execute(
                """SELECT ecosystem, COUNT(*) AS c
                   FROM version_vulnerabilities
                   GROUP BY ecosystem"""
            )
            by_eco = {r[0]: r[1] for r in cur.fetchall()}

        return {
            "org_id": org_id,
            "vuln_catalog_total": vuln_total,
            "upgrade_queries_total": query_total,
            "resolved_queries": resolved,
            "high_risk_queries": high_risk,
            "vulns_by_ecosystem": by_eco,
            "supported_ecosystems": sorted(self._adapters.keys()),
        }

    def list_queries(
        self, org_id: str, limit: int = 50
    ) -> List[Dict[str, Any]]:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                """SELECT id, purl, cve_ids_json, recommended_version,
                          breaking_change_risk, computed_at
                   FROM upgrade_queries
                   WHERE org_id = ?
                   ORDER BY computed_at DESC LIMIT ?""",
                (org_id, max(1, min(limit, 500))),
            )
            rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            try:
                r["cve_ids"] = json.loads(r.pop("cve_ids_json") or "[]")
            except (json.JSONDecodeError, TypeError):
                r["cve_ids"] = []
        return rows

    # ----- event bus wiring (best-effort) -----
    def _emit(self, event_type: str, payload: Dict[str, Any]) -> None:
        if _get_tg_bus is None:
            return
        try:
            import asyncio
            import inspect

            bus = _get_tg_bus()
            if bus is None:
                return
            emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
            if emit is None:
                return
            result = emit(event_type, payload)
            if inspect.iscoroutine(result):
                # Schedule on the running loop if any, else fire-and-forget.
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    try:
                        asyncio.run(result)
                    except RuntimeError:
                        # Could not run; close coroutine to suppress warning
                        result.close()
        except Exception:  # pragma: no cover - bus is best-effort
            _logger.debug("trustgraph emit failed", exc_info=True)


__all__ = [
    "UpgradePathResolverEngine",
    "EcosystemAdapter",
    "NpmAdapter",
    "PypiAdapter",
    "MavenAdapter",
    "NpmLiveAdapter",
    "PyPILiveAdapter",
    "MavenLiveAdapter",
    "OfflineRegistryAdapter",
    "compare_versions",
    "parse_purl",
]
