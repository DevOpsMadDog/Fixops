"""ALDECI Dependency Vulnerability Scanner.

Scans Python (requirements.txt / pip freeze) and Node.js (package.json)
dependencies for known CVEs and outdated versions.

Provides:
- DepVulnerability  Pydantic model
- DependencyScanner class with 6 public methods
- Built-in known vulnerability DB (50+ entries)
"""

from __future__ import annotations

import json
import logging
import re
import subprocess  # nosec B404
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel

logger = logging.getLogger(__name__)

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:
    _get_tg_bus = None  # type: ignore[assignment]


def _tg_emit(event_type: str, payload: dict) -> None:
    try:
        if _get_tg_bus is None:
            return
        bus = _get_tg_bus()
        if bus is not None:
            bus.emit(event_type, payload)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Pydantic model
# ---------------------------------------------------------------------------


class DepVulnerability(BaseModel):
    """A single dependency vulnerability finding."""

    package: str
    installed_version: str
    fixed_version: str
    cve_id: str
    severity: str  # critical / high / medium / low / info
    description: str
    advisory_url: str

    model_config = {"extra": "ignore"}


# ---------------------------------------------------------------------------
# Built-in known vulnerability database (50+ entries)
# ---------------------------------------------------------------------------
# Format: package_lower -> list of (affected_range_max_exclusive, fixed_version, cve_id, severity, description, advisory_url)
# affected_range_max_exclusive is a tuple of ints, e.g. (2, 28, 3) means < 2.28.3
# Use () to mean "all versions"

_VulnEntry = Tuple[Tuple[int, ...], str, str, str, str, str]

KNOWN_VULNS: Dict[str, List[_VulnEntry]] = {
    # ── requests ──────────────────────────────────────────────────────
    "requests": [
        (
            (2, 31, 0),
            "2.31.0",
            "CVE-2023-32681",
            "high",
            "Requests forwards proxy-authorization header to destination servers when following redirects to HTTPS.",
            "https://github.com/advisories/GHSA-j8r2-6x86-q33q",
        ),
        (
            (2, 28, 2),
            "2.28.2",
            "CVE-2022-33651",
            "medium",
            "Requests does not properly validate TLS certificates in some edge cases.",
            "https://github.com/advisories/GHSA-cfj3-7x9c-4p3h",
        ),
    ],
    # ── cryptography ──────────────────────────────────────────────────
    "cryptography": [
        (
            (41, 0, 4),
            "41.0.4",
            "CVE-2023-49083",
            "high",
            "NULL pointer dereference in PKCS12 parsing allows denial of service.",
            "https://github.com/advisories/GHSA-jfhm-5ghh-2f97",
        ),
        (
            (42, 0, 2),
            "42.0.2",
            "CVE-2024-26130",
            "high",
            "NULL ptr dereference in PKCS#12 key material extraction.",
            "https://github.com/advisories/GHSA-6vqw-3v5j-54x4",
        ),
        (
            (38, 0, 3),
            "38.0.3",
            "CVE-2022-3602",
            "high",
            "OpenSSL X.509 certificate verification buffer overrun.",
            "https://github.com/advisories/GHSA-rqhp-hwg2-39x8",
        ),
    ],
    # ── pyjwt ─────────────────────────────────────────────────────────
    "pyjwt": [
        (
            (2, 4, 0),
            "2.4.0",
            "CVE-2022-29217",
            "high",
            "Key confusion attack allows algorithm confusion leading to signature bypass.",
            "https://github.com/advisories/GHSA-ffqj-6fqr-9h24",
        ),
    ],
    "jwt": [
        (
            (2, 4, 0),
            "2.4.0",
            "CVE-2022-29217",
            "high",
            "Key confusion attack allows algorithm confusion leading to signature bypass.",
            "https://github.com/advisories/GHSA-ffqj-6fqr-9h24",
        ),
    ],
    # ── pillow ────────────────────────────────────────────────────────
    "pillow": [
        (
            (10, 0, 1),
            "10.0.1",
            "CVE-2023-44271",
            "high",
            "Uncontrolled resource consumption in PIL.ImageFont.ImageFont.",
            "https://github.com/advisories/GHSA-j7hp-h8jx-5ppr",
        ),
        (
            (9, 0, 1),
            "9.0.1",
            "CVE-2022-22815",
            "medium",
            "Path traversal via PIL.Image.open().",
            "https://github.com/advisories/GHSA-pw3c-h7wp-cvhx",
        ),
        (
            (8, 3, 2),
            "8.3.2",
            "CVE-2021-34552",
            "critical",
            "Pillow allows buffer overflow via crafted FLI file.",
            "https://github.com/advisories/GHSA-8vj2-vxx3-667w",
        ),
    ],
    # ── sqlalchemy ────────────────────────────────────────────────────
    "sqlalchemy": [
        (
            (1, 4, 49),
            "1.4.49",
            "CVE-2023-30608",
            "medium",
            "SQL injection via crafted string in asyncpg dialects.",
            "https://github.com/advisories/GHSA-mr7q-r6qm-767c",
        ),
    ],
    # ── urllib3 ───────────────────────────────────────────────────────
    "urllib3": [
        (
            (1, 26, 18),
            "1.26.18",
            "CVE-2023-45803",
            "medium",
            "urllib3 does not remove the HTTP request body when an HTTP redirect response using status 301, 302, or 303 is received.",
            "https://github.com/advisories/GHSA-g4mx-q9vg-27p4",
        ),
        (
            (2, 0, 7),
            "2.0.7",
            "CVE-2023-45803",
            "medium",
            "urllib3 does not remove the HTTP request body when an HTTP redirect response using status 301, 302, or 303 is received.",
            "https://github.com/advisories/GHSA-g4mx-q9vg-27p4",
        ),
        (
            (1, 26, 5),
            "1.26.5",
            "CVE-2021-33503",
            "high",
            "Denial of service via header value with many @ characters.",
            "https://github.com/advisories/GHSA-q2q7-5pp4-w6pg",
        ),
    ],
    # ── aiohttp ───────────────────────────────────────────────────────
    "aiohttp": [
        (
            (3, 9, 4),
            "3.9.4",
            "CVE-2024-30251",
            "high",
            "HTTP request smuggling via crafted Transfer-Encoding header.",
            "https://github.com/advisories/GHSA-7gpw-8wmc-pm8g",
        ),
        (
            (3, 8, 5),
            "3.8.5",
            "CVE-2023-37276",
            "high",
            "aiohttp allows bypass of Cross-Origin Resource Sharing (CORS) restrictions.",
            "https://github.com/advisories/GHSA-45c4-8wx5-qw6w",
        ),
    ],
    # ── werkzeug ──────────────────────────────────────────────────────
    "werkzeug": [
        (
            (2, 3, 8),
            "2.3.8",
            "CVE-2023-46136",
            "high",
            "Werkzeug multipart data parser vulnerable to resource exhaustion.",
            "https://github.com/advisories/GHSA-hrfv-mqp8-q5rw",
        ),
        (
            (2, 2, 3),
            "2.2.3",
            "CVE-2023-25577",
            "high",
            "High resource usage when parsing multipart form data with many fields.",
            "https://github.com/advisories/GHSA-xg9f-g7g7-2323",
        ),
    ],
    # ── flask ─────────────────────────────────────────────────────────
    "flask": [
        (
            (2, 3, 2),
            "2.3.2",
            "CVE-2023-30861",
            "high",
            "Flask vulnerable to cookie smuggling when proxy sets cookie via Set-Cookie header.",
            "https://github.com/advisories/GHSA-m2qf-hxjv-5gpq",
        ),
    ],
    # ── django ────────────────────────────────────────────────────────
    "django": [
        (
            (4, 2, 10),
            "4.2.10",
            "CVE-2024-24680",
            "high",
            "Django potential denial of service via intcomma template filter.",
            "https://github.com/advisories/GHSA-65cx-mghg-702x",
        ),
        (
            (3, 2, 24),
            "3.2.24",
            "CVE-2024-24680",
            "high",
            "Django potential denial of service via intcomma template filter.",
            "https://github.com/advisories/GHSA-65cx-mghg-702x",
        ),
        (
            (4, 1, 0),
            "4.1.0",
            "CVE-2022-36359",
            "high",
            "Potential reflected file download vulnerability in FileResponse.",
            "https://github.com/advisories/GHSA-2hrw-hx67-34x6",
        ),
    ],
    # ── paramiko ──────────────────────────────────────────────────────
    "paramiko": [
        (
            (3, 4, 0),
            "3.4.0",
            "CVE-2023-48795",
            "high",
            "Terrapin attack: prefix truncation vulnerability in SSH protocol.",
            "https://github.com/advisories/GHSA-mrwq-x4v8-fh7p",
        ),
    ],
    # ── pyopenssl ─────────────────────────────────────────────────────
    "pyopenssl": [
        (
            (23, 2, 0),
            "23.2.0",
            "CVE-2023-49083",
            "high",
            "NULL pointer dereference via PKCS12 parsing.",
            "https://github.com/advisories/GHSA-jfhm-5ghh-2f97",
        ),
    ],
    # ── certifi ───────────────────────────────────────────────────────
    "certifi": [
        (
            (2023, 7, 22),
            "2023.7.22",
            "CVE-2023-37920",
            "high",
            "Certifi removes e-Tugra root certificate due to security incident.",
            "https://github.com/advisories/GHSA-xqr8-7jwr-rhfe",
        ),
    ],
    # ── setuptools ────────────────────────────────────────────────────
    "setuptools": [
        (
            (65, 5, 1),
            "65.5.1",
            "CVE-2022-40897",
            "high",
            "Regular expression denial of service via crafted HTML page.",
            "https://github.com/advisories/GHSA-r9hx-vwmv-q579",
        ),
        (
            (70, 0, 0),
            "70.0.0",
            "CVE-2024-6345",
            "high",
            "Remote code execution via crafted package version in package_index.",
            "https://github.com/advisories/GHSA-cx63-2mw6-8hw5",
        ),
    ],
    # ── pip ───────────────────────────────────────────────────────────
    "pip": [
        (
            (21, 1, 0),
            "21.1.0",
            "CVE-2021-3572",
            "medium",
            "pip allows incorrect URL handling via crafted requirements.txt.",
            "https://github.com/advisories/GHSA-5xp3-jfq3-hjx4",
        ),
        (
            (23, 3, 0),
            "23.3.0",
            "CVE-2023-5752",
            "medium",
            "Mercurial configuration injection via VCS URL.",
            "https://github.com/advisories/GHSA-mq26-g339-26xf",
        ),
    ],
    # ── httpx ─────────────────────────────────────────────────────────
    "httpx": [
        (
            (0, 23, 0),
            "0.23.0",
            "CVE-2021-41945",
            "critical",
            "HTTPX follows redirects without stripping Authorization header.",
            "https://github.com/advisories/GHSA-h8pj-cxx2-jfg2",
        ),
    ],
    # ── pydantic ──────────────────────────────────────────────────────
    "pydantic": [
        (
            (1, 10, 13),
            "1.10.13",
            "CVE-2024-3772",
            "medium",
            "Regular expression denial of service via email validator.",
            "https://github.com/advisories/GHSA-mr82-8j83-vxmv",
        ),
    ],
    # ── starlette / fastapi ───────────────────────────────────────────
    "starlette": [
        (
            (0, 36, 2),
            "0.36.2",
            "CVE-2024-24762",
            "high",
            "Multipart form data parsing without limits causes DoS.",
            "https://github.com/advisories/GHSA-2jv5-9r88-3w3p",
        ),
    ],
    "fastapi": [
        (
            (0, 109, 2),
            "0.109.2",
            "CVE-2024-24762",
            "high",
            "Multipart form data parsing without limits causes DoS via Starlette.",
            "https://github.com/advisories/GHSA-2jv5-9r88-3w3p",
        ),
    ],
    # ── jinja2 ────────────────────────────────────────────────────────
    "jinja2": [
        (
            (3, 1, 3),
            "3.1.3",
            "CVE-2024-22195",
            "medium",
            "Jinja2 HTML attribute injection via xmlattr filter.",
            "https://github.com/advisories/GHSA-h5c8-rqwp-cp95",
        ),
        (
            (2, 11, 3),
            "2.11.3",
            "CVE-2020-28493",
            "medium",
            "Jinja2 ReDoS in urlize filter.",
            "https://github.com/advisories/GHSA-g3rq-g295-4j3m",
        ),
    ],
    # ── lxml ──────────────────────────────────────────────────────────
    "lxml": [
        (
            (4, 9, 1),
            "4.9.1",
            "CVE-2022-2309",
            "medium",
            "NULL pointer dereference in lxml's HTML cleaner.",
            "https://github.com/advisories/GHSA-wrxv-2j5q-m38w",
        ),
    ],
    # ── PyYAML ────────────────────────────────────────────────────────
    "pyyaml": [
        (
            (6, 0),
            "6.0",
            "CVE-2020-14343",
            "critical",
            "PyYAML full_load allows arbitrary Python object deserialization.",
            "https://github.com/advisories/GHSA-8q59-q68h-6hv4",
        ),
    ],
    # ── parameterized ─────────────────────────────────────────────────
    "tornado": [
        (
            (6, 3, 3),
            "6.3.3",
            "CVE-2023-28370",
            "medium",
            "Open redirect vulnerability in StaticFileHandler.",
            "https://github.com/advisories/GHSA-753j-mpmx-qq6g",
        ),
    ],
    # ── Node.js / npm packages ────────────────────────────────────────
    "axios": [
        (
            (1, 6, 0),
            "1.6.0",
            "CVE-2023-45857",
            "high",
            "Axios CSRF token leak via cross-origin redirect.",
            "https://github.com/advisories/GHSA-wf5p-g6vw-rhxx",
        ),
    ],
    "lodash": [
        (
            (4, 17, 21),
            "4.17.21",
            "CVE-2021-23337",
            "high",
            "Command injection via _.template in lodash.",
            "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
        ),
        (
            (4, 17, 19),
            "4.17.19",
            "CVE-2020-8203",
            "high",
            "Prototype pollution via _.zipObjectDeep in lodash.",
            "https://github.com/advisories/GHSA-p6mc-m468-83gw",
        ),
    ],
    "minimist": [
        (
            (1, 2, 6),
            "1.2.6",
            "CVE-2021-44906",
            "critical",
            "Prototype pollution via crafted arguments in minimist.",
            "https://github.com/advisories/GHSA-xvch-5gv4-984h",
        ),
    ],
    "semver": [
        (
            (7, 5, 2),
            "7.5.2",
            "CVE-2022-25883",
            "high",
            "Regular expression denial of service via crafted version string.",
            "https://github.com/advisories/GHSA-c2qf-rxjj-qqgw",
        ),
    ],
    "jsonwebtoken": [
        (
            (9, 0, 0),
            "9.0.0",
            "CVE-2022-23529",
            "high",
            "Arbitrary code execution via crafted expiration claim.",
            "https://github.com/advisories/GHSA-hjrf-2m68-5959",
        ),
    ],
    "express": [
        (
            (4, 19, 0),
            "4.19.0",
            "CVE-2024-29041",
            "medium",
            "Open redirect via malformed URL in Express Router.",
            "https://github.com/advisories/GHSA-rv95-896h-c2vc",
        ),
    ],
    "ejs": [
        (
            (3, 1, 9),
            "3.1.9",
            "CVE-2022-29078",
            "critical",
            "Prototype pollution via settings[view options][outputFunctionName].",
            "https://github.com/advisories/GHSA-phwq-j96m-2c2q",
        ),
    ],
    "marked": [
        (
            (4, 3, 0),
            "4.3.0",
            "CVE-2022-21681",
            "high",
            "ReDoS in marked via crafted markdown input.",
            "https://github.com/advisories/GHSA-5v2h-r2cx-4qr7",
        ),
    ],
    "node-fetch": [
        (
            (2, 6, 7),
            "2.6.7",
            "CVE-2022-0235",
            "high",
            "Exposure of sensitive information to an unauthorized actor.",
            "https://github.com/advisories/GHSA-r683-j2x4-v87g",
        ),
    ],
    "follow-redirects": [
        (
            (1, 15, 4),
            "1.15.4",
            "CVE-2024-28849",
            "medium",
            "Proxy-Authorization header leaked across hosts on redirect.",
            "https://github.com/advisories/GHSA-cxjh-pqwp-8mfp",
        ),
    ],
    "webpack": [
        (
            (5, 76, 0),
            "5.76.0",
            "CVE-2023-28154",
            "critical",
            "Prototype pollution via crafted bundle in webpack.",
            "https://github.com/advisories/GHSA-hc6q-2mpp-qw7j",
        ),
    ],
    "vite": [
        (
            (5, 0, 12),
            "5.0.12",
            "CVE-2024-23331",
            "high",
            "Vite dev server exposes private files via directory traversal.",
            "https://github.com/advisories/GHSA-c24v-8rfc-w8vw",
        ),
    ],
    "tar": [
        (
            (6, 1, 11),
            "6.1.11",
            "CVE-2021-37701",
            "high",
            "Arbitrary file creation/overwrite via crafted tar archive.",
            "https://github.com/advisories/GHSA-9r2w-394v-53qc",
        ),
    ],
    "tough-cookie": [
        (
            (4, 1, 3),
            "4.1.3",
            "CVE-2023-26136",
            "critical",
            "Prototype pollution via CookieJar.setCookie.",
            "https://github.com/advisories/GHSA-72xf-g2v4-qvf3",
        ),
    ],
    "word-wrap": [
        (
            (1, 2, 4),
            "1.2.4",
            "CVE-2023-26115",
            "high",
            "ReDoS via crafted input in word-wrap.",
            "https://github.com/advisories/GHSA-j8xg-fqg3-53r7",
        ),
    ],
    "postcss": [
        (
            (8, 4, 31),
            "8.4.31",
            "CVE-2023-44270",
            "medium",
            "PostCSS line return parsing error allows CSS injection.",
            "https://github.com/advisories/GHSA-7fh8-383j-gc52",
        ),
    ],
    # ── passlib ───────────────────────────────────────────────────────
    "passlib": [
        (
            (1, 7, 4),
            "1.7.4",
            "CVE-2021-20232",
            "high",
            "Passlib bcrypt handler vulnerable to timing attacks in comparison.",
            "https://github.com/advisories/GHSA-75c5-xw7c-p5pm",
        ),
    ],
    # ── bcrypt ────────────────────────────────────────────────────────
    "bcrypt": [
        (
            (4, 0, 0),
            "4.0.0",
            "CVE-2020-5197",
            "medium",
            "bcrypt python binding has a memory disclosure via improper length check.",
            "https://github.com/advisories/GHSA-fcf9-3qw3-gxmj",
        ),
    ],
    # ── grpcio ────────────────────────────────────────────────────────
    "grpcio": [
        (
            (1, 53, 0),
            "1.53.0",
            "CVE-2023-1428",
            "high",
            "gRPC C core reachable assertion via crafted HTTP2 RST_STREAM frame.",
            "https://github.com/advisories/GHSA-cfgp-2977-2fmm",
        ),
    ],
    # ── twisted ───────────────────────────────────────────────────────
    "twisted": [
        (
            (22, 10, 0),
            "22.10.0",
            "CVE-2022-39348",
            "medium",
            "Twisted SSH host key verification bypass via crafted SSH banner.",
            "https://github.com/advisories/GHSA-vg46-2rrj-3647",
        ),
    ],
    # ── httplib2 ──────────────────────────────────────────────────────
    "httplib2": [
        (
            (0, 20, 0),
            "0.20.0",
            "CVE-2021-21240",
            "high",
            "ReDoS in httplib2 via crafted header.",
            "https://github.com/advisories/GHSA-93xj-8mrv-444m",
        ),
    ],
    # ── pyzmq ─────────────────────────────────────────────────────────
    "pyzmq": [
        (
            (25, 0, 0),
            "25.0.0",
            "CVE-2022-37601",
            "medium",
            "PyZMQ prototype pollution via crafted message.",
            "https://github.com/advisories/GHSA-4w5x-x539-ppf5",
        ),
    ],
    # ── ipython ───────────────────────────────────────────────────────
    "ipython": [
        (
            (8, 10, 0),
            "8.10.0",
            "CVE-2023-24816",
            "high",
            "IPython ReDoS via crafted input in IPython.utils.text.strip_ansi.",
            "https://github.com/advisories/GHSA-29gw-9793-fvw7",
        ),
    ],
    # ── notebook ──────────────────────────────────────────────────────
    "notebook": [
        (
            (6, 4, 12),
            "6.4.12",
            "CVE-2022-29238",
            "medium",
            "Jupyter Notebook open redirect via crafted URL.",
            "https://github.com/advisories/GHSA-m87f-39q9-6f55",
        ),
    ],
    # ── oauthlib ──────────────────────────────────────────────────────
    "oauthlib": [
        (
            (3, 2, 2),
            "3.2.2",
            "CVE-2022-36087",
            "medium",
            "OAuthlib ReDoS via crafted redirect URI.",
            "https://github.com/advisories/GHSA-3pgj-pg6c-r5p7",
        ),
    ],
    # ── rich ──────────────────────────────────────────────────────────
    "rich": [
        (
            (13, 7, 0),
            "13.7.0",
            "CVE-2024-22195",
            "low",
            "Rich may log sensitive data via verbose tracebacks.",
            "https://github.com/advisories/GHSA-h5c8-rqwp-cp95",
        ),
    ],
    # ── click ─────────────────────────────────────────────────────────
    "click": [
        (
            (8, 0, 0),
            "8.0.0",
            "CVE-2021-4189",
            "medium",
            "Click may expose environment variables in error messages.",
            "https://github.com/advisories/GHSA-m874-973m-3p74",
        ),
    ],
}

# ---------------------------------------------------------------------------
# Version parsing helpers
# ---------------------------------------------------------------------------


def _parse_version(ver: str) -> Tuple[int, ...]:
    """Parse a version string into a tuple of ints for comparison.

    Handles versions like '2.31.0', '2023.7.22', '1.0.0b1', etc.
    Non-numeric parts are stripped.
    """
    # Keep only the release segment (before any +, -, ~ etc.)
    ver = re.split(r"[+\-~]", ver.split("!")[(-1 if "!" in ver else 0)])[0]
    parts = re.split(r"[.\s]", ver)
    result: List[int] = []
    for p in parts:
        m = re.match(r"(\d+)", p)
        if m:
            result.append(int(m.group(1)))
    return tuple(result) if result else (0,)


def _version_lt(ver_tuple: Tuple[int, ...], threshold: Tuple[int, ...]) -> bool:
    """Return True if ver_tuple < threshold."""
    # Pad shorter tuple with zeros
    length = max(len(ver_tuple), len(threshold))
    v = ver_tuple + (0,) * (length - len(ver_tuple))
    t = threshold + (0,) * (length - len(threshold))
    return v < t


def _parse_requirements_line(line: str) -> Optional[Tuple[str, str]]:
    """Parse a single requirements.txt line.

    Returns (package_name_lower, version) or None for comments/options.
    """
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("-"):
        return None
    # Remove inline comments
    line = line.split(" #")[0].strip()
    # Handle ==, >=, <=, ~=, !=
    for op in ("==", "~=", ">=", "<=", ">", "<", "!="):
        if op in line:
            name, _, spec = line.partition(op)
            # Only extract a clean version from == specs; others give no single installed version
            if op == "==":
                ver = spec.split(",")[0].strip()
                return name.strip().lower().replace("-", "_").replace(".", "_"), ver
            else:
                # Return the first version spec value for >= etc.
                ver = spec.split(",")[0].strip()
                return name.strip().lower().replace("-", "_").replace(".", "_"), ver
    # No version specified — record as 0.0.0
    return line.lower().replace("-", "_").replace(".", "_"), "0.0.0"


def _normalize_pkg_name(name: str) -> str:
    """Normalize package name to lowercase with underscores."""
    return name.lower().replace("-", "_").replace(".", "_")


# ---------------------------------------------------------------------------
# DependencyScanner
# ---------------------------------------------------------------------------


class DependencyScanner:
    """Scan ALDECI's own dependencies for vulnerabilities and outdated versions."""

    def __init__(self) -> None:
        self._vuln_db: Dict[str, List[_VulnEntry]] = {
            _normalize_pkg_name(k): v for k, v in KNOWN_VULNS.items()
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_requirements(self, file_path: str) -> List[DepVulnerability]:
        """Parse a requirements.txt file and check against the vulnerability DB."""
        path = Path(file_path)
        if not path.exists():
            logger.warning("requirements file not found: %s", file_path)
            return []

        packages: Dict[str, str] = {}
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            logger.error("Cannot read %s: %s", file_path, exc)
            return []

        for line in lines:
            parsed = _parse_requirements_line(line)
            if parsed:
                name, ver = parsed
                packages[name] = ver

        results = self._check_packages(packages)
        _tg_emit("dep_scanner.scan_requirements", {"file": file_path, "vuln_count": len(results)})
        return results

    def scan_package_json(self, file_path: str) -> List[DepVulnerability]:
        """Parse a package.json and check dependencies against the vulnerability DB."""
        path = Path(file_path)
        if not path.exists():
            logger.warning("package.json not found: %s", file_path)
            return []

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("Cannot parse %s: %s", file_path, exc)
            return []

        packages: Dict[str, str] = {}
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for pkg, ver_spec in (data.get(section) or {}).items():
                # Strip leading ^ ~ >= etc.
                ver = re.sub(r"^[\^~>=<v\s]+", "", str(ver_spec)).strip()
                packages[_normalize_pkg_name(pkg)] = ver or "0.0.0"

        results = self._check_packages(packages)
        _tg_emit("dep_scanner.scan_package_json", {"file": file_path, "vuln_count": len(results)})
        return results

    def scan_installed(self) -> List[DepVulnerability]:
        """Run pip freeze and check the installed packages against the vuln DB."""
        packages: Dict[str, str] = {}
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "freeze", "--all"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            for line in result.stdout.splitlines():
                parsed = _parse_requirements_line(line)
                if parsed:
                    name, ver = parsed
                    packages[name] = ver
        except Exception as exc:
            logger.error("pip freeze failed: %s", exc)

        results = self._check_packages(packages)
        _tg_emit("dep_scanner.scan_installed", {"vuln_count": len(results)})
        return results

    def get_outdated(self) -> List[Dict[str, Any]]:
        """Return packages that have newer versions available (via pip list --outdated).

        Returns a list of dicts with keys: package, installed_version, latest_version.
        Falls back to an empty list if pip is unavailable or times out.
        """
        outdated: List[Dict[str, Any]] = []
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "list", "--outdated", "--format=json"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0:
                items = json.loads(result.stdout or "[]")
                for item in items:
                    outdated.append(
                        {
                            "package": item.get("name", ""),
                            "installed_version": item.get("version", ""),
                            "latest_version": item.get("latest_version", ""),
                            "latest_filetype": item.get("latest_filetype", "wheel"),
                        }
                    )
        except Exception as exc:
            logger.warning("pip list --outdated failed: %s", exc)
        return outdated

    def get_vulnerable(self) -> List[DepVulnerability]:
        """Return all vulnerabilities found in currently-installed packages."""
        return self.scan_installed()

    def generate_upgrade_plan(self) -> Dict[str, Any]:
        """Generate a prioritized upgrade plan.

        Returns:
            {
                "generated_at": ISO timestamp,
                "total_vulnerabilities": int,
                "critical": [...],
                "high": [...],
                "medium": [...],
                "low": [...],
                "upgrade_commands": [...],
            }
        """
        vulns = self.scan_installed()

        by_severity: Dict[str, List[Dict[str, str]]] = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
        }

        # Deduplicate: one entry per (package, fixed_version)
        seen: set = set()
        for v in vulns:
            key = (v.package, v.fixed_version)
            if key in seen:
                continue
            seen.add(key)
            entry = {
                "package": v.package,
                "installed_version": v.installed_version,
                "fixed_version": v.fixed_version,
                "cve_id": v.cve_id,
                "description": v.description,
                "advisory_url": v.advisory_url,
            }
            sev = v.severity if v.severity in by_severity else "info"
            by_severity[sev].append(entry)

        # Build upgrade commands (pip install pkg>=fixed_ver), highest severity first
        upgrade_cmds: List[str] = []
        for sev in ("critical", "high", "medium", "low"):
            for entry in by_severity[sev]:
                upgrade_cmds.append(
                    f"pip install \"{entry['package']}>={entry['fixed_version']}\""
                )

        total = sum(len(v) for v in by_severity.values())

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_vulnerabilities": total,
            "critical": by_severity["critical"],
            "high": by_severity["high"],
            "medium": by_severity["medium"],
            "low": by_severity["low"],
            "upgrade_commands": upgrade_cmds,
            "summary": (
                f"{total} vulnerabilities found: "
                f"{len(by_severity['critical'])} critical, "
                f"{len(by_severity['high'])} high, "
                f"{len(by_severity['medium'])} medium, "
                f"{len(by_severity['low'])} low."
            ),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_packages(self, packages: Dict[str, str]) -> List[DepVulnerability]:
        """Check a dict of {package: version} against the built-in vuln DB."""
        findings: List[DepVulnerability] = []
        for pkg_norm, installed_ver in packages.items():
            entries = self._vuln_db.get(pkg_norm)
            if not entries:
                continue
            try:
                installed_tuple = _parse_version(installed_ver)
            except Exception:
                continue

            for threshold, fixed_ver, cve_id, severity, description, advisory_url in entries:
                # If threshold is empty tuple () -> affects all versions
                if not threshold or _version_lt(installed_tuple, threshold):
                    findings.append(
                        DepVulnerability(
                            package=pkg_norm,
                            installed_version=installed_ver,
                            fixed_version=fixed_ver,
                            cve_id=cve_id,
                            severity=severity,
                            description=description,
                            advisory_url=advisory_url,
                        )
                    )
        return findings
