"""ALDECI License Compliance Scanner.

Scans Python (requirements.txt) and Node.js (package.json) dependencies for
license risks, evaluates them against org policies, and stores results in SQLite.

Provides:
- LicenseRisk      enum: PERMISSIVE, WEAK_COPYLEFT, STRONG_COPYLEFT,
                         NETWORK_COPYLEFT, COMMERCIAL, UNKNOWN
- LicensePolicy    enum: ALLOW, WARN, BLOCK
- LicenseResult    Pydantic model
- LicenseScanner   class with 6 public methods + 100+ package DB + SPDX mapping
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

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

_DB_ENV = "FIXOPS_DATA_DIR"
_DEFAULT_DB_DIR = ".fixops_data"
_THREAD_LOCAL = threading.local()


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class LicenseRisk(str, Enum):
    """Risk classification for a software license."""

    PERMISSIVE = "permissive"
    WEAK_COPYLEFT = "weak_copyleft"
    STRONG_COPYLEFT = "strong_copyleft"
    NETWORK_COPYLEFT = "network_copyleft"
    COMMERCIAL = "commercial"
    UNKNOWN = "unknown"


class LicensePolicy(str, Enum):
    """Org policy action for a license or risk level."""

    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


# ---------------------------------------------------------------------------
# Pydantic model
# ---------------------------------------------------------------------------


class LicenseResult(BaseModel):
    """A single license scan result for one package."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    package: str
    version: str
    license_name: str
    risk_level: LicenseRisk
    policy_action: LicensePolicy
    spdx_id: str
    org_id: str = "default"
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"extra": "ignore"}


# ---------------------------------------------------------------------------
# Built-in license database: package name → (spdx_id, risk_level)
# ---------------------------------------------------------------------------
# 100+ common Python + Node.js packages

_PACKAGE_LICENSE_DB: Dict[str, Tuple[str, LicenseRisk]] = {
    # ── Python: permissive ─────────────────────────────────────────────────
    "flask": ("MIT", LicenseRisk.PERMISSIVE),
    "requests": ("Apache-2.0", LicenseRisk.PERMISSIVE),
    "fastapi": ("MIT", LicenseRisk.PERMISSIVE),
    "uvicorn": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "pydantic": ("MIT", LicenseRisk.PERMISSIVE),
    "starlette": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "httpx": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "aiohttp": ("Apache-2.0", LicenseRisk.PERMISSIVE),
    "click": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "boto3": ("Apache-2.0", LicenseRisk.PERMISSIVE),
    "botocore": ("Apache-2.0", LicenseRisk.PERMISSIVE),
    "s3transfer": ("Apache-2.0", LicenseRisk.PERMISSIVE),
    "urllib3": ("MIT", LicenseRisk.PERMISSIVE),
    "certifi": ("MPL-2.0", LicenseRisk.WEAK_COPYLEFT),
    "charset-normalizer": ("MIT", LicenseRisk.PERMISSIVE),
    "idna": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "six": ("MIT", LicenseRisk.PERMISSIVE),
    "attrs": ("MIT", LicenseRisk.PERMISSIVE),
    "typing-extensions": ("PSF-2.0", LicenseRisk.PERMISSIVE),
    "packaging": ("Apache-2.0", LicenseRisk.PERMISSIVE),
    "setuptools": ("MIT", LicenseRisk.PERMISSIVE),
    "wheel": ("MIT", LicenseRisk.PERMISSIVE),
    "pip": ("MIT", LicenseRisk.PERMISSIVE),
    "cryptography": ("Apache-2.0", LicenseRisk.PERMISSIVE),
    "pyopenssl": ("Apache-2.0", LicenseRisk.PERMISSIVE),
    "paramiko": ("LGPL-2.1-or-later", LicenseRisk.WEAK_COPYLEFT),
    "jinja2": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "markupsafe": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "werkzeug": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "itsdangerous": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "pillow": ("HPND", LicenseRisk.PERMISSIVE),
    "numpy": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "pandas": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "scipy": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "matplotlib": ("PSF-2.0", LicenseRisk.PERMISSIVE),
    "scikit-learn": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "tensorflow": ("Apache-2.0", LicenseRisk.PERMISSIVE),
    "torch": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "transformers": ("Apache-2.0", LicenseRisk.PERMISSIVE),
    "openai": ("MIT", LicenseRisk.PERMISSIVE),
    "anthropic": ("MIT", LicenseRisk.PERMISSIVE),
    "langchain": ("MIT", LicenseRisk.PERMISSIVE),
    "sqlalchemy": ("MIT", LicenseRisk.PERMISSIVE),
    "alembic": ("MIT", LicenseRisk.PERMISSIVE),
    "psycopg2": ("LGPL-3.0-or-later", LicenseRisk.WEAK_COPYLEFT),
    "psycopg2-binary": ("LGPL-3.0-or-later", LicenseRisk.WEAK_COPYLEFT),
    "pymysql": ("MIT", LicenseRisk.PERMISSIVE),
    "redis": ("MIT", LicenseRisk.PERMISSIVE),
    "celery": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "kombu": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "pytest": ("MIT", LicenseRisk.PERMISSIVE),
    "pytest-asyncio": ("Apache-2.0", LicenseRisk.PERMISSIVE),
    "pytest-cov": ("MIT", LicenseRisk.PERMISSIVE),
    "coverage": ("Apache-2.0", LicenseRisk.PERMISSIVE),
    "mypy": ("MIT", LicenseRisk.PERMISSIVE),
    "black": ("MIT", LicenseRisk.PERMISSIVE),
    "ruff": ("MIT", LicenseRisk.PERMISSIVE),
    "isort": ("MIT", LicenseRisk.PERMISSIVE),
    "flake8": ("MIT", LicenseRisk.PERMISSIVE),
    "pre-commit": ("MIT", LicenseRisk.PERMISSIVE),
    "bandit": ("Apache-2.0", LicenseRisk.PERMISSIVE),
    "structlog": ("Apache-2.0", LicenseRisk.PERMISSIVE),
    "loguru": ("MIT", LicenseRisk.PERMISSIVE),
    "rich": ("MIT", LicenseRisk.PERMISSIVE),
    "typer": ("MIT", LicenseRisk.PERMISSIVE),
    "pyyaml": ("MIT", LicenseRisk.PERMISSIVE),
    "toml": ("MIT", LicenseRisk.PERMISSIVE),
    "tomli": ("MIT", LicenseRisk.PERMISSIVE),
    "python-dotenv": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "httpcore": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "anyio": ("MIT", LicenseRisk.PERMISSIVE),
    "sniffio": ("MIT", LicenseRisk.PERMISSIVE),
    "h11": ("MIT", LicenseRisk.PERMISSIVE),
    "h2": ("MIT", LicenseRisk.PERMISSIVE),
    "trio": ("MIT OR Apache-2.0", LicenseRisk.PERMISSIVE),
    "websockets": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "arrow": ("Apache-2.0", LicenseRisk.PERMISSIVE),
    "pendulum": ("MIT", LicenseRisk.PERMISSIVE),
    "dateutil": ("Apache-2.0", LicenseRisk.PERMISSIVE),
    "python-dateutil": ("Apache-2.0", LicenseRisk.PERMISSIVE),
    "pytz": ("MIT", LicenseRisk.PERMISSIVE),
    "tzdata": ("Apache-2.0", LicenseRisk.PERMISSIVE),
    # ── Python: weak copyleft ──────────────────────────────────────────────
    "chardet": ("LGPL-2.1-or-later", LicenseRisk.WEAK_COPYLEFT),
    "pygments": ("BSD-2-Clause", LicenseRisk.PERMISSIVE),
    "lxml": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "beautifulsoup4": ("MIT", LicenseRisk.PERMISSIVE),
    "bs4": ("MIT", LicenseRisk.PERMISSIVE),
    "mysqlclient": ("GPL-2.0-only", LicenseRisk.STRONG_COPYLEFT),
    # ── Python: network copyleft ───────────────────────────────────────────
    "gitpython": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    # ── Python: commercial / proprietary ──────────────────────────────────
    "pyinstaller": ("GPL-2.0-or-later", LicenseRisk.STRONG_COPYLEFT),
    # ── Node.js: permissive ────────────────────────────────────────────────
    "react": ("MIT", LicenseRisk.PERMISSIVE),
    "react-dom": ("MIT", LicenseRisk.PERMISSIVE),
    "react-router": ("MIT", LicenseRisk.PERMISSIVE),
    "react-router-dom": ("MIT", LicenseRisk.PERMISSIVE),
    "next": ("MIT", LicenseRisk.PERMISSIVE),
    "vue": ("MIT", LicenseRisk.PERMISSIVE),
    "nuxt": ("MIT", LicenseRisk.PERMISSIVE),
    "svelte": ("MIT", LicenseRisk.PERMISSIVE),
    "angular": ("MIT", LicenseRisk.PERMISSIVE),
    "@angular/core": ("MIT", LicenseRisk.PERMISSIVE),
    "express": ("MIT", LicenseRisk.PERMISSIVE),
    "koa": ("MIT", LicenseRisk.PERMISSIVE),
    "fastify": ("MIT", LicenseRisk.PERMISSIVE),
    "axios": ("MIT", LicenseRisk.PERMISSIVE),
    "lodash": ("MIT", LicenseRisk.PERMISSIVE),
    "underscore": ("MIT", LicenseRisk.PERMISSIVE),
    "moment": ("MIT", LicenseRisk.PERMISSIVE),
    "dayjs": ("MIT", LicenseRisk.PERMISSIVE),
    "date-fns": ("MIT", LicenseRisk.PERMISSIVE),
    "uuid": ("MIT", LicenseRisk.PERMISSIVE),
    "chalk": ("MIT", LicenseRisk.PERMISSIVE),
    "dotenv": ("BSD-2-Clause", LicenseRisk.PERMISSIVE),
    "jest": ("MIT", LicenseRisk.PERMISSIVE),
    "vitest": ("MIT", LicenseRisk.PERMISSIVE),
    "mocha": ("MIT", LicenseRisk.PERMISSIVE),
    "chai": ("MIT", LicenseRisk.PERMISSIVE),
    "sinon": ("BSD-3-Clause", LicenseRisk.PERMISSIVE),
    "eslint": ("MIT", LicenseRisk.PERMISSIVE),
    "prettier": ("MIT", LicenseRisk.PERMISSIVE),
    "typescript": ("Apache-2.0", LicenseRisk.PERMISSIVE),
    "webpack": ("MIT", LicenseRisk.PERMISSIVE),
    "vite": ("MIT", LicenseRisk.PERMISSIVE),
    "rollup": ("MIT", LicenseRisk.PERMISSIVE),
    "esbuild": ("MIT", LicenseRisk.PERMISSIVE),
    "tailwindcss": ("MIT", LicenseRisk.PERMISSIVE),
    "postcss": ("MIT", LicenseRisk.PERMISSIVE),
    "autoprefixer": ("MIT", LicenseRisk.PERMISSIVE),
    "sass": ("MIT", LicenseRisk.PERMISSIVE),
    "zod": ("MIT", LicenseRisk.PERMISSIVE),
    "yup": ("MIT", LicenseRisk.PERMISSIVE),
    "classnames": ("MIT", LicenseRisk.PERMISSIVE),
    "clsx": ("MIT", LicenseRisk.PERMISSIVE),
    "immer": ("MIT", LicenseRisk.PERMISSIVE),
    "zustand": ("MIT", LicenseRisk.PERMISSIVE),
    "redux": ("MIT", LicenseRisk.PERMISSIVE),
    "@reduxjs/toolkit": ("MIT", LicenseRisk.PERMISSIVE),
    "mobx": ("MIT", LicenseRisk.PERMISSIVE),
    "socket.io": ("MIT", LicenseRisk.PERMISSIVE),
    "ws": ("MIT", LicenseRisk.PERMISSIVE),
    "jsonwebtoken": ("MIT", LicenseRisk.PERMISSIVE),
    "bcrypt": ("MIT", LicenseRisk.PERMISSIVE),
    "bcryptjs": ("MIT", LicenseRisk.PERMISSIVE),
    "sharp": ("Apache-2.0", LicenseRisk.PERMISSIVE),
    "multer": ("MIT", LicenseRisk.PERMISSIVE),
    "mongoose": ("MIT", LicenseRisk.PERMISSIVE),
    "sequelize": ("MIT", LicenseRisk.PERMISSIVE),
    "knex": ("MIT", LicenseRisk.PERMISSIVE),
    "pg": ("MIT", LicenseRisk.PERMISSIVE),
    "mysql2": ("MIT", LicenseRisk.PERMISSIVE),
    "ioredis": ("MIT", LicenseRisk.PERMISSIVE),
    "node-fetch": ("MIT", LicenseRisk.PERMISSIVE),
    "cross-fetch": ("MIT", LicenseRisk.PERMISSIVE),
    "body-parser": ("MIT", LicenseRisk.PERMISSIVE),
    "cors": ("MIT", LicenseRisk.PERMISSIVE),
    "helmet": ("MIT", LicenseRisk.PERMISSIVE),
    "morgan": ("MIT", LicenseRisk.PERMISSIVE),
    "compression": ("MIT", LicenseRisk.PERMISSIVE),
    "winston": ("MIT", LicenseRisk.PERMISSIVE),
    "pino": ("MIT", LicenseRisk.PERMISSIVE),
    "debug": ("MIT", LicenseRisk.PERMISSIVE),
    "semver": ("ISC", LicenseRisk.PERMISSIVE),
    "glob": ("ISC", LicenseRisk.PERMISSIVE),
    "minimatch": ("ISC", LicenseRisk.PERMISSIVE),
    "commander": ("MIT", LicenseRisk.PERMISSIVE),
    "yargs": ("MIT", LicenseRisk.PERMISSIVE),
    "inquirer": ("MIT", LicenseRisk.PERMISSIVE),
    "ora": ("MIT", LicenseRisk.PERMISSIVE),
    "nodemon": ("MIT", LicenseRisk.PERMISSIVE),
    "concurrently": ("MIT", LicenseRisk.PERMISSIVE),
    "rimraf": ("ISC", LicenseRisk.PERMISSIVE),
    "mkdirp": ("MIT", LicenseRisk.PERMISSIVE),
    "copy-webpack-plugin": ("MIT", LicenseRisk.PERMISSIVE),
    "html-webpack-plugin": ("MIT", LicenseRisk.PERMISSIVE),
    "@vitejs/plugin-react": ("MIT", LicenseRisk.PERMISSIVE),
}

# ---------------------------------------------------------------------------
# SPDX ID → risk level mapping
# ---------------------------------------------------------------------------

_SPDX_RISK_MAP: Dict[str, LicenseRisk] = {
    # Permissive
    "MIT": LicenseRisk.PERMISSIVE,
    "Apache-2.0": LicenseRisk.PERMISSIVE,
    "BSD-2-Clause": LicenseRisk.PERMISSIVE,
    "BSD-3-Clause": LicenseRisk.PERMISSIVE,
    "ISC": LicenseRisk.PERMISSIVE,
    "Unlicense": LicenseRisk.PERMISSIVE,
    "CC0-1.0": LicenseRisk.PERMISSIVE,
    "WTFPL": LicenseRisk.PERMISSIVE,
    "Zlib": LicenseRisk.PERMISSIVE,
    "PSF-2.0": LicenseRisk.PERMISSIVE,
    "Python-2.0": LicenseRisk.PERMISSIVE,
    "HPND": LicenseRisk.PERMISSIVE,
    "BlueOak-1.0.0": LicenseRisk.PERMISSIVE,
    "0BSD": LicenseRisk.PERMISSIVE,
    "Artistic-2.0": LicenseRisk.PERMISSIVE,
    "BSL-1.1": LicenseRisk.PERMISSIVE,
    # Weak copyleft
    "LGPL-2.0-only": LicenseRisk.WEAK_COPYLEFT,
    "LGPL-2.0-or-later": LicenseRisk.WEAK_COPYLEFT,
    "LGPL-2.1-only": LicenseRisk.WEAK_COPYLEFT,
    "LGPL-2.1-or-later": LicenseRisk.WEAK_COPYLEFT,
    "LGPL-3.0-only": LicenseRisk.WEAK_COPYLEFT,
    "LGPL-3.0-or-later": LicenseRisk.WEAK_COPYLEFT,
    "MPL-2.0": LicenseRisk.WEAK_COPYLEFT,
    "MPL-1.1": LicenseRisk.WEAK_COPYLEFT,
    "CDDL-1.0": LicenseRisk.WEAK_COPYLEFT,
    "EPL-1.0": LicenseRisk.WEAK_COPYLEFT,
    "EPL-2.0": LicenseRisk.WEAK_COPYLEFT,
    "EUPL-1.1": LicenseRisk.WEAK_COPYLEFT,
    "EUPL-1.2": LicenseRisk.WEAK_COPYLEFT,
    "CECILL-2.1": LicenseRisk.WEAK_COPYLEFT,
    # Strong copyleft
    "GPL-2.0-only": LicenseRisk.STRONG_COPYLEFT,
    "GPL-2.0-or-later": LicenseRisk.STRONG_COPYLEFT,
    "GPL-3.0-only": LicenseRisk.STRONG_COPYLEFT,
    "GPL-3.0-or-later": LicenseRisk.STRONG_COPYLEFT,
    "OSL-3.0": LicenseRisk.STRONG_COPYLEFT,
    "EUPL-1.0": LicenseRisk.STRONG_COPYLEFT,
    # Network copyleft
    "AGPL-3.0-only": LicenseRisk.NETWORK_COPYLEFT,
    "AGPL-3.0-or-later": LicenseRisk.NETWORK_COPYLEFT,
    "AGPL-1.0-only": LicenseRisk.NETWORK_COPYLEFT,
    "SSPL-1.0": LicenseRisk.NETWORK_COPYLEFT,
    "BUSL-1.1": LicenseRisk.NETWORK_COPYLEFT,
    "Commons-Clause": LicenseRisk.NETWORK_COPYLEFT,
    # Commercial
    "LicenseRef-Proprietary": LicenseRisk.COMMERCIAL,
    "LicenseRef-Commercial": LicenseRisk.COMMERCIAL,
    "LicenseRef-EULA": LicenseRisk.COMMERCIAL,
}

# Common aliases → canonical SPDX ID
_LICENSE_ALIASES: Dict[str, str] = {
    "mit": "MIT",
    "mit license": "MIT",
    "apache": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "bsd-2": "BSD-2-Clause",
    "bsd-3": "BSD-3-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "isc": "ISC",
    "isc license": "ISC",
    "gpl": "GPL-3.0-only",
    "gpl-2": "GPL-2.0-only",
    "gpl-2.0": "GPL-2.0-only",
    "gpl-3": "GPL-3.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "gpl v2": "GPL-2.0-only",
    "gpl v3": "GPL-3.0-only",
    "gnu gpl v2": "GPL-2.0-only",
    "gnu gpl v3": "GPL-3.0-only",
    "gnu general public license v2": "GPL-2.0-only",
    "gnu general public license v3": "GPL-3.0-only",
    "lgpl": "LGPL-3.0-or-later",
    "lgpl-2": "LGPL-2.0-or-later",
    "lgpl-2.0": "LGPL-2.0-or-later",
    "lgpl-2.1": "LGPL-2.1-or-later",
    "lgpl-3": "LGPL-3.0-or-later",
    "lgpl-3.0": "LGPL-3.0-or-later",
    "agpl": "AGPL-3.0-only",
    "agpl-3": "AGPL-3.0-only",
    "agpl-3.0": "AGPL-3.0-only",
    "mpl": "MPL-2.0",
    "mpl-2": "MPL-2.0",
    "mpl-2.0": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
    "sspl": "SSPL-1.0",
    "sspl-1.0": "SSPL-1.0",
    "proprietary": "LicenseRef-Proprietary",
    "commercial": "LicenseRef-Commercial",
    "eula": "LicenseRef-EULA",
    "unlicense": "Unlicense",
    "public domain": "Unlicense",
    "cc0": "CC0-1.0",
    "cc0 1.0": "CC0-1.0",
    "wtfpl": "WTFPL",
    "psf": "PSF-2.0",
    "python": "Python-2.0",
    "zlib": "Zlib",
    "eupl": "EUPL-1.2",
    "eupl-1.1": "EUPL-1.1",
    "eupl-1.2": "EUPL-1.2",
    "epl": "EPL-2.0",
    "epl-1.0": "EPL-1.0",
    "epl-2.0": "EPL-2.0",
    "cddl": "CDDL-1.0",
    "osl": "OSL-3.0",
    "osl-3.0": "OSL-3.0",
}

# Default policy: risk level → policy action
_DEFAULT_RISK_POLICY: Dict[LicenseRisk, LicensePolicy] = {
    LicenseRisk.PERMISSIVE: LicensePolicy.ALLOW,
    LicenseRisk.WEAK_COPYLEFT: LicensePolicy.WARN,
    LicenseRisk.STRONG_COPYLEFT: LicensePolicy.WARN,
    LicenseRisk.NETWORK_COPYLEFT: LicensePolicy.BLOCK,
    LicenseRisk.COMMERCIAL: LicensePolicy.BLOCK,
    LicenseRisk.UNKNOWN: LicensePolicy.WARN,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _db_path() -> Path:
    data_dir = Path(os.getenv(_DB_ENV, _DEFAULT_DB_DIR))
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / "license_scanner.db"


def _normalize_license(raw: str) -> str:
    """Return canonical SPDX ID from a raw license string."""
    key = raw.strip().lower()
    return _LICENSE_ALIASES.get(key, raw.strip())


def _spdx_to_risk(spdx_id: str) -> LicenseRisk:
    """Map an SPDX ID to a LicenseRisk level."""
    # Try exact match
    if spdx_id in _SPDX_RISK_MAP:
        return _SPDX_RISK_MAP[spdx_id]
    # Try prefix matching for versioned SPDX IDs
    for key, risk in _SPDX_RISK_MAP.items():
        if spdx_id.startswith(key.split("-")[0] + "-"):
            return risk
    return LicenseRisk.UNKNOWN


def _parse_version_from_requirement(line: str) -> str:
    """Extract version string from a requirements line like package==1.2.3."""
    match = re.search(r"==\s*([^\s,;]+)", line)
    return match.group(1) if match else "unknown"


def _parse_package_name(line: str) -> str:
    """Extract package name from a requirements line."""
    line = line.strip()
    match = re.match(r"^([A-Za-z0-9_.\-]+)", line)
    return match.group(1).lower().replace("_", "-") if match else ""


# ---------------------------------------------------------------------------
# LicenseScanner
# ---------------------------------------------------------------------------


class LicenseScanner:
    """SQLite-backed license compliance scanner for Python and Node.js deps.

    Usage::

        scanner = LicenseScanner()
        results = scanner.scan_requirements(content)
        violations = scanner.get_violations("my-org")
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._db_path = Path(db_path) if db_path else _db_path()
        self._init_db()

    # ------------------------------------------------------------------
    # DB bootstrap
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(_THREAD_LOCAL, "license_scanner_conn"):
            conn = sqlite3.connect(str(self._db_path))
            conn.execute("PRAGMA journal_mode=WAL")
            conn.row_factory = sqlite3.Row
            _THREAD_LOCAL.license_scanner_conn = conn
        return _THREAD_LOCAL.license_scanner_conn

    def _init_db(self) -> None:
        conn = self._conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scan_results (
                id TEXT PRIMARY KEY,
                package TEXT NOT NULL,
                version TEXT NOT NULL,
                license_name TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                policy_action TEXT NOT NULL,
                spdx_id TEXT NOT NULL,
                org_id TEXT NOT NULL DEFAULT 'default',
                scanned_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS org_policies (
                org_id TEXT NOT NULL,
                rule_key TEXT NOT NULL,
                rule_value TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (org_id, rule_key)
            );
            """
        )
        conn.commit()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _lookup_package(self, name: str) -> Tuple[str, LicenseRisk]:
        """Return (spdx_id, risk_level) for a package name."""
        key = name.strip().lower().replace("_", "-")
        if key in _PACKAGE_LICENSE_DB:
            return _PACKAGE_LICENSE_DB[key]
        return ("LicenseRef-Unknown", LicenseRisk.UNKNOWN)

    def _lookup_license(self, raw_license: str) -> Tuple[str, LicenseRisk]:
        """Normalise a raw license string and return (spdx_id, risk_level)."""
        if not raw_license or raw_license.upper() in ("UNKNOWN", "NONE", ""):
            return ("LicenseRef-Unknown", LicenseRisk.UNKNOWN)
        spdx_id = _normalize_license(raw_license)
        risk = _spdx_to_risk(spdx_id)
        return (spdx_id, risk)

    def _get_org_policy(self, org_id: str) -> Dict[str, Any]:
        """Load policy rules for org from DB, returning a dict."""
        conn = self._conn()
        rows = conn.execute(
            "SELECT rule_key, rule_value FROM org_policies WHERE org_id = ?",
            (org_id,),
        ).fetchall()
        policy: Dict[str, Any] = {}
        for row in rows:
            try:
                policy[row["rule_key"]] = json.loads(row["rule_value"])
            except (json.JSONDecodeError, TypeError):
                policy[row["rule_key"]] = row["rule_value"]
        return policy

    def _apply_policy(
        self,
        spdx_id: str,
        risk_level: LicenseRisk,
        policy: Dict[str, Any],
    ) -> LicensePolicy:
        """Determine the policy action for one package given org policy."""
        blocked: List[str] = policy.get("blocked_licenses", [])
        allowed: List[str] = policy.get("allowed_licenses", [])
        risk_overrides: Dict[str, str] = policy.get("risk_policy", {})

        if spdx_id in blocked:
            return LicensePolicy.BLOCK
        if allowed and spdx_id not in allowed:
            return LicensePolicy.WARN

        # Check risk-level overrides stored in policy
        if risk_level.value in risk_overrides:
            try:
                return LicensePolicy(risk_overrides[risk_level.value])
            except ValueError:
                pass

        return _DEFAULT_RISK_POLICY.get(risk_level, LicensePolicy.WARN)

    def _persist_results(self, results: List[LicenseResult]) -> None:
        """Upsert scan results into DB — one executemany() instead of N execute() calls."""
        if not results:
            return
        conn = self._conn()
        rows = [
            (
                r.id,
                r.package,
                r.version,
                r.license_name,
                r.risk_level.value,
                r.policy_action.value,
                r.spdx_id,
                r.org_id,
                r.scanned_at.isoformat(),
            )
            for r in results
        ]
        conn.executemany(
            """
            INSERT OR REPLACE INTO scan_results
              (id, package, version, license_name, risk_level, policy_action,
               spdx_id, org_id, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()

    def _build_result(
        self,
        package: str,
        version: str,
        spdx_id: str,
        risk_level: LicenseRisk,
        org_id: str,
        policy: Dict[str, Any],
    ) -> LicenseResult:
        policy_action = self._apply_policy(spdx_id, risk_level, policy)
        return LicenseResult(
            package=package,
            version=version,
            license_name=spdx_id,
            risk_level=risk_level,
            policy_action=policy_action,
            spdx_id=spdx_id,
            org_id=org_id,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_requirements(
        self,
        content: str,
        org_id: str = "default",
    ) -> List[LicenseResult]:
        """Parse requirements.txt content and return license results.

        Args:
            content: Raw text of a requirements.txt file.
            org_id:  Organisation identifier for policy lookup.

        Returns:
            List of LicenseResult, one per resolvable dependency.
        """
        policy = self._get_org_policy(org_id)
        results: List[LicenseResult] = []

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-", "git+", "http")):
                continue
            name = _parse_package_name(line)
            if not name:
                continue
            version = _parse_version_from_requirement(line)
            spdx_id, risk = self._lookup_package(name)
            results.append(
                self._build_result(name, version, spdx_id, risk, org_id, policy)
            )

        self._persist_results(results)
        _tg_emit("license_scanner.scan_requirements", {"org_id": org_id, "results_count": len(results)})
        return results

    def scan_package_json(
        self,
        content: str,
        org_id: str = "default",
    ) -> List[LicenseResult]:
        """Parse package.json content and return license results.

        Args:
            content: Raw JSON text of a package.json file.
            org_id:  Organisation identifier for policy lookup.

        Returns:
            List of LicenseResult, one per dependency.
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse package.json: %s", exc)
            return []

        policy = self._get_org_policy(org_id)
        results: List[LicenseResult] = []

        all_deps: Dict[str, str] = {}
        all_deps.update(data.get("dependencies", {}))
        all_deps.update(data.get("devDependencies", {}))

        for pkg_name, version_spec in all_deps.items():
            version = version_spec.lstrip("^~>=<").split(" ")[0] if version_spec else "unknown"
            name_key = pkg_name.lower().replace("_", "-")
            spdx_id, risk = self._lookup_package(name_key)
            results.append(
                self._build_result(pkg_name, version, spdx_id, risk, org_id, policy)
            )

        self._persist_results(results)
        return results

    def evaluate_policy(
        self,
        results: List[LicenseResult],
        policy: Dict[str, Any],
    ) -> List[LicenseResult]:
        """Re-evaluate a list of LicenseResult objects against a given policy.

        Useful for what-if policy analysis without touching the DB.

        Args:
            results: Previously scanned LicenseResult objects.
            policy:  Policy dict with optional keys:
                     - blocked_licenses: list of SPDX IDs to block
                     - allowed_licenses: list of SPDX IDs to allow
                     - risk_policy: dict mapping risk level → policy action

        Returns:
            New list of LicenseResult with updated policy_action fields.
        """
        updated: List[LicenseResult] = []
        for r in results:
            new_action = self._apply_policy(r.spdx_id, r.risk_level, policy)
            updated.append(r.model_copy(update={"policy_action": new_action}))
        return updated

    def get_license_summary(self, org_id: str = "default") -> Dict[str, Any]:
        """Return distribution of scanned packages by risk level for an org.

        Args:
            org_id: Organisation identifier.

        Returns:
            Dict with keys: total, by_risk (counts per LicenseRisk),
            by_policy (counts per LicensePolicy), scanned_at.
        """
        conn = self._conn()
        rows = conn.execute(
            "SELECT risk_level, policy_action, COUNT(*) as cnt "
            "FROM scan_results WHERE org_id = ? "
            "GROUP BY risk_level, policy_action",
            (org_id,),
        ).fetchall()

        by_risk: Dict[str, int] = {}
        by_policy: Dict[str, int] = {}
        total = 0

        for row in rows:
            cnt = row["cnt"]
            total += cnt
            risk = row["risk_level"]
            action = row["policy_action"]
            by_risk[risk] = by_risk.get(risk, 0) + cnt
            by_policy[action] = by_policy.get(action, 0) + cnt

        return {
            "org_id": org_id,
            "total": total,
            "by_risk": by_risk,
            "by_policy": by_policy,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def set_policy(self, org_id: str, rules: Dict[str, Any]) -> None:
        """Persist license policy rules for an organisation.

        Args:
            org_id: Organisation identifier.
            rules:  Arbitrary policy dict, e.g.:
                    {
                      "blocked_licenses": ["AGPL-3.0-only", "SSPL-1.0"],
                      "allowed_licenses": ["MIT", "Apache-2.0", "BSD-3-Clause"],
                      "risk_policy": {"strong_copyleft": "warn"},
                    }
        """
        conn = self._conn()
        now = datetime.now(timezone.utc).isoformat()
        rows = [(org_id, key, json.dumps(value), now) for key, value in rules.items()]
        conn.executemany(
            """
            INSERT OR REPLACE INTO org_policies (org_id, rule_key, rule_value, updated_at)
            VALUES (?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()
        logger.info("Policy updated for org %s: %d rules", org_id, len(rules))

    def get_violations(self, org_id: str = "default") -> List[LicenseResult]:
        """Return all scan results for an org where policy_action = BLOCK.

        Args:
            org_id: Organisation identifier.

        Returns:
            List of LicenseResult objects that violate the org policy.
        """
        conn = self._conn()
        rows = conn.execute(
            "SELECT * FROM scan_results WHERE org_id = ? AND policy_action = 'block' "
            "ORDER BY scanned_at DESC",
            (org_id,),
        ).fetchall()

        results: List[LicenseResult] = []
        for row in rows:
            try:
                results.append(
                    LicenseResult(
                        id=row["id"],
                        package=row["package"],
                        version=row["version"],
                        license_name=row["license_name"],
                        risk_level=LicenseRisk(row["risk_level"]),
                        policy_action=LicensePolicy(row["policy_action"]),
                        spdx_id=row["spdx_id"],
                        org_id=row["org_id"],
                        scanned_at=datetime.fromisoformat(row["scanned_at"]),
                    )
                )
            except (ValueError, KeyError) as exc:
                logger.warning("Skipping malformed row: %s", exc)
        return results
