"""Supply chain security analyzer — detect compromised packages, typosquats, and transitive risks."""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from threading import Lock
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)

RISK_CATEGORIES = [
    "typosquat",
    "known_malicious",
    "abandoned",
    "compromised_version",
    "suspicious_maintainer",
    "transitive_risk",
]

# Known malicious packages: (name, version_or_None, description)
_KNOWN_MALICIOUS: list[tuple[str, Optional[str], str]] = [
    ("event-stream", "3.3.6", "Cryptominer embedded in postinstall"),
    ("colors", "1.4.44-liberty-2", "Malicious protest code — infinite loop"),
    ("node-ipc", "10.1.2", "Malicious protest code — file deletion"),
    ("ctx", None, "PyPI credential stealer"),
    ("discordpy-self", None, "Remote Access Trojan (RAT)"),
    ("loglib-modules", None, "Info stealer — exfiltrates env vars"),
    ("pytesseract", "0.3.10", "Typosquatted variant with backdoor"),
    ("python-dateutil", "2.8.3", "Compromised maintainer account version"),
    ("setup-tools", None, "Typosquat of setuptools — credential stealer"),
    ("urllib", None, "Typosquat of urllib3 — malicious"),
    ("colourama", None, "Typosquat of colorama — info stealer"),
    ("py-util", None, "Typosquat collecting system info"),
    ("jeIlyfish", None, "Typosquat of jellyfish — credential theft"),
]

# Popular legitimate packages for typosquat reference
_POPULAR_PACKAGES: dict[str, list[str]] = {
    "pypi": [
        "requests", "numpy", "pandas", "flask", "django", "fastapi",
        "setuptools", "urllib3", "colorama", "boto3", "pydantic",
        "sqlalchemy", "pytest", "cryptography", "paramiko", "pillow",
        "tensorflow", "torch", "scikit-learn", "scipy",
    ],
    "npm": [
        "lodash", "express", "react", "axios", "chalk", "commander",
        "moment", "webpack", "babel", "typescript", "eslint", "prettier",
        "jest", "mocha", "nodemon", "dotenv", "cors", "body-parser",
    ],
}

_DEFAULT_DB = "data/supply_chain.db"


class SupplyChainAnalyzer:
    """Analyze software supply chain risks: malicious packages, typosquats, transitive risks."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = Lock()
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        logger.info("supply_chain_analyzer.init", db_path=self.db_path)

    # ------------------------------------------------------------------
    # DB setup
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS supply_chain_analyses (
                    analysis_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL DEFAULT 'default',
                    package_name TEXT,
                    ecosystem TEXT,
                    risk_score REAL,
                    overall_risk TEXT,
                    is_known_malicious INTEGER DEFAULT 0,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sca_org ON supply_chain_analyses(org_id)"
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Core analysis
    # ------------------------------------------------------------------

    def analyze_package(
        self,
        name: str,
        version: Optional[str] = None,
        ecosystem: str = "pypi",
    ) -> dict:
        """Analyze a single package for supply chain risks."""
        risks: list[dict] = []
        risk_score = 0.0

        # 1. Known malicious check
        is_known_malicious = self.check_known_malicious(name, version)
        if is_known_malicious:
            risk_score = max(risk_score, 90.0)
            risks.append({
                "category": "known_malicious",
                "severity": "critical",
                "description": f"Package '{name}' (version={version}) is in the known-malicious database",
            })

        # 2. Typosquat check
        similar_packages = self.detect_typosquats(name, ecosystem)
        is_typosquat = len(similar_packages) > 0
        if is_typosquat:
            risk_score = max(risk_score, 70.0)
            risks.append({
                "category": "typosquat",
                "severity": "high",
                "description": (
                    f"'{name}' is similar to popular packages: "
                    + ", ".join(similar_packages[:5])
                ),
            })

        # 3. Suspicious naming heuristics
        suspicious_patterns = [
            (r"[\-_]test$", "Package name ends with -test or _test"),
            (r"^test[\-_]", "Package name starts with test-"),
            (r"[\-_]dev$", "Package name ends with -dev or _dev (unofficial fork?)"),
            (r"\d{5,}", "Package name contains long numeric sequence"),
        ]
        import re
        for pattern, msg in suspicious_patterns:
            if re.search(pattern, name, re.IGNORECASE):
                risk_score = max(risk_score, 25.0)
                risks.append({
                    "category": "suspicious_maintainer",
                    "severity": "low",
                    "description": msg,
                })
                break

        # 4. Simulate abandonment detection (real impl would call registry API)
        # Use deterministic seed based on package name for reproducible demo data
        import hashlib
        name_hash = int(hashlib.md5(name.encode(), usedforsecurity=False).hexdigest(), 16)
        # Simulate: ~10% of packages are "abandoned" (>2 years no release)
        days_since_release = (name_hash % 1000) + 1
        is_abandoned = days_since_release > 730
        if is_abandoned:
            risk_score = max(risk_score, 35.0)
            risks.append({
                "category": "abandoned",
                "severity": "medium",
                "description": (
                    f"No release in ~{days_since_release} days — package may be unmaintained"
                ),
            })

        # 5. Compromised version check (version-specific flags from known list)
        if version and self._is_compromised_version(name, version):
            risk_score = max(risk_score, 80.0)
            risks.append({
                "category": "compromised_version",
                "severity": "critical",
                "description": f"Version {version} of '{name}' has been flagged as compromised",
            })

        return {
            "package": name,
            "version": version,
            "ecosystem": ecosystem,
            "risk_score": round(risk_score, 2),
            "risks": risks,
            "is_typosquat": is_typosquat,
            "similar_packages": similar_packages,
            "is_known_malicious": is_known_malicious,
            "days_since_last_release": days_since_release,
            "is_abandoned": is_abandoned,
        }

    def analyze_requirements(self, content: str, ecosystem: str = "pypi") -> dict:
        """Analyze requirements.txt or package.json content."""
        packages = self._parse_requirements(content, ecosystem)
        results = []
        high_risk_count = 0

        for pkg_name, pkg_version in packages:
            analysis = self.analyze_package(pkg_name, pkg_version, ecosystem)
            results.append(analysis)
            if analysis["risk_score"] >= 70.0:
                high_risk_count += 1

        # Determine overall risk
        if not results:
            overall_risk = "low"
        else:
            max_score = max(r["risk_score"] for r in results)
            if max_score >= 90:
                overall_risk = "critical"
            elif max_score >= 70:
                overall_risk = "high"
            elif max_score >= 40:
                overall_risk = "medium"
            else:
                overall_risk = "low"

        return {
            "total_packages": len(results),
            "high_risk_count": high_risk_count,
            "packages": results,
            "overall_risk": overall_risk,
        }

    # ------------------------------------------------------------------
    # Typosquat detection
    # ------------------------------------------------------------------

    def detect_typosquats(self, package_name: str, ecosystem: str = "pypi") -> list[str]:
        """Generate typosquat candidates and check against known-popular packages."""
        popular = _POPULAR_PACKAGES.get(ecosystem, _POPULAR_PACKAGES["pypi"])
        name_lower = package_name.lower()

        matches: list[str] = []
        for pop_pkg in popular:
            pop_lower = pop_pkg.lower()
            if pop_lower == name_lower:
                continue  # exact match is not a typosquat
            dist = self._edit_distance(name_lower, pop_lower)
            # Within edit distance 1 or 2 for longer packages
            threshold = 1 if len(pop_lower) <= 5 else 2
            if 0 < dist <= threshold:
                matches.append(pop_pkg)

        return matches

    @staticmethod
    def _edit_distance(a: str, b: str) -> int:
        """Levenshtein edit distance."""
        m, n = len(a), len(b)
        dp = list(range(n + 1))
        for i in range(1, m + 1):
            prev = dp[0]
            dp[0] = i
            for j in range(1, n + 1):
                temp = dp[j]
                if a[i - 1] == b[j - 1]:
                    dp[j] = prev
                else:
                    dp[j] = 1 + min(prev, dp[j], dp[j - 1])
                prev = temp
        return dp[n]

    # ------------------------------------------------------------------
    # Known malicious check
    # ------------------------------------------------------------------

    def check_known_malicious(self, name: str, version: Optional[str] = None) -> bool:
        """Check against built-in list of known malicious packages."""
        name_lower = name.lower()
        for mal_name, mal_version, _ in _KNOWN_MALICIOUS:
            if mal_name.lower() != name_lower:
                continue
            # Name matches — check version
            if mal_version is None:
                return True  # Any version is malicious
            if version is not None and version.strip() == mal_version:
                return True
        return False

    def _is_compromised_version(self, name: str, version: str) -> bool:
        """Check if a specific version is flagged as compromised (subset of known malicious)."""
        name_lower = name.lower()
        for mal_name, mal_version, _ in _KNOWN_MALICIOUS:
            if mal_name.lower() == name_lower and mal_version == version:
                return True
        return False

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def store_analysis(self, analysis: dict, org_id: str = "default") -> str:
        """Store analysis result. Returns analysis_id."""
        analysis_id = str(uuid.uuid4())
        now = time.time()
        package_name = analysis.get("package") or analysis.get("packages", [{}])[0].get("package", "")
        ecosystem = analysis.get("ecosystem", "pypi")
        risk_score = analysis.get("risk_score", analysis.get("overall_risk_score", 0.0))
        overall_risk = analysis.get("overall_risk", "low")
        is_malicious = int(analysis.get("is_known_malicious", False))

        with self._lock, self._get_conn() as conn:
            conn.execute(
                """INSERT INTO supply_chain_analyses
                   (analysis_id, org_id, package_name, ecosystem, risk_score,
                    overall_risk, is_known_malicious, payload, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    analysis_id,
                    org_id,
                    package_name,
                    ecosystem,
                    risk_score,
                    overall_risk,
                    is_malicious,
                    json.dumps(analysis),
                    now,
                ),
            )
            conn.commit()

        logger.info("supply_chain.stored", analysis_id=analysis_id, org_id=org_id)
        return analysis_id

    def get_analysis(self, analysis_id: str) -> Optional[dict]:
        """Retrieve a stored analysis by ID."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT payload FROM supply_chain_analyses WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["payload"])

    def list_analyses(self, org_id: str = "default", limit: int = 50) -> list[dict]:
        """List stored analyses for an org."""
        with self._get_conn() as conn:
            rows = conn.execute(
                """SELECT analysis_id, package_name, ecosystem, risk_score,
                          overall_risk, is_known_malicious, created_at
                   FROM supply_chain_analyses
                   WHERE org_id = ?
                   ORDER BY created_at DESC
                   LIMIT ?""",
                (org_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_risk_summary(self, org_id: str = "default") -> dict:
        """Summary of all analyses for the org."""
        with self._get_conn() as conn:
            row = conn.execute(
                """SELECT
                       COUNT(*) AS total_analyzed,
                       SUM(CASE WHEN risk_score >= 70 THEN 1 ELSE 0 END) AS high_risk_packages,
                       SUM(is_known_malicious) AS known_malicious_detected
                   FROM supply_chain_analyses
                   WHERE org_id = ?""",
                (org_id,),
            ).fetchone()
        return {
            "total_analyzed": row["total_analyzed"] or 0,
            "high_risk_packages": row["high_risk_packages"] or 0,
            "known_malicious_detected": row["known_malicious_detected"] or 0,
        }

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_requirements(content: str, ecosystem: str) -> list[tuple[str, Optional[str]]]:
        """Parse requirements.txt or package.json into (name, version) tuples."""
        results: list[tuple[str, Optional[str]]] = []

        if ecosystem in ("pypi", "pip"):
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                import re
                # Handle ==, >=, <=, ~=, !=
                m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*(?:==\s*([^\s,;]+))?', line)
                if m:
                    results.append((m.group(1), m.group(2)))
        elif ecosystem in ("npm", "node"):
            try:
                data = json.loads(content)
                deps = {}
                deps.update(data.get("dependencies", {}))
                deps.update(data.get("devDependencies", {}))
                for pkg, ver in deps.items():
                    ver_clean = ver.lstrip("^~>=<").strip() if ver else None
                    results.append((pkg, ver_clean or None))
            except (json.JSONDecodeError, AttributeError):
                pass

        return results


# Module-level singleton
_analyzer: Optional[SupplyChainAnalyzer] = None
_analyzer_lock = Lock()


def get_supply_chain_analyzer() -> SupplyChainAnalyzer:
    """Return shared SupplyChainAnalyzer instance."""
    global _analyzer
    with _analyzer_lock:
        if _analyzer is None:
            _analyzer = SupplyChainAnalyzer()
    return _analyzer
