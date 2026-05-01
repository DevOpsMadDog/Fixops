"""MobileAppSecurityEngine — ALDECI.

Manages mobile application security scanning, findings, and risk posture.

Features:
- App registration across iOS, Android, React Native, Flutter, Xamarin, Web
- Security findings by OWASP Mobile Top 10 categories
- Scan lifecycle: queued → running → completed/failed
- Stats: risk breakdown, platform distribution, finding severity

SQLite WAL + threading.RLock + multi-tenant org_id isolation.
DB at .fixops_data/mobile_app_security.db.

Compliance: OWASP Mobile Top 10, CWE, NIST SP 800-163.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "mobile_app_security.db"
)

VALID_PLATFORMS = frozenset({"ios", "android", "react_native", "flutter", "xamarin", "web"})
VALID_CATEGORIES = frozenset({"banking", "healthcare", "retail", "enterprise", "social", "gaming", "utility"})
VALID_RISK_LEVELS = frozenset({"critical", "high", "medium", "low"})
VALID_APP_STATUSES = frozenset({"active", "archived", "deprecated"})

VALID_FINDING_TYPES = frozenset({
    "insecure_storage", "weak_crypto", "hardcoded_secret", "improper_auth",
    "insecure_transport", "code_injection", "reverse_engineering",
    "data_leakage", "improper_session", "third_party_lib",
})
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
VALID_FINDING_STATUSES = frozenset({"open", "in_review", "fixed", "accepted_risk"})

VALID_SCAN_TYPES = frozenset({"sast", "dast", "penetration", "api", "binary"})
VALID_SCAN_STATUSES = frozenset({"queued", "running", "completed", "failed"})


class MobileAppSecurityEngine:
    """SQLite-backed mobile app security engine. Thread-safe, multi-tenant."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # DB INIT
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS mas_apps (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    app_name     TEXT NOT NULL,
                    bundle_id    TEXT NOT NULL,
                    platform     TEXT NOT NULL,
                    version      TEXT NOT NULL DEFAULT '1.0.0',
                    category     TEXT NOT NULL,
                    risk_score   REAL NOT NULL DEFAULT 50.0,
                    risk_level   TEXT NOT NULL DEFAULT 'medium',
                    last_scanned TEXT,
                    status       TEXT NOT NULL DEFAULT 'active',
                    created_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_mas_apps_org ON mas_apps(org_id);

                CREATE TABLE IF NOT EXISTS mas_findings (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    app_id         TEXT NOT NULL,
                    finding_type   TEXT NOT NULL,
                    severity       TEXT NOT NULL,
                    title          TEXT NOT NULL,
                    description    TEXT,
                    owasp_category TEXT,
                    status         TEXT NOT NULL DEFAULT 'open',
                    cwe_id         TEXT,
                    discovered_at  TEXT NOT NULL,
                    created_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_mas_findings_org ON mas_findings(org_id);
                CREATE INDEX IF NOT EXISTS idx_mas_findings_app ON mas_findings(app_id);

                CREATE TABLE IF NOT EXISTS mas_scans (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    app_id           TEXT NOT NULL,
                    scan_type        TEXT NOT NULL,
                    status           TEXT NOT NULL DEFAULT 'queued',
                    total_findings   INTEGER NOT NULL DEFAULT 0,
                    critical_findings INTEGER NOT NULL DEFAULT 0,
                    scan_score       REAL NOT NULL DEFAULT 0.0,
                    started_at       TEXT,
                    completed_at     TEXT,
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_mas_scans_org ON mas_scans(org_id);
                CREATE INDEX IF NOT EXISTS idx_mas_scans_app ON mas_scans(app_id);
            """)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # APPS
    # ------------------------------------------------------------------

    def register_app(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new mobile application. Returns the app record."""
        app_name = data.get("app_name", "").strip()
        if not app_name:
            raise ValueError("app_name is required")

        bundle_id = data.get("bundle_id", "").strip()
        if not bundle_id:
            raise ValueError("bundle_id is required")

        platform = data.get("platform", "").lower()
        if platform not in VALID_PLATFORMS:
            raise ValueError(f"platform must be one of {sorted(VALID_PLATFORMS)}, got '{platform}'")

        category = data.get("category", "").lower()
        if category not in VALID_CATEGORIES:
            raise ValueError(f"category must be one of {sorted(VALID_CATEGORIES)}, got '{category}'")

        risk_score = float(data.get("risk_score", 50.0))
        risk_level = data.get("risk_level", "medium").lower()
        if risk_level not in VALID_RISK_LEVELS:
            raise ValueError(f"risk_level must be one of {sorted(VALID_RISK_LEVELS)}, got '{risk_level}'")

        app_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO mas_apps
                   (id, org_id, app_name, bundle_id, platform, version, category,
                    risk_score, risk_level, last_scanned, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    app_id, org_id, app_name, bundle_id, platform,
                    data.get("version", "1.0.0"), category,
                    risk_score, risk_level, data.get("last_scanned"),
                    data.get("status", "active"), now,
                ),
            )
        _logger.info("mas.app_registered org=%s app_id=%s platform=%s", org_id, app_id, platform)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "mobile_app_security", "org_id": org_id, "source_engine": "mobile_app_security"})
            except Exception:
                pass

        return self.get_app(org_id, app_id)

    def list_apps(
        self,
        org_id: str,
        platform: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List apps for org, optionally filtered by platform or risk_level."""
        query = "SELECT * FROM mas_apps WHERE org_id=?"
        params: List[Any] = [org_id]
        if platform:
            query += " AND platform=?"
            params.append(platform)
        if risk_level:
            query += " AND risk_level=?"
            params.append(risk_level)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Connector fallback — MobSFConnector → derived apps
    # ------------------------------------------------------------------

    def list_apps_with_mobsf_fallback(
        self,
        org_id: str,
        platform: Optional[str] = None,
        risk_level: Optional[str] = None,
        mobsf_connector: Any = None,
    ) -> Dict[str, Any]:
        """List mobile apps; when org has zero rows AND
        ``MobSFConnector.is_configured()`` is True, project the live MobSF
        scan corpus as derived rows.

        Behaviour:
            - Org-registered rows always take precedence (returns
              ``source="org_registered"``).
            - When org has none AND ``MOBSF_API_URL`` + ``MOBSF_API_KEY``
              are set, ``import_findings(org_id)`` runs and each scan
              becomes a derived app row tagged ``source="mobsf"``.
            - When MobSF is not configured, returns
              ``{"apps": [], "source": "needs_credentials", "hint": ...}``.
            - When MobSF is configured but has no scans for this org, returns
              ``source="needs_scan"``.
            - When MobSF returns an HTTP/network error, returns
              ``source="connector_error"`` with the error string surfaced.
            - Filters apply against derived rows.

        Args:
            org_id:           Tenant identifier.
            platform:         Optional filter (ios|android|...).
            risk_level:       Optional filter (critical|high|medium|low).
            mobsf_connector:  Override for testing — must expose
                              ``is_configured()`` + ``import_findings(org_id)``.

        Returns:
            ``{apps, total, source, hint?, scans_pulled?}``.
        """
        rows = self.list_apps(org_id, platform=platform, risk_level=risk_level)
        if rows:
            return {
                "apps": rows,
                "total": len(rows),
                "source": "org_registered",
            }

        # Lazy-import MobSF connector unless override provided.
        if mobsf_connector is None:
            try:
                from connectors.mobsf_connector import get_mobsf_connector
                mobsf_connector = get_mobsf_connector()
            except ImportError as exc:
                _logger.warning("MobSFConnector unavailable: %s", exc)
                return {
                    "apps": [],
                    "total": 0,
                    "source": "needs_credentials",
                    "hint": (
                        "Install requests and configure MOBSF_API_URL + "
                        "MOBSF_API_KEY environment variables, then re-query. "
                        "Or POST /api/v1/mobile-app-security/apps to register "
                        "manually."
                    ),
                }

        if not mobsf_connector.is_configured():
            return {
                "apps": [],
                "total": 0,
                "source": "needs_credentials",
                "hint": (
                    "Set MOBSF_API_URL (e.g. http://localhost:8000) and "
                    "MOBSF_API_KEY (MobSF UI → API Docs) to enable mobile "
                    "scan ingestion. Or POST /api/v1/mobile-app-security/"
                    "apps to register manually."
                ),
            }

        try:
            payload = mobsf_connector.import_findings(org_id=org_id)
        except (ValueError, RuntimeError, OSError) as exc:
            _logger.warning("MobSF import_findings failed: %s", exc)
            return {
                "apps": [],
                "total": 0,
                "source": "connector_error",
                "error": str(exc),
                "hint": (
                    "MobSF is configured but the import call failed. "
                    "Verify the MobSF instance is reachable at MOBSF_API_URL "
                    "and the API key is valid."
                ),
            }

        status = (payload or {}).get("status")
        if status == "needs_credentials":
            return {
                "apps": [],
                "total": 0,
                "source": "needs_credentials",
                "hint": "Set MOBSF_API_URL + MOBSF_API_KEY env vars.",
            }
        if status == "error":
            return {
                "apps": [],
                "total": 0,
                "source": "connector_error",
                "error": payload.get("error"),
                "hint": (
                    "MobSF reported an error during ingestion — verify the "
                    "instance is up and the API key has scan-list scope."
                ),
            }

        raw_apps = payload.get("apps") or []
        if not raw_apps:
            return {
                "apps": [],
                "total": 0,
                "source": "needs_scan",
                "hint": (
                    "MobSF is configured but has no scans yet. Upload an "
                    "APK/IPA to the MobSF instance or run a CI scan, then "
                    "re-query."
                ),
            }

        derived: List[Dict[str, Any]] = []
        for raw in raw_apps:
            derived_platform = (raw.get("platform") or "").lower()
            derived_risk_level = (raw.get("risk_level") or "").lower()
            if platform is not None and derived_platform != platform:
                continue
            if risk_level is not None and derived_risk_level != risk_level:
                continue
            now = self._now()
            derived.append({
                "id": f"mobsf:{raw.get('mobsf_hash') or raw.get('bundle_id', '')}",
                "org_id": org_id,
                "app_name": raw.get("app_name"),
                "bundle_id": raw.get("bundle_id"),
                "platform": derived_platform or "android",
                "version": raw.get("version", "1.0.0"),
                "category": raw.get("category", "enterprise"),
                "risk_score": float(raw.get("risk_score") or 50.0),
                "risk_level": derived_risk_level or "medium",
                "last_scanned": raw.get("last_scanned"),
                "status": raw.get("status", "active"),
                "created_at": now,
                # provenance
                "source": "mobsf",
                "mobsf_hash": raw.get("mobsf_hash", ""),
            })

        return {
            "apps": derived,
            "total": len(derived),
            "source": "mobsf",
            "scans_pulled": payload.get("scans_pulled", 0),
            "scorecards_pulled": payload.get("scorecards_pulled", 0),
            "hint": (
                "Apps projected from MobSF scan corpus. Org-registered rows "
                "take precedence — POST /api/v1/mobile-app-security/apps to "
                "override."
            ),
        }

    def get_app(self, org_id: str, app_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single app scoped to org_id. Returns None if not found."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM mas_apps WHERE org_id=? AND id=?",
                (org_id, app_id),
            ).fetchone()
        if not row:
            return None
        return dict(row)

    # ------------------------------------------------------------------
    # FINDINGS
    # ------------------------------------------------------------------

    def record_finding(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a security finding for an app. Returns the finding record."""
        app_id = data.get("app_id", "").strip()
        if not app_id:
            raise ValueError("app_id is required")

        # Verify app belongs to org
        app = self.get_app(org_id, app_id)
        if not app:
            raise ValueError(f"App {app_id} not found for org {org_id}")

        finding_type = data.get("finding_type", "").lower()
        if finding_type not in VALID_FINDING_TYPES:
            raise ValueError(f"finding_type must be one of {sorted(VALID_FINDING_TYPES)}, got '{finding_type}'")

        severity = data.get("severity", "").lower()
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}, got '{severity}'")

        title = data.get("title", "").strip()
        if not title:
            raise ValueError("title is required")

        finding_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO mas_findings
                   (id, org_id, app_id, finding_type, severity, title, description,
                    owasp_category, status, cwe_id, discovered_at, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    finding_id, org_id, app_id, finding_type, severity, title,
                    data.get("description"), data.get("owasp_category"),
                    data.get("status", "open"), data.get("cwe_id"),
                    data.get("discovered_at", now), now,
                ),
            )
        _logger.info("mas.finding_recorded org=%s finding_id=%s type=%s", org_id, finding_id, finding_type)
        return self._get_finding(org_id, finding_id)

    def list_findings(
        self,
        org_id: str,
        app_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List findings for org, optionally filtered."""
        query = "SELECT * FROM mas_findings WHERE org_id=?"
        params: List[Any] = [org_id]
        if app_id:
            query += " AND app_id=?"
            params.append(app_id)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def update_finding_status(
        self,
        org_id: str,
        finding_id: str,
        status: str,
    ) -> Dict[str, Any]:
        """Update the status of a finding. Returns updated record."""
        if status not in VALID_FINDING_STATUSES:
            raise ValueError(f"status must be one of {sorted(VALID_FINDING_STATUSES)}, got '{status}'")
        # Verify finding belongs to org
        existing = self._get_finding(org_id, finding_id)
        if not existing:
            raise ValueError(f"Finding {finding_id} not found for org {org_id}")
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE mas_findings SET status=? WHERE org_id=? AND id=?",
                (status, org_id, finding_id),
            )
        _logger.info("mas.finding_status_updated org=%s finding_id=%s status=%s", org_id, finding_id, status)
        return self._get_finding(org_id, finding_id)

    def _get_finding(self, org_id: str, finding_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM mas_findings WHERE org_id=? AND id=?",
                (org_id, finding_id),
            ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # SCANS
    # ------------------------------------------------------------------

    def create_scan(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new scan for an app. Returns the scan record."""
        app_id = data.get("app_id", "").strip()
        if not app_id:
            raise ValueError("app_id is required")

        # Verify app belongs to org
        app = self.get_app(org_id, app_id)
        if not app:
            raise ValueError(f"App {app_id} not found for org {org_id}")

        scan_type = data.get("scan_type", "").lower()
        if scan_type not in VALID_SCAN_TYPES:
            raise ValueError(f"scan_type must be one of {sorted(VALID_SCAN_TYPES)}, got '{scan_type}'")

        scan_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO mas_scans
                   (id, org_id, app_id, scan_type, status,
                    total_findings, critical_findings, scan_score,
                    started_at, completed_at, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    scan_id, org_id, app_id, scan_type,
                    data.get("status", "queued"),
                    0, 0, 0.0,
                    data.get("started_at"), None, now,
                ),
            )
        _logger.info("mas.scan_created org=%s scan_id=%s type=%s", org_id, scan_id, scan_type)
        return self._get_scan(org_id, scan_id)

    def complete_scan(
        self,
        org_id: str,
        scan_id: str,
        total_findings: int,
        critical_findings: int,
        scan_score: float,
    ) -> Dict[str, Any]:
        """Mark a scan as completed and update app.last_scanned."""
        existing = self._get_scan(org_id, scan_id)
        if not existing:
            raise ValueError(f"Scan {scan_id} not found for org {org_id}")
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """UPDATE mas_scans
                   SET status='completed', total_findings=?, critical_findings=?,
                       scan_score=?, completed_at=?
                   WHERE org_id=? AND id=?""",
                (total_findings, critical_findings, scan_score, now, org_id, scan_id),
            )
            # Update app.last_scanned
            conn.execute(
                "UPDATE mas_apps SET last_scanned=? WHERE org_id=? AND id=?",
                (now, org_id, existing["app_id"]),
            )
        _logger.info("mas.scan_completed org=%s scan_id=%s", org_id, scan_id)
        return self._get_scan(org_id, scan_id)

    def list_scans(
        self,
        org_id: str,
        app_id: Optional[str] = None,
        scan_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List scans for org, optionally filtered."""
        query = "SELECT * FROM mas_scans WHERE org_id=?"
        params: List[Any] = [org_id]
        if app_id:
            query += " AND app_id=?"
            params.append(app_id)
        if scan_type:
            query += " AND scan_type=?"
            params.append(scan_type)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def _get_scan(self, org_id: str, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM mas_scans WHERE org_id=? AND id=?",
                (org_id, scan_id),
            ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # STATS
    # ------------------------------------------------------------------

    def get_mobile_stats(self, org_id: str) -> Dict[str, Any]:
        """Return mobile app security overview stats for org_id."""
        with self._connect() as conn:
            total_apps = conn.execute(
                "SELECT COUNT(*) FROM mas_apps WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            active_apps = conn.execute(
                "SELECT COUNT(*) FROM mas_apps WHERE org_id=? AND status='active'", (org_id,)
            ).fetchone()[0]

            avg_row = conn.execute(
                "SELECT AVG(risk_score) FROM mas_apps WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            avg_risk_score = round(avg_row, 2) if avg_row is not None else 0.0

            platform_rows = conn.execute(
                "SELECT platform, COUNT(*) as cnt FROM mas_apps WHERE org_id=? GROUP BY platform",
                (org_id,),
            ).fetchall()
            by_platform = {r["platform"]: r["cnt"] for r in platform_rows}

            total_findings = conn.execute(
                "SELECT COUNT(*) FROM mas_findings WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            open_findings = conn.execute(
                "SELECT COUNT(*) FROM mas_findings WHERE org_id=? AND status='open'", (org_id,)
            ).fetchone()[0]

            critical_findings = conn.execute(
                "SELECT COUNT(*) FROM mas_findings WHERE org_id=? AND severity='critical'", (org_id,)
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT finding_type, COUNT(*) as cnt FROM mas_findings WHERE org_id=? GROUP BY finding_type",
                (org_id,),
            ).fetchall()
            by_finding_type = {r["finding_type"]: r["cnt"] for r in type_rows}

            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM mas_findings WHERE org_id=? GROUP BY severity",
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

        return {
            "total_apps": total_apps,
            "active_apps": active_apps,
            "total_findings": total_findings,
            "open_findings": open_findings,
            "critical_findings": critical_findings,
            "avg_risk_score": avg_risk_score,
            "by_platform": by_platform,
            "by_finding_type": by_finding_type,
            "by_severity": by_severity,
        }
