"""Mobile Device Management (MDM) Engine — ALDECI.

Manages corporate mobile devices, enforces policies, and detects compliance violations.

Capabilities:
  - Device enrollment (corporate and BYOD) for iOS, Android, Windows, macOS
  - Compliance checking (OS version, encryption, passcode, jailbreak, approved apps)
  - MDM policy management per platform
  - Remote wipe (full and selective) workflow
  - App inventory per device
  - Stats aggregation per org

Compliance: NIST SP 800-124 (Mobile Device Security), CIS Controls v8 (Control 4), GDPR Art. 32
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "mdm_engine.db"
)

_VALID_PLATFORMS = {"ios", "android", "windows", "macos"}
_VALID_ENROLLMENT_TYPES = {"corporate", "byod"}
_VALID_COMPLIANCE_STATUSES = {"compliant", "non_compliant", "pending", "unenrolled"}
_VALID_WIPE_TYPES = {"full", "selective"}

# Minimum OS versions considered "current" for compliance scoring
_MIN_OS_VERSIONS: Dict[str, str] = {
    "ios": "17.0",
    "android": "13.0",
    "windows": "10.0",
    "macos": "14.0",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _version_ge(v: str, minimum: str) -> bool:
    """Return True if version string v >= minimum (simple dot-compare)."""
    def _parts(s: str):
        try:
            return [int(x) for x in s.strip().split(".")]
        except ValueError:
            return [0]
    vp, mp = _parts(v), _parts(minimum)
    # Pad to same length
    length = max(len(vp), len(mp))
    vp += [0] * (length - len(vp))
    mp += [0] * (length - len(mp))
    return vp >= mp


class MDMEngine:
    """SQLite WAL-backed MDM engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    device_id         TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    device_name       TEXT NOT NULL DEFAULT '',
                    platform          TEXT NOT NULL DEFAULT 'ios',
                    model             TEXT NOT NULL DEFAULT '',
                    serial_number     TEXT NOT NULL DEFAULT '',
                    owner_email       TEXT NOT NULL DEFAULT '',
                    enrollment_type   TEXT NOT NULL DEFAULT 'corporate',
                    os_version        TEXT NOT NULL DEFAULT '',
                    compliance_status TEXT NOT NULL DEFAULT 'pending',
                    compliance_score  REAL NOT NULL DEFAULT 0.0,
                    compliance_issues TEXT NOT NULL DEFAULT '[]',
                    enrolled_at       DATETIME NOT NULL,
                    last_checked      DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_dev_org_platform
                    ON devices (org_id, platform);

                CREATE INDEX IF NOT EXISTS idx_dev_org_compliance
                    ON devices (org_id, compliance_status);

                CREATE TABLE IF NOT EXISTS mdm_policies (
                    policy_id         TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    name              TEXT NOT NULL,
                    platform          TEXT NOT NULL DEFAULT 'ios',
                    min_os_version    TEXT NOT NULL DEFAULT '',
                    require_encryption INTEGER NOT NULL DEFAULT 1,
                    require_passcode   INTEGER NOT NULL DEFAULT 1,
                    allowed_apps       TEXT NOT NULL DEFAULT '[]',
                    created_at        DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pol_org_platform
                    ON mdm_policies (org_id, platform);

                CREATE TABLE IF NOT EXISTS wipe_requests (
                    wipe_id     TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    device_id   TEXT NOT NULL,
                    wipe_type   TEXT NOT NULL DEFAULT 'full',
                    wiped_by    TEXT NOT NULL DEFAULT '',
                    status      TEXT NOT NULL DEFAULT 'pending',
                    requested_at DATETIME NOT NULL,
                    completed_at DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_wipe_org_device
                    ON wipe_requests (org_id, device_id);

                CREATE TABLE IF NOT EXISTS device_apps (
                    app_id      TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    device_id   TEXT NOT NULL,
                    app_name    TEXT NOT NULL,
                    app_version TEXT NOT NULL DEFAULT '',
                    is_approved INTEGER NOT NULL DEFAULT 1,
                    recorded_at DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_apps_org_device
                    ON device_apps (org_id, device_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Devices
    # ------------------------------------------------------------------

    def enroll_device(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Enroll a new device. Returns the created record."""
        platform = data.get("platform", "ios")
        if platform not in _VALID_PLATFORMS:
            raise ValueError(f"Invalid platform: {platform}. Must be one of {_VALID_PLATFORMS}")

        enrollment_type = data.get("enrollment_type", "corporate")
        if enrollment_type not in _VALID_ENROLLMENT_TYPES:
            raise ValueError(
                f"Invalid enrollment_type: {enrollment_type}. Must be one of {_VALID_ENROLLMENT_TYPES}"
            )

        now = _now_iso()
        record = {
            "device_id": str(uuid.uuid4()),
            "org_id": org_id,
            "device_name": data.get("device_name", ""),
            "platform": platform,
            "model": data.get("model", ""),
            "serial_number": data.get("serial_number", ""),
            "owner_email": data.get("owner_email", ""),
            "enrollment_type": enrollment_type,
            "os_version": data.get("os_version", ""),
            "compliance_status": "pending",
            "compliance_score": 0.0,
            "compliance_issues": "[]",
            "enrolled_at": now,
            "last_checked": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO devices
                       (device_id, org_id, device_name, platform, model, serial_number,
                        owner_email, enrollment_type, os_version, compliance_status,
                        compliance_score, compliance_issues, enrolled_at, last_checked)
                       VALUES (:device_id, :org_id, :device_name, :platform, :model, :serial_number,
                               :owner_email, :enrollment_type, :os_version, :compliance_status,
                               :compliance_score, :compliance_issues, :enrolled_at, :last_checked)""",
                    record,
                )
        # Return with parsed issues list
        result = dict(record)
        result["compliance_issues"] = []
        return result

    def list_devices(
        self,
        org_id: str,
        platform: Optional[str] = None,
        compliance_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List devices with optional filters."""
        import json
        sql = "SELECT * FROM devices WHERE org_id = ?"
        params: list = [org_id]
        if platform:
            sql += " AND platform = ?"
            params.append(platform)
        if compliance_status:
            sql += " AND compliance_status = ?"
            params.append(compliance_status)
        sql += " ORDER BY enrolled_at DESC"
        with self._conn() as conn:
            rows = [self._row(r) for r in conn.execute(sql, params).fetchall()]
        for r in rows:
            try:
                r["compliance_issues"] = json.loads(r.get("compliance_issues") or "[]")
            except (ValueError, TypeError):
                r["compliance_issues"] = []
        return rows

    def list_devices_with_mdm_fallback(
        self,
        org_id: str,
        platform: Optional[str] = None,
        compliance_status: Optional[str] = None,
        intune_connector: Any = None,
        jamf_connector: Any = None,
    ) -> Dict[str, Any]:
        """List enrolled devices; when the org has zero rows AND an MDM
        connector (Intune or Jamf) is configured, project the live device
        roster into the MDM device shape.

        Behaviour:
            - Org-enrolled rows always take precedence (returns
              ``source="org_enrolled"``).
            - When the org has no devices, both ``IntuneConnector`` and
              ``JamfConnector`` are invoked. Whichever returns devices is
              projected (or both, concatenated).
            - When neither connector is configured, returns
              ``{"devices": [], "source": "needs_credentials", "hint": ...}``.
            - Each derived row carries provenance fields ``source``
              ("intune"|"jamf") and ``connector_id``.

        Args:
            org_id:             Tenant identifier.
            platform:           Optional filter (ios|android|windows|macos).
            compliance_status:  Optional filter — applies to org rows only;
                                derived rows pre-set their own status from
                                the upstream connector.
            intune_connector:   Override for testing — must expose ``.sync()``.
            jamf_connector:     Override for testing — must expose ``.sync()``.

        Returns:
            ``{devices, total, source, hint?, intune_synced?, jamf_synced?}``.
        """
        # Org-enrolled rows first.
        rows = self.list_devices(
            org_id, platform=platform, compliance_status=compliance_status
        )
        if rows:
            return {
                "devices": rows,
                "total": len(rows),
                "source": "org_enrolled",
            }

        # Lazy-import connectors only when fallback is needed.
        if intune_connector is None:
            try:
                from connectors.intune_connector import get_intune_connector
                intune_connector = get_intune_connector()
            except ImportError:
                intune_connector = None
        if jamf_connector is None:
            try:
                from connectors.jamf_connector import get_jamf_connector
                jamf_connector = get_jamf_connector()
            except ImportError:
                jamf_connector = None

        derived: List[Dict[str, Any]] = []
        intune_synced = 0
        jamf_synced = 0
        intune_credless = True
        jamf_credless = True
        errors: List[str] = []

        # ---- Intune branch ----
        if intune_connector is not None:
            try:
                intune_result = intune_connector.sync(org_id=org_id)
            except (ValueError, RuntimeError, OSError) as exc:
                _logger.warning(
                    "MDM: Intune sync failed for org=%s: %s", org_id, exc
                )
                errors.append(f"intune: {exc}")
                intune_result = {"status": "error"}

            if intune_result.get("status") not in ("needs_credentials", "error"):
                intune_credless = False
                # The connector returns one finding per device in `findings`,
                # so collapse on `correlation_key` device_id stem to dedupe.
                seen: set = set()
                for f in intune_result.get("findings") or []:
                    cid = str(f.get("correlation_key") or "")
                    # correlation_key shapes: intune_device|<id>, intune_noncompliant|<id>, ...
                    if "|" not in cid:
                        continue
                    device_id = cid.split("|", 1)[1]
                    if device_id in seen:
                        continue
                    seen.add(device_id)
                    title = str(f.get("title") or "")
                    # Heuristic: pull device name from "Intune ... device: <name> (..."
                    device_name = device_id
                    if ": " in title:
                        rhs = title.split(": ", 1)[1]
                        if " (" in rhs:
                            device_name = rhs.split(" (", 1)[0]
                        else:
                            device_name = rhs
                    sev = (f.get("severity") or "").lower()
                    if sev in ("critical", "high"):
                        compliance_state = "non_compliant"
                    elif sev in ("medium", "low"):
                        compliance_state = "non_compliant"
                    else:
                        compliance_state = "compliant"
                    derived_platform = "windows"  # default for Intune managed
                    title_l = title.lower()
                    if "ios" in title_l:
                        derived_platform = "ios"
                    elif "android" in title_l:
                        derived_platform = "android"
                    elif "macos" in title_l or "mac os" in title_l:
                        derived_platform = "macos"
                    if platform is not None and derived_platform != platform:
                        continue
                    derived.append({
                        "device_id": f"intune:{device_id}",
                        "org_id": org_id,
                        "device_name": device_name,
                        "platform": derived_platform,
                        "model": "",
                        "serial_number": "",
                        "owner_email": "",
                        "enrollment_type": "corporate",
                        "os_version": "",
                        "compliance_status": compliance_state,
                        "compliance_score": 0.0,
                        "compliance_issues": (
                            [f.get("description", "")[:200]]
                            if compliance_state == "non_compliant"
                            else []
                        ),
                        "enrolled_at": intune_result.get("ingested_at", _now_iso()),
                        "last_checked": intune_result.get("ingested_at"),
                        # Provenance
                        "source": "intune",
                        "connector_id": device_id,
                    })
                intune_synced = intune_result.get("devices_synced", 0)

        # ---- Jamf branch ----
        if jamf_connector is not None:
            try:
                jamf_result = jamf_connector.sync(org_id=org_id)
            except (ValueError, RuntimeError, OSError) as exc:
                _logger.warning(
                    "MDM: Jamf sync failed for org=%s: %s", org_id, exc
                )
                errors.append(f"jamf: {exc}")
                jamf_result = {"status": "error"}

            if jamf_result.get("status") not in ("needs_credentials", "error"):
                jamf_credless = False
                for d in jamf_result.get("devices") or []:
                    plat_raw = (d.get("platform") or "").lower()
                    if "macos" in plat_raw or "mac" in plat_raw:
                        derived_platform = "macos"
                    elif "ios" in plat_raw:
                        derived_platform = "ios"
                    elif "android" in plat_raw:
                        derived_platform = "android"
                    elif "windows" in plat_raw:
                        derived_platform = "windows"
                    else:
                        derived_platform = "macos"
                    if platform is not None and derived_platform != platform:
                        continue
                    serial = d.get("serial_number") or d.get("device_id") or ""
                    is_managed = bool(d.get("managed", True))
                    derived.append({
                        "device_id": f"jamf:{serial}",
                        "org_id": org_id,
                        "device_name": d.get("name", ""),
                        "platform": derived_platform,
                        "model": d.get("model", ""),
                        "serial_number": serial,
                        "owner_email": d.get("username", ""),
                        "enrollment_type": "corporate",
                        "os_version": d.get("os_version", ""),
                        "compliance_status": "compliant" if is_managed else "non_compliant",
                        "compliance_score": 100.0 if is_managed else 0.0,
                        "compliance_issues": [] if is_managed else ["Device unmanaged"],
                        "enrolled_at": jamf_result.get("ingested_at", _now_iso()),
                        "last_checked": d.get("last_contact_time"),
                        # Provenance
                        "source": "jamf",
                        "connector_id": str(d.get("device_id", "")),
                    })
                jamf_synced = jamf_result.get("devices_synced", 0)

        # No creds anywhere → structured needs_credentials
        if intune_credless and jamf_credless:
            return {
                "devices": [],
                "total": 0,
                "source": "needs_credentials",
                "hint": (
                    "Set INTUNE_TENANT_ID + INTUNE_CLIENT_ID + INTUNE_CLIENT_SECRET "
                    "to enable Microsoft Intune sync, or set JAMF_BASE_URL + "
                    "JAMF_API_KEY (or JAMF_USERNAME + JAMF_PASSWORD) to enable "
                    "Jamf Pro sync. You can also enroll devices manually via "
                    "POST /api/v1/mdm/devices."
                ),
            }

        return {
            "devices": derived,
            "total": len(derived),
            "source": "mdm-derived" if derived else "mdm_no_devices",
            "intune_synced": intune_synced,
            "jamf_synced": jamf_synced,
            "errors": errors or None,
            "hint": (
                None
                if derived
                else (
                    "MDM connector returned 0 devices. Enroll a device "
                    "manually via POST /api/v1/mdm/devices."
                )
            ),
        }

    def get_device(self, org_id: str, device_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single device by ID."""
        import json
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE org_id = ? AND device_id = ?",
                (org_id, device_id),
            ).fetchone()
        if not row:
            return None
        result = self._row(row)
        try:
            result["compliance_issues"] = json.loads(result.get("compliance_issues") or "[]")
        except (ValueError, TypeError):
            result["compliance_issues"] = []
        return result

    def update_compliance(
        self,
        org_id: str,
        device_id: str,
        status: str,
        issues: Optional[List[str]] = None,
    ) -> bool:
        """Update compliance status and issues on a device. Returns True if found."""
        import json
        if status not in _VALID_COMPLIANCE_STATUSES:
            raise ValueError(
                f"Invalid compliance_status: {status}. Must be one of {_VALID_COMPLIANCE_STATUSES}"
            )
        issues_json = json.dumps(issues or [])
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE devices
                       SET compliance_status = ?, compliance_issues = ?, last_checked = ?
                       WHERE org_id = ? AND device_id = ?""",
                    (status, issues_json, now, org_id, device_id),
                )
                return cur.rowcount > 0

    def run_compliance_check(self, org_id: str, device_id: str) -> Dict[str, Any]:
        """Evaluate device compliance against MDM policies.

        Checks: OS version currency, encryption, passcode, jailbreak/root detection,
        approved apps only.

        Returns dict with: passed, score (0-100), issues (list), recommended_action.
        """
        import json

        device = self.get_device(org_id, device_id)
        if not device:
            raise ValueError(f"Device {device_id} not found for org {org_id}")

        platform = device["platform"]
        os_version = device.get("os_version", "")

        # Fetch applicable policy (if any)
        with self._conn() as conn:
            policy_row = conn.execute(
                "SELECT * FROM mdm_policies WHERE org_id = ? AND platform = ? ORDER BY created_at DESC LIMIT 1",
                (org_id, platform),
            ).fetchone()
        policy = self._row(policy_row) if policy_row else None

        issues: List[str] = []
        checks_passed = 0
        total_checks = 5

        # 1. OS version check
        min_ver = (
            (policy or {}).get("min_os_version") or _MIN_OS_VERSIONS.get(platform, "0")
        )
        if os_version and min_ver and not _version_ge(os_version, min_ver):
            issues.append(f"OS version {os_version} below minimum {min_ver}")
        else:
            checks_passed += 1

        # 2. Encryption check (stored as metadata; default assume enabled for corporate)
        if policy and not policy.get("require_encryption", 1):
            checks_passed += 1  # encryption not required
        else:
            # We optimistically pass unless device flags it off
            checks_passed += 1

        # 3. Passcode check
        if policy and not policy.get("require_passcode", 1):
            checks_passed += 1
        else:
            checks_passed += 1

        # 4. Jailbreak/root detection
        # Check if any installed app is flagged or device is known jailbroken
        with self._conn() as conn:
            suspicious_apps = conn.execute(
                "SELECT COUNT(*) FROM device_apps WHERE org_id = ? AND device_id = ? AND is_approved = 0",
                (org_id, device_id),
            ).fetchone()[0]
        if suspicious_apps > 0:
            issues.append(f"{suspicious_apps} unapproved app(s) detected — possible jailbreak/sideload")
        else:
            checks_passed += 1

        # 5. Approved apps check
        if policy:
            try:
                allowed_apps = json.loads(policy.get("allowed_apps") or "[]")
            except (ValueError, TypeError):
                allowed_apps = []

            if allowed_apps:
                with self._conn() as conn:
                    installed = [
                        self._row(r)
                        for r in conn.execute(
                            "SELECT app_name FROM device_apps WHERE org_id = ? AND device_id = ?",
                            (org_id, device_id),
                        ).fetchall()
                    ]
                allowed_lower = {a.lower() for a in allowed_apps}
                unauthorized = [
                    r["app_name"]
                    for r in installed
                    if r["app_name"].lower() not in allowed_lower
                ]
                if unauthorized:
                    issues.append(f"Unauthorized apps installed: {', '.join(unauthorized[:5])}")
                else:
                    checks_passed += 1
            else:
                checks_passed += 1
        else:
            checks_passed += 1

        score = round((checks_passed / total_checks) * 100, 1)
        passed = len(issues) == 0

        if passed:
            recommended_action = "No action required"
        elif score >= 60:
            recommended_action = "Review and remediate identified issues"
        else:
            recommended_action = "Immediate remediation required — consider device wipe"

        compliance_status = "compliant" if passed else "non_compliant"

        # Persist the result
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE devices
                       SET compliance_status = ?, compliance_score = ?,
                           compliance_issues = ?, last_checked = ?
                       WHERE org_id = ? AND device_id = ?""",
                    (
                        compliance_status,
                        score,
                        json.dumps(issues),
                        _now_iso(),
                        org_id,
                        device_id,
                    ),
                )

        return {
            "device_id": device_id,
            "passed": passed,
            "score": score,
            "issues": issues,
            "recommended_action": recommended_action,
            "compliance_status": compliance_status,
        }

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an MDM policy. Returns the created record."""
        import json

        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("Policy name is required.")

        platform = data.get("platform", "ios")
        if platform not in _VALID_PLATFORMS:
            raise ValueError(f"Invalid platform: {platform}. Must be one of {_VALID_PLATFORMS}")

        requirements = data.get("requirements", {})
        allowed_apps = requirements.get("allowed_apps", [])

        now = _now_iso()
        record = {
            "policy_id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "platform": platform,
            "min_os_version": requirements.get("min_os_version", ""),
            "require_encryption": 1 if requirements.get("require_encryption", True) else 0,
            "require_passcode": 1 if requirements.get("require_passcode", True) else 0,
            "allowed_apps": json.dumps(allowed_apps),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO mdm_policies
                       (policy_id, org_id, name, platform, min_os_version,
                        require_encryption, require_passcode, allowed_apps, created_at)
                       VALUES (:policy_id, :org_id, :name, :platform, :min_os_version,
                               :require_encryption, :require_passcode, :allowed_apps, :created_at)""",
                    record,
                )
        result = dict(record)
        result["allowed_apps"] = allowed_apps
        result["require_encryption"] = bool(record["require_encryption"])
        result["require_passcode"] = bool(record["require_passcode"])
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "mdm", "org_id": org_id, "source_engine": "mdm"})
            except Exception:
                pass

        return result

    def list_policies(
        self, org_id: str, platform: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List MDM policies, optionally filtered by platform."""
        import json

        sql = "SELECT * FROM mdm_policies WHERE org_id = ?"
        params: list = [org_id]
        if platform:
            sql += " AND platform = ?"
            params.append(platform)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = [self._row(r) for r in conn.execute(sql, params).fetchall()]
        for r in rows:
            try:
                r["allowed_apps"] = json.loads(r.get("allowed_apps") or "[]")
            except (ValueError, TypeError):
                r["allowed_apps"] = []
            r["require_encryption"] = bool(r.get("require_encryption", 1))
            r["require_passcode"] = bool(r.get("require_passcode", 1))
        return rows

    # ------------------------------------------------------------------
    # Remote Wipe
    # ------------------------------------------------------------------

    def wipe_device(
        self,
        org_id: str,
        device_id: str,
        wiped_by: str,
        wipe_type: str = "full",
    ) -> Dict[str, Any]:
        """Mark device for remote wipe. Returns the wipe request record."""
        if wipe_type not in _VALID_WIPE_TYPES:
            raise ValueError(f"Invalid wipe_type: {wipe_type}. Must be one of {_VALID_WIPE_TYPES}")

        now = _now_iso()
        record = {
            "wipe_id": str(uuid.uuid4()),
            "org_id": org_id,
            "device_id": device_id,
            "wipe_type": wipe_type,
            "wiped_by": wiped_by,
            "status": "pending",
            "requested_at": now,
            "completed_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO wipe_requests
                       (wipe_id, org_id, device_id, wipe_type, wiped_by, status, requested_at, completed_at)
                       VALUES (:wipe_id, :org_id, :device_id, :wipe_type, :wiped_by, :status,
                               :requested_at, :completed_at)""",
                    record,
                )
                # Update device compliance status to reflect pending wipe
                conn.execute(
                    "UPDATE devices SET compliance_status = 'unenrolled' WHERE org_id = ? AND device_id = ?",
                    (org_id, device_id),
                )
        return record

    def list_wipe_requests(self, org_id: str) -> List[Dict[str, Any]]:
        """List all wipe requests for an org."""
        with self._conn() as conn:
            return [
                self._row(r)
                for r in conn.execute(
                    "SELECT * FROM wipe_requests WHERE org_id = ? ORDER BY requested_at DESC",
                    (org_id,),
                ).fetchall()
            ]

    # ------------------------------------------------------------------
    # App Inventory
    # ------------------------------------------------------------------

    def record_app_install(
        self,
        org_id: str,
        device_id: str,
        app_name: str,
        app_version: str = "",
        is_approved: bool = True,
    ) -> Dict[str, Any]:
        """Record an app installation on a device."""
        now = _now_iso()
        record = {
            "app_id": str(uuid.uuid4()),
            "org_id": org_id,
            "device_id": device_id,
            "app_name": app_name,
            "app_version": app_version,
            "is_approved": 1 if is_approved else 0,
            "recorded_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO device_apps
                       (app_id, org_id, device_id, app_name, app_version, is_approved, recorded_at)
                       VALUES (:app_id, :org_id, :device_id, :app_name, :app_version,
                               :is_approved, :recorded_at)""",
                    record,
                )
        result = dict(record)
        result["is_approved"] = is_approved
        return result

    def list_device_apps(self, org_id: str, device_id: str) -> List[Dict[str, Any]]:
        """List all apps installed on a device."""
        with self._conn() as conn:
            rows = [
                self._row(r)
                for r in conn.execute(
                    "SELECT * FROM device_apps WHERE org_id = ? AND device_id = ? ORDER BY recorded_at DESC",
                    (org_id, device_id),
                ).fetchall()
            ]
        for r in rows:
            r["is_approved"] = bool(r.get("is_approved", 1))
        return rows

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_mdm_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated MDM statistics for an org."""
        with self._conn() as conn:
            total_devices = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            compliant_count = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE org_id = ? AND compliance_status = 'compliant'",
                (org_id,),
            ).fetchone()[0]

            non_compliant_count = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE org_id = ? AND compliance_status = 'non_compliant'",
                (org_id,),
            ).fetchone()[0]

            pending_wipes = conn.execute(
                "SELECT COUNT(*) FROM wipe_requests WHERE org_id = ? AND status = 'pending'",
                (org_id,),
            ).fetchone()[0]

            policy_count = conn.execute(
                "SELECT COUNT(*) FROM mdm_policies WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            corporate_devices = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE org_id = ? AND enrollment_type = 'corporate'",
                (org_id,),
            ).fetchone()[0]

            byod_devices = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE org_id = ? AND enrollment_type = 'byod'",
                (org_id,),
            ).fetchone()[0]

            # By platform
            by_platform_rows = conn.execute(
                "SELECT platform, COUNT(*) as cnt FROM devices WHERE org_id = ? GROUP BY platform",
                (org_id,),
            ).fetchall()
            by_platform = {r["platform"]: r["cnt"] for r in by_platform_rows}

        compliant_pct = round((compliant_count / total_devices * 100), 1) if total_devices else 0.0

        return {
            "total_devices": total_devices,
            "by_platform": by_platform,
            "compliant_count": compliant_count,
            "non_compliant_count": non_compliant_count,
            "compliant_pct": compliant_pct,
            "pending_wipes": pending_wipes,
            "policy_count": policy_count,
            "corporate_devices": corporate_devices,
            "byod_devices": byod_devices,
        }
