"""Data Loss Prevention engine — detect PII, PCI, and sensitive data patterns."""
import json
import re
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Optional

import structlog

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = structlog.get_logger()

# Detection patterns
DLP_PATTERNS = {
    "credit_card": {
        "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "severity": "critical", "category": "pci"
    },
    "ssn": {
        "pattern": r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
        "severity": "critical", "category": "pii"
    },
    "email_address": {
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "severity": "medium", "category": "pii"
    },
    "phone_number": {
        "pattern": r"\b(?:\+?1[-.]?)?\(?(?:[0-9]{3})\)?[-.]?(?:[0-9]{3})[-.]?(?:[0-9]{4})\b",
        "severity": "medium", "category": "pii"
    },
    "aws_access_key": {
        "pattern": r"\b(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b",
        "severity": "critical", "category": "credentials"
    },
    "private_key": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "severity": "critical", "category": "credentials"
    },
    "ip_address": {
        "pattern": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        "severity": "low", "category": "network"
    },
    "passport_number": {
        "pattern": r"\b[A-Z]{1,2}[0-9]{6,9}\b",
        "severity": "high", "category": "pii"
    },
}

# Pre-compiled built-in patterns (compiled once at import time).
# Each value keeps the original metadata plus a 'compiled' key.
_DLP_COMPILED: dict = {
    name: {**meta, "compiled": re.compile(meta["pattern"])}
    for name, meta in DLP_PATTERNS.items()
}

# Per-org cache: org_id -> dict[name, {compiled, severity, category}]
# Invalidated whenever a custom pattern is added/deleted for that org.
_ORG_PATTERN_CACHE: dict = {}


def _invalidate_org_cache(org_id: str) -> None:
    _ORG_PATTERN_CACHE.pop(org_id, None)


# Pre-compiled regexes for _mask_pii (avoids re-compilation on every call)
_MASK_CC_RE = re.compile(r'\b(\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?)(\d{4})\b')
_MASK_SSN_RE = re.compile(r'\b(\d{3})[\-\s]?(\d{2})[\-\s]?(\d{4})\b')
_MASK_EMAIL_RE = re.compile(
    r'\b([a-zA-Z0-9])[a-zA-Z0-9._%+\-]*@([a-zA-Z0-9])[a-zA-Z0-9.\-]*(\.[a-zA-Z]{2,})\b'
)
_MASK_PHONE_RE = re.compile(
    r'\b(\+?1?\s?)?(\(?\d{3}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{4})\b'
)
_MASK_IBAN_RE = re.compile(r'\b([A-Z]{2}\d{2})\s?[\dA-Z\s]{10,26}([\dA-Z]{4})\b')
_MASK_PASSPORT_RE = re.compile(r'\b([A-Z]{1,2})\d{6,8}\b')
_MASK_MEDICAL_RE = re.compile(r'\b\d{3,12}\b')
_MASK_IP_RE = re.compile(r'\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b')

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _redact_sample(match: str) -> str:
    """Return a redacted sample: first 3 chars + *** + last 2 chars."""
    if len(match) <= 5:
        return "*" * len(match)
    return match[:3] + "***" + match[-2:]


def _compute_risk_level(findings: list) -> str:
    """Compute overall risk level from list of finding dicts."""
    if not findings:
        return "low"
    highest = max(_SEVERITY_ORDER.get(f["severity"], 0) for f in findings)
    return {0: "low", 1: "medium", 2: "high", 3: "critical"}[highest]


class _NoCloseConn:
    """Thin proxy that swallows close() calls so callers' finally-blocks
    don't destroy the persistent engine connection."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def close(self) -> None:  # intentional no-op
        pass

    def __getattr__(self, name: str):
        return getattr(self._conn, name)

    # Explicit pass-throughs for the context-manager protocol so
    # ``with self._get_connection() as conn:`` also works.
    def __enter__(self):
        return self._conn.__enter__()

    def __exit__(self, *args):
        return self._conn.__exit__(*args)


class DLPEngine:
    def __init__(self, db_path: str = "data/dlp.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # Persistent connection — opened once, reused for the engine lifetime.
        # WAL mode allows concurrent readers; check_same_thread=False is safe
        # because each engine instance is used from a single async worker.
        _raw = sqlite3.connect(str(self.db_path), check_same_thread=False)
        _raw.execute("PRAGMA journal_mode=WAL")
        _raw.row_factory = sqlite3.Row
        self._persistent_conn = _NoCloseConn(_raw)
        self._init_tables()

    def _get_connection(self) -> "_NoCloseConn":
        """Return the persistent connection (close() is a no-op on the proxy)."""
        return self._persistent_conn

    def _init_tables(self):
        conn = self._get_connection()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    scan_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    context TEXT,
                    total_findings INTEGER NOT NULL,
                    findings_json TEXT NOT NULL,
                    categories_found TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS custom_patterns (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    created_at REAL NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_scan_results_org_id ON scan_results(org_id);
                CREATE INDEX IF NOT EXISTS idx_scan_results_risk_level ON scan_results(risk_level);
                CREATE INDEX IF NOT EXISTS idx_custom_patterns_org_id ON custom_patterns(org_id);
            """)
            conn.commit()
        finally:
            conn.close()

    def _get_patterns_for_org(self, org_id: str) -> dict:
        """Return merged built-in + org-specific compiled patterns (cached per org).

        Returns dict[name -> {compiled, severity, category}].
        """
        if org_id in _ORG_PATTERN_CACHE:
            return _ORG_PATTERN_CACHE[org_id]

        # Start from pre-compiled built-ins
        patterns: dict = dict(_DLP_COMPILED)

        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT name, pattern, severity, category FROM custom_patterns WHERE org_id = ?",
                (org_id,)
            ).fetchall()
            for row in rows:
                try:
                    patterns[row["name"]] = {
                        "compiled": re.compile(row["pattern"]),
                        "severity": row["severity"],
                        "category": row["category"],
                    }
                except re.error:
                    pass  # bad custom pattern — skip silently
        finally:
            conn.close()

        _ORG_PATTERN_CACHE[org_id] = patterns
        return patterns

    def scan_text(self, text: str, context: str = "", org_id: str = "default") -> dict:
        """Scan text for sensitive data patterns.

        Returns:
            {scan_id, total_findings, findings, categories_found, risk_level}

        NOTE: Never stores actual matched values — only counts and redacted samples.
        """
        patterns = self._get_patterns_for_org(org_id)
        findings = []

        for pattern_name, meta in patterns.items():
            try:
                matches = meta["compiled"].findall(text)
            except re.error as exc:
                _logger.warning("dlp.bad_pattern", pattern=pattern_name, error=str(exc))
                continue

            # Flatten tuple matches (e.g. groups from alternation)
            flat_matches = []
            for m in matches:
                if isinstance(m, tuple):
                    flat_matches.append("".join(m))
                else:
                    flat_matches.append(m)

            if not flat_matches:
                continue

            findings.append({
                "pattern_name": pattern_name,
                "severity": meta["severity"],
                "category": meta["category"],
                "match_count": len(flat_matches),
                "redacted_sample": _redact_sample(flat_matches[0]),
            })

        categories_found = sorted({f["category"] for f in findings})
        risk_level = _compute_risk_level(findings)
        scan_id = str(uuid.uuid4())
        now = time.time()

        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO scan_results
                   (scan_id, org_id, context, total_findings, findings_json,
                    categories_found, risk_level, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id, org_id, context, len(findings),
                    json.dumps(findings), json.dumps(categories_found),
                    risk_level, now,
                )
            )
            conn.commit()
        finally:
            conn.close()

        _logger.info("dlp.scan_complete", scan_id=scan_id, findings=len(findings),
                     risk_level=risk_level, org_id=org_id)
        return {
            "scan_id": scan_id,
            "total_findings": len(findings),
            "findings": findings,
            "categories_found": categories_found,
            "risk_level": risk_level,
        }

    def scan_file(self, file_path: str, org_id: str = "default") -> dict:
        """Read a file and scan its contents. Returns same shape as scan_text."""
        path = Path(file_path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            _logger.error("dlp.file_read_error", path=file_path, error=str(exc))
            raise ValueError(f"Cannot read file: {file_path}") from exc

        return self.scan_text(text, context=f"file:{file_path}", org_id=org_id)

    def redact_text(self, text: str, org_id: str = "default") -> str:
        """Replace all detected sensitive data with [REDACTED-TYPE] placeholders."""
        patterns = self._get_patterns_for_org(org_id)
        result = text
        for pattern_name, meta in patterns.items():
            try:
                result = re.sub(
                    meta["pattern"],
                    f"[REDACTED-{pattern_name.upper()}]",
                    result,
                )
            except re.error as exc:
                _logger.warning("dlp.bad_pattern_redact", pattern=pattern_name, error=str(exc))
        return result

    def get_scan_result(self, scan_id: str) -> Optional[dict]:
        """Retrieve a stored scan result by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM scan_results WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        finally:
            conn.close()

        if row is None:
            return None
        return {
            "scan_id": row["scan_id"],
            "org_id": row["org_id"],
            "context": row["context"],
            "total_findings": row["total_findings"],
            "findings": json.loads(row["findings_json"]),
            "categories_found": json.loads(row["categories_found"]),
            "risk_level": row["risk_level"],
            "created_at": row["created_at"],
        }

    def list_scan_results(self, org_id: str = "default", risk_level: str = None,
                          limit: int = 50) -> list:
        """List scan results for an org, optionally filtered by risk_level."""
        conn = self._get_connection()
        try:
            if risk_level:
                rows = conn.execute(
                    """SELECT * FROM scan_results
                       WHERE org_id = ? AND risk_level = ?
                       ORDER BY created_at DESC LIMIT ?""",
                    (org_id, risk_level, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM scan_results
                       WHERE org_id = ?
                       ORDER BY created_at DESC LIMIT ?""",
                    (org_id, limit)
                ).fetchall()
        finally:
            conn.close()

        return [
            {
                "scan_id": r["scan_id"],
                "org_id": r["org_id"],
                "context": r["context"],
                "total_findings": r["total_findings"],
                "categories_found": json.loads(r["categories_found"]),
                "risk_level": r["risk_level"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    def get_stats(self, org_id: str = "default") -> dict:
        """Return {total_scans, total_findings, by_category, by_severity, critical_scans}."""
        conn = self._get_connection()
        try:
            total_scans = conn.execute(
                "SELECT COUNT(*) FROM scan_results WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            total_findings = conn.execute(
                "SELECT COALESCE(SUM(total_findings), 0) FROM scan_results WHERE org_id = ?",
                (org_id,)
            ).fetchone()[0]

            critical_scans = conn.execute(
                "SELECT COUNT(*) FROM scan_results WHERE org_id = ? AND risk_level = 'critical'",
                (org_id,)
            ).fetchone()[0]

            rows = conn.execute(
                "SELECT findings_json FROM scan_results WHERE org_id = ?", (org_id,)
            ).fetchall()
        finally:
            conn.close()

        by_category: dict = {}
        by_severity: dict = {}
        for row in rows:
            findings = json.loads(row["findings_json"])
            for f in findings:
                cat = f.get("category", "unknown")
                sev = f.get("severity", "unknown")
                count = f.get("match_count", 1)
                by_category[cat] = by_category.get(cat, 0) + count
                by_severity[sev] = by_severity.get(sev, 0) + count

        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "by_category": by_category,
            "by_severity": by_severity,
            "critical_scans": critical_scans,
        }

    def add_custom_pattern(self, name: str, pattern: str, severity: str,
                           category: str, org_id: str = "default") -> dict:
        """Add a custom detection pattern for an org."""
        # Validate regex compiles
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"Invalid regex pattern: {exc}") from exc

        record_id = str(uuid.uuid4())
        now = time.time()

        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO custom_patterns
                   (id, name, pattern, severity, category, org_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (record_id, name, pattern, severity, category, org_id, now)
            )
            conn.commit()
        finally:
            conn.close()

        _invalidate_org_cache(org_id)
        _logger.info("dlp.custom_pattern_added", name=name, org_id=org_id)
        return {
            "id": record_id,
            "name": name,
            "pattern": pattern,
            "severity": severity,
            "category": category,
            "org_id": org_id,
            "created_at": now,
        }

    # =========================================================================
    # Policy-based DLP — multi-tenant incident lifecycle
    # =========================================================================
    #
    # These methods extend DLPEngine with a full policy/incident/exception model
    # (distinct from the pattern-scan API above) backed by additional tables in
    # the same SQLite database so the two surfaces can coexist.
    # =========================================================================

    _VALID_DATA_TYPES = {
        "credit_card", "ssn", "email", "phone", "iban", "passport",
        "medical", "ip_address", "custom",
    }
    _VALID_CHANNELS = {
        "email", "web", "usb", "cloud_upload", "print", "clipboard",
    }
    _VALID_ACTIONS = {"block", "quarantine", "alert", "allow"}
    _VALID_SEVERITIES_POL = {"critical", "high", "medium", "low"}
    _VALID_INCIDENT_STATUSES = {
        "new", "investigating", "confirmed", "false_positive", "resolved",
    }

    def _ensure_policy_tables(self) -> None:
        """Create policy/incident/exception tables if they don't yet exist."""
        conn = self._get_connection()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS dlp_policies (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    policy_name     TEXT NOT NULL,
                    data_types      TEXT NOT NULL DEFAULT '[]',
                    channels        TEXT NOT NULL DEFAULT '[]',
                    action          TEXT NOT NULL DEFAULT 'alert',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    hit_count       INTEGER NOT NULL DEFAULT 0,
                    created_at      TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_dlp_policies_org
                    ON dlp_policies (org_id, enabled);

                CREATE TABLE IF NOT EXISTS dlp_incidents (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    policy_id           TEXT NOT NULL DEFAULT '',
                    channel             TEXT NOT NULL DEFAULT '',
                    user_id             TEXT NOT NULL DEFAULT '',
                    user_email          TEXT NOT NULL DEFAULT '',
                    endpoint_hostname   TEXT NOT NULL DEFAULT '',
                    data_type           TEXT NOT NULL DEFAULT '',
                    detected_pattern    TEXT NOT NULL DEFAULT '',
                    content_preview     TEXT NOT NULL DEFAULT '',
                    severity            TEXT NOT NULL DEFAULT 'medium',
                    action_taken        TEXT NOT NULL DEFAULT 'alerted',
                    file_name           TEXT NOT NULL DEFAULT '',
                    destination         TEXT NOT NULL DEFAULT '',
                    status              TEXT NOT NULL DEFAULT 'new',
                    created_at          TEXT NOT NULL,
                    resolved_at         TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_dlp_incidents_org_status
                    ON dlp_incidents (org_id, status, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_dlp_incidents_org_severity
                    ON dlp_incidents (org_id, severity);

                CREATE TABLE IF NOT EXISTS dlp_exceptions (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    user_id     TEXT NOT NULL DEFAULT '',
                    policy_id   TEXT NOT NULL DEFAULT '',
                    reason      TEXT NOT NULL DEFAULT '',
                    approved_by TEXT NOT NULL DEFAULT '',
                    expires_at  TEXT,
                    created_at  TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_dlp_exceptions_org
                    ON dlp_exceptions (org_id);

                CREATE TABLE IF NOT EXISTS dlp_stats_daily (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    date                TEXT NOT NULL,
                    total_scans         INTEGER NOT NULL DEFAULT 0,
                    incidents           INTEGER NOT NULL DEFAULT 0,
                    blocked             INTEGER NOT NULL DEFAULT 0,
                    quarantined         INTEGER NOT NULL DEFAULT 0,
                    allowed_with_alert  INTEGER NOT NULL DEFAULT 0,
                    by_channel          TEXT NOT NULL DEFAULT '{}',
                    by_data_type        TEXT NOT NULL DEFAULT '{}',
                    created_at          TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_dlp_stats_org_date
                    ON dlp_stats_daily (org_id, date);
            """)
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _now_iso() -> str:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _mask_pii(content: str, data_type: str) -> str:
        """Mask PII in content based on data_type (uses pre-compiled regexes)."""
        if not content:
            return content
        if data_type == "credit_card":
            masked = _MASK_CC_RE.sub(r'****-****-****-\2', content)
            return masked if masked != content else "****-****-****-1234"
        if data_type == "ssn":
            masked = _MASK_SSN_RE.sub(lambda m: f"***-**-{m.group(3)}", content)
            return masked if masked != content else "***-**-6789"
        if data_type == "email":
            masked = _MASK_EMAIL_RE.sub(
                lambda m: f"{m.group(1)}***@***.{m.group(3).lstrip('.')}",
                content,
            )
            return masked if masked != content else "j***@***.com"
        if data_type == "phone":
            masked = _MASK_PHONE_RE.sub(r'***-***-****', content)
            return masked if masked != content else "***-***-****"
        if data_type == "iban":
            masked = _MASK_IBAN_RE.sub(
                lambda m: f"{m.group(1)}****...{m.group(2)}", content
            )
            return masked if masked != content else "GB******...****"
        if data_type == "passport":
            masked = _MASK_PASSPORT_RE.sub(r'\1*******', content)
            return masked if masked != content else "P*******"
        if data_type == "medical":
            masked = _MASK_MEDICAL_RE.sub('****', content)
            return masked if masked != content else "[MEDICAL-REDACTED]"
        if data_type == "ip_address":
            masked = _MASK_IP_RE.sub(r'\1.\2.*.*', content)
            return masked if masked != content else "*.*.*.*"
        return content[:3] + "***" + content[-3:] if len(content) > 6 else "***"

    def _get_policy_conn(self) -> sqlite3.Connection:
        """Return a connection, ensuring policy tables exist."""
        self._ensure_policy_tables()
        return self._get_connection()

    def _policy_row(self, row) -> dict:
        d = dict(row)
        for field in ("data_types", "channels"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        if "enabled" in d:
            d["enabled"] = bool(d["enabled"])
        return d

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: dict) -> dict:
        """Create a DLP policy. Returns the created record."""
        policy_name = (data.get("policy_name") or "").strip()
        if not policy_name:
            raise ValueError("policy_name is required.")
        data_types = data.get("data_types", [])
        if isinstance(data_types, str):
            data_types = json.loads(data_types)
        channels = data.get("channels", [])
        if isinstance(channels, str):
            channels = json.loads(channels)
        action = data.get("action", "alert")
        if action not in self._VALID_ACTIONS:
            raise ValueError(f"Invalid action: {action}")
        severity = data.get("severity", "medium")
        if severity not in self._VALID_SEVERITIES_POL:
            raise ValueError(f"Invalid severity: {severity}")
        now = self._now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "policy_name": policy_name,
            "data_types": data_types,
            "channels": channels,
            "action": action,
            "severity": severity,
            "enabled": bool(data.get("enabled", True)),
            "hit_count": 0,
            "created_at": now,
        }
        conn = self._get_policy_conn()
        try:
            conn.execute(
                """INSERT INTO dlp_policies
                   (id, org_id, policy_name, data_types, channels, action,
                    severity, enabled, hit_count, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (record["id"], org_id, policy_name,
                 json.dumps(data_types), json.dumps(channels),
                 action, severity, 1 if record["enabled"] else 0,
                 0, now),
            )
            conn.commit()
        finally:
            conn.close()
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "dlp", "org_id": org_id, "source_engine": "dlp"})
            except Exception:
                pass

        return record

    def list_policies(self, org_id: str, enabled=None) -> list:
        """List policies, optionally filtered by enabled state."""
        sql = "SELECT * FROM dlp_policies WHERE org_id = ?"
        params: list = [org_id]
        if enabled is not None:
            sql += " AND enabled = ?"
            params.append(1 if enabled else 0)
        sql += " ORDER BY created_at DESC"
        conn = self._get_policy_conn()
        try:
            rows = conn.execute(sql, params).fetchall()
        finally:
            conn.close()
        return [self._policy_row(r) for r in rows]

    def get_policy(self, org_id: str, policy_id: str):
        """Return a single policy or None."""
        conn = self._get_policy_conn()
        try:
            row = conn.execute(
                "SELECT * FROM dlp_policies WHERE org_id = ? AND id = ?",
                (org_id, policy_id),
            ).fetchone()
        finally:
            conn.close()
        return self._policy_row(row) if row else None

    # ------------------------------------------------------------------
    # Incident Detection
    # ------------------------------------------------------------------

    def detect_incident(self, org_id: str, data: dict):
        """Check data against enabled policies; create incident if matched.

        Returns the incident dict if a policy fired, else None.
        """
        data_type = data.get("data_type", "")
        channel = data.get("channel", "")
        content = data.get("content", "")

        policies = self.list_policies(org_id, enabled=True)
        matched_policy = None
        for policy in policies:
            policy_data_types = policy.get("data_types", [])
            policy_channels = policy.get("channels", [])
            if data_type in policy_data_types and (not policy_channels or channel in policy_channels):
                matched_policy = policy
                break

        if not matched_policy:
            return None

        action_map = {"block": "blocked", "quarantine": "quarantined",
                      "allow": "allowed", "alert": "alerted"}
        action_taken = action_map.get(matched_policy["action"], "alerted")
        detected_pattern = self._mask_pii(content[:50] if content else "", data_type)
        content_preview = self._mask_pii(content[:100] if content else "", data_type)

        now = self._now_iso()
        incident = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "policy_id": matched_policy["id"],
            "channel": channel,
            "user_id": data.get("user_id", ""),
            "user_email": data.get("user_email", ""),
            "endpoint_hostname": data.get("endpoint_hostname", ""),
            "data_type": data_type,
            "detected_pattern": detected_pattern,
            "content_preview": content_preview,
            "severity": matched_policy["severity"],
            "action_taken": action_taken,
            "file_name": data.get("file_name", ""),
            "destination": data.get("destination", ""),
            "status": "new",
            "created_at": now,
            "resolved_at": None,
        }
        conn = self._get_policy_conn()
        try:
            conn.execute(
                """INSERT INTO dlp_incidents
                   (id, org_id, policy_id, channel, user_id, user_email,
                    endpoint_hostname, data_type, detected_pattern, content_preview,
                    severity, action_taken, file_name, destination, status,
                    created_at, resolved_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (incident["id"], org_id, incident["policy_id"], channel,
                 incident["user_id"], incident["user_email"],
                 incident["endpoint_hostname"], data_type,
                 detected_pattern, content_preview,
                 incident["severity"], action_taken,
                 incident["file_name"], incident["destination"],
                 "new", now, None),
            )
            conn.execute(
                "UPDATE dlp_policies SET hit_count = hit_count + 1 WHERE org_id = ? AND id = ?",
                (org_id, matched_policy["id"]),
            )
            conn.commit()
        finally:
            conn.close()
        return incident

    def list_incidents(self, org_id: str, severity=None, channel=None,
                       status=None, limit: int = 50) -> list:
        """List incidents with optional filters."""
        sql = "SELECT * FROM dlp_incidents WHERE org_id = ?"
        params: list = [org_id]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if channel:
            sql += " AND channel = ?"
            params.append(channel)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        conn = self._get_policy_conn()
        try:
            rows = conn.execute(sql, params).fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    def update_incident_status(self, org_id: str, incident_id: str,
                               status: str) -> bool:
        """Update incident status. Returns True if found and updated."""
        if status not in self._VALID_INCIDENT_STATUSES:
            raise ValueError(f"Invalid status: {status}")
        now = self._now_iso()
        resolved_at = now if status == "resolved" else None
        conn = self._get_policy_conn()
        try:
            if resolved_at:
                cur = conn.execute(
                    "UPDATE dlp_incidents SET status=?, resolved_at=? WHERE org_id=? AND id=?",
                    (status, resolved_at, org_id, incident_id),
                )
            else:
                cur = conn.execute(
                    "UPDATE dlp_incidents SET status=? WHERE org_id=? AND id=?",
                    (status, org_id, incident_id),
                )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Exceptions
    # ------------------------------------------------------------------

    def create_exception(self, org_id: str, data: dict) -> dict:
        """Create a policy exception for a user."""
        user_id = (data.get("user_id") or "").strip()
        if not user_id:
            raise ValueError("user_id is required.")
        now = self._now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "user_id": user_id,
            "policy_id": data.get("policy_id", ""),
            "reason": data.get("reason", ""),
            "approved_by": data.get("approved_by", ""),
            "expires_at": data.get("expires_at"),
            "created_at": now,
        }
        conn = self._get_policy_conn()
        try:
            conn.execute(
                """INSERT INTO dlp_exceptions
                   (id, org_id, user_id, policy_id, reason, approved_by, expires_at, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (record["id"], org_id, user_id, record["policy_id"],
                 record["reason"], record["approved_by"],
                 record["expires_at"], now),
            )
            conn.commit()
        finally:
            conn.close()
        return record

    def list_exceptions(self, org_id: str) -> list:
        """List all exceptions for an org."""
        conn = self._get_policy_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM dlp_exceptions WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats (policy-based)
    # ------------------------------------------------------------------

    def get_dlp_stats(self, org_id: str) -> dict:
        """Return aggregated DLP stats for org (policy/incident model)."""
        conn = self._get_policy_conn()
        try:
            total = conn.execute(
                "SELECT COUNT(*) FROM dlp_incidents WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM dlp_incidents WHERE org_id = ? GROUP BY severity",
                (org_id,),
            ).fetchall()
            ch_rows = conn.execute(
                "SELECT channel, COUNT(*) as cnt FROM dlp_incidents WHERE org_id = ? GROUP BY channel",
                (org_id,),
            ).fetchall()
            dt_rows = conn.execute(
                "SELECT data_type, COUNT(*) as cnt FROM dlp_incidents WHERE org_id = ? GROUP BY data_type",
                (org_id,),
            ).fetchall()
            blocked = conn.execute(
                "SELECT COUNT(*) FROM dlp_incidents WHERE org_id = ? AND action_taken = 'blocked'",
                (org_id,),
            ).fetchone()[0]
            fp = conn.execute(
                "SELECT COUNT(*) FROM dlp_incidents WHERE org_id = ? AND status = 'false_positive'",
                (org_id,),
            ).fetchone()[0]
            user_rows = conn.execute(
                """SELECT user_email, COUNT(*) as cnt FROM dlp_incidents
                   WHERE org_id = ? AND user_email != ''
                   GROUP BY user_email ORDER BY cnt DESC LIMIT 10""",
                (org_id,),
            ).fetchall()
            policy_rows = conn.execute(
                """SELECT policy_id, COUNT(*) as cnt FROM dlp_incidents
                   WHERE org_id = ? GROUP BY policy_id ORDER BY cnt DESC LIMIT 10""",
                (org_id,),
            ).fetchall()
        finally:
            conn.close()

        return {
            "total_incidents": total,
            "by_severity": {r["severity"]: r["cnt"] for r in sev_rows},
            "by_channel": {r["channel"]: r["cnt"] for r in ch_rows},
            "by_data_type": {r["data_type"]: r["cnt"] for r in dt_rows},
            "block_rate": round(blocked / total, 4) if total > 0 else 0.0,
            "false_positive_rate": round(fp / total, 4) if total > 0 else 0.0,
            "top_users": [{"user_email": r["user_email"], "count": r["cnt"]} for r in user_rows],
            "top_policies": [{"policy_id": r["policy_id"], "count": r["cnt"]} for r in policy_rows],
        }

    def get_daily_trends(self, org_id: str, days: int = 30) -> list:
        """Return daily incident counts for the past N days."""
        conn = self._get_policy_conn()
        try:
            rows = conn.execute(
                """SELECT DATE(created_at) as date, COUNT(*) as count
                   FROM dlp_incidents
                   WHERE org_id = ? AND created_at >= DATE('now', ? || ' days')
                   GROUP BY DATE(created_at) ORDER BY date ASC""",
                (org_id, f"-{days}"),
            ).fetchall()
        finally:
            conn.close()
        return [{"date": r["date"], "count": r["count"]} for r in rows]
