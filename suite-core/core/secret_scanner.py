"""
secret_scanner.py — Regex-based secret detection with rotation tracking.

Provides in-process secret scanning without external tool dependencies.
Supports: text scanning, file scanning, directory scanning, git diff scanning,
custom patterns, rotation tracking, and pre-commit hook config generation.

SQLite-backed for persistence. Thread-safe via WAL mode.

Usage::

    scanner = SecretScanner()
    secrets = scanner.scan_text(content, "config.py")
    scanner.mark_rotated(secrets[0].id, "alice@example.com")
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

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


class SecretType(str, Enum):
    AWS_KEY = "aws_key"
    AWS_SECRET = "aws_secret"
    GITHUB_TOKEN = "github_token"
    GITLAB_TOKEN = "gitlab_token"
    SLACK_TOKEN = "slack_token"
    AZURE_KEY = "azure_key"
    GCP_KEY = "gcp_key"
    PRIVATE_KEY = "private_key"
    JWT_TOKEN = "jwt_token"
    DATABASE_URL = "database_url"
    API_KEY_GENERIC = "api_key_generic"
    PASSWORD = "password"
    ENCRYPTION_KEY = "encryption_key"


class SecretStatus(str, Enum):
    ACTIVE = "active"
    ROTATED = "rotated"
    FALSE_POSITIVE = "false_positive"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class SecretPattern(BaseModel):
    """A single secret detection pattern."""

    type: SecretType
    pattern: str = Field(..., description="Regex pattern string")
    description: str
    severity: str = Field(default="high", description="critical | high | medium | low")
    false_positive_patterns: List[str] = Field(
        default_factory=list,
        description="Regex patterns that indicate a false positive match",
    )


class DetectedSecret(BaseModel):
    """A detected secret instance."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: SecretType
    file_path: str
    line_number: int
    matched_text_masked: str = Field(
        ..., description="First 4 + last 4 chars only; middle replaced with ***"
    )
    severity: str
    commit_sha: Optional[str] = None
    author: Optional[str] = None
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: SecretStatus = SecretStatus.ACTIVE
    org_id: str = "default"


class RotationRecord(BaseModel):
    """Record that a secret was rotated."""

    secret_id: str
    rotated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    rotated_by: str
    new_key_prefix: Optional[str] = None


# ---------------------------------------------------------------------------
# Built-in patterns (20+)
# ---------------------------------------------------------------------------

_BUILTIN_PATTERNS: List[SecretPattern] = [
    # AWS
    SecretPattern(
        type=SecretType.AWS_KEY,
        pattern=r"(?<![A-Z0-9])(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
        description="AWS Access Key ID",
        severity="critical",
        false_positive_patterns=[
            r"AKIAIOSFODNN7EXAMPLE",
            r"EXAMPLE",
            r"YOUR_AWS",
            r"<YOUR",
        ],
    ),
    SecretPattern(
        type=SecretType.AWS_SECRET,
        pattern=r"(?i)aws[_\-\s]*secret[_\-\s]*(?:access[_\-\s]*)?key\s*[=:]\s*[\"']*([A-Za-z0-9/+=]{39,44})",
        description="AWS Secret Access Key",
        severity="critical",
        false_positive_patterns=[r"EXAMPLE", r"YOUR_SECRET", r"<YOUR"],
    ),
    # GitHub
    SecretPattern(
        type=SecretType.GITHUB_TOKEN,
        pattern=r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        description="GitHub Personal Access Token",
        severity="critical",
        false_positive_patterns=[r"ghp_EXAMPLE", r"YOUR_TOKEN"],
    ),
    SecretPattern(
        type=SecretType.GITHUB_TOKEN,
        pattern=r"github[_\-]?(?:pat|token|key)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9_]{35,255})",
        description="GitHub Token (named variable)",
        severity="high",
        false_positive_patterns=[r"EXAMPLE", r"YOUR_TOKEN", r"<YOUR"],
    ),
    # GitLab
    SecretPattern(
        type=SecretType.GITLAB_TOKEN,
        pattern=r"glpat-[A-Za-z0-9\-_]{20,}",
        description="GitLab Personal Access Token",
        severity="critical",
        false_positive_patterns=[r"glpat-EXAMPLE", r"YOUR_TOKEN"],
    ),
    # Slack
    SecretPattern(
        type=SecretType.SLACK_TOKEN,
        pattern=r"xox[baprs]-(?:[0-9]{10,13}-){1,3}[a-zA-Z0-9]{20,64}",
        description="Slack Bot/App/User Token",
        severity="high",
        false_positive_patterns=[r"xoxb-EXAMPLE", r"YOUR_TOKEN"],
    ),
    SecretPattern(
        type=SecretType.SLACK_TOKEN,
        pattern=r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,10}/B[A-Z0-9]{8,10}/[A-Za-z0-9]{24}",
        description="Slack Webhook URL",
        severity="high",
        false_positive_patterns=[r"EXAMPLE"],
    ),
    # Azure
    SecretPattern(
        type=SecretType.AZURE_KEY,
        pattern=r"(?i)(?:azure|az)[_\-\s]*(?:storage[_\-\s]*)?(?:account[_\-\s]*)?(?:key|secret|connection[_\-\s]*string)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9+/=]{44,88})",
        description="Azure Storage Key / Connection String secret",
        severity="critical",
        false_positive_patterns=[r"EXAMPLE", r"YOUR_KEY", r"<YOUR"],
    ),
    SecretPattern(
        type=SecretType.AZURE_KEY,
        pattern=r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{44,}",
        description="Azure Storage Connection String",
        severity="critical",
        false_positive_patterns=[r"EXAMPLE", r"yourstorageaccount"],
    ),
    # GCP
    SecretPattern(
        type=SecretType.GCP_KEY,
        pattern=r"AIza[0-9A-Za-z\-_]{35}",
        description="Google API Key",
        severity="high",
        false_positive_patterns=[r"AIzaEXAMPLE", r"YOUR_KEY"],
    ),
    SecretPattern(
        type=SecretType.GCP_KEY,
        pattern=r'"type"\s*:\s*"service_account"',
        description="GCP Service Account JSON",
        severity="critical",
        false_positive_patterns=[r"EXAMPLE"],
    ),
    # Private Key
    SecretPattern(
        type=SecretType.PRIVATE_KEY,
        pattern=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        description="PEM Private Key block",
        severity="critical",
        false_positive_patterns=[r"EXAMPLE", r"test_key", r"dummy"],
    ),
    # JWT
    SecretPattern(
        type=SecretType.JWT_TOKEN,
        pattern=r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        description="JSON Web Token (JWT)",
        severity="medium",
        false_positive_patterns=[r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJzdWIiOiIxMjM0NTY3ODkwIn0"],
    ),
    # Database URLs
    SecretPattern(
        type=SecretType.DATABASE_URL,
        pattern=r"(?:postgres|postgresql|mysql|mongodb|redis|mssql|oracle)(?:\+\w+)?://[^:@\s]+:[^@\s]+@[^\s\"']+",
        description="Database connection URL with credentials",
        severity="critical",
        false_positive_patterns=[
            r"user:password@",
            r"username:password@",
            r"<user>",
            r"YOUR_PASSWORD",
            r"://[^:@\s]*EXAMPLE[^:@\s]*:",  # EXAMPLE in username portion only
            r":\bEXAMPLE\b",                  # EXAMPLE as the literal password
        ],
    ),
    # Generic API Key patterns
    SecretPattern(
        type=SecretType.API_KEY_GENERIC,
        pattern=r"(?i)api[_\-\s]?key[\"'\s]*[:=][\"'\s]*([A-Za-z0-9_\-]{20,64})",
        description="Generic API Key assignment",
        severity="medium",
        false_positive_patterns=[
            r"YOUR_API_KEY",
            r"<api_key>",
            r"EXAMPLE",
            r"api_key_here",
            r"placeholder",
        ],
    ),
    SecretPattern(
        type=SecretType.API_KEY_GENERIC,
        pattern=r"(?i)access[_\-\s]?token[\"'\s]*[:=][\"'\s]*([A-Za-z0-9_\-\.]{20,128})",
        description="Generic Access Token assignment",
        severity="medium",
        false_positive_patterns=[
            r"YOUR_TOKEN",
            r"<token>",
            r"EXAMPLE",
            r"token_here",
        ],
    ),
    # Password patterns
    SecretPattern(
        type=SecretType.PASSWORD,
        pattern=r"(?i)password[\"'\s]*[:=][\"'\s]*([^\s\"'<>{}\[\]]{8,128})",
        description="Hardcoded password assignment",
        severity="high",
        false_positive_patterns=[
            r"YOUR_PASSWORD",
            r"<password>",
            r"EXAMPLE",
            r"\$\{",
            r"\$\(",
            r"password_here",
            r"changeme",
            r"placeholder",
            r"^\*+$",
        ],
    ),
    SecretPattern(
        type=SecretType.PASSWORD,
        pattern=r"(?i)passwd[\"'\s]*[:=][\"'\s]*([^\s\"'<>{}\[\]]{8,128})",
        description="Hardcoded passwd assignment",
        severity="high",
        false_positive_patterns=[
            r"YOUR_PASSWD",
            r"<passwd>",
            r"EXAMPLE",
            r"\$\{",
            r"passwd_here",
        ],
    ),
    # Encryption key patterns
    SecretPattern(
        type=SecretType.ENCRYPTION_KEY,
        pattern=r"(?i)(?:secret|encryption|encrypt|cipher)[_\-\s]?key[\"'\s]*[:=][\"'\s]*([A-Za-z0-9+/=_\-]{16,64})",
        description="Encryption or secret key assignment",
        severity="high",
        false_positive_patterns=[
            r"YOUR_KEY",
            r"<key>",
            r"EXAMPLE",
            r"key_here",
            r"placeholder",
        ],
    ),
    # Stripe / payment
    SecretPattern(
        type=SecretType.API_KEY_GENERIC,
        pattern=r"sk_(?:live|test)_[A-Za-z0-9]{24,}",
        description="Stripe Secret Key",
        severity="critical",
        false_positive_patterns=[r"sk_test_EXAMPLE", r"YOUR_STRIPE"],
    ),
    # Twilio
    SecretPattern(
        type=SecretType.API_KEY_GENERIC,
        pattern=r"SK[0-9a-fA-F]{32}",
        description="Twilio API Key SID",
        severity="high",
        false_positive_patterns=[r"EXAMPLE"],
    ),
    # SendGrid
    SecretPattern(
        type=SecretType.API_KEY_GENERIC,
        pattern=r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
        description="SendGrid API Key",
        severity="high",
        false_positive_patterns=[r"SG\.EXAMPLE"],
    ),
]

# File extensions to skip during directory scan
_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".wasm",
    ".pyc", ".pyo", ".class", ".jar",
    ".lock",  # dependency lock files often have hashes that look like keys
}

# Directories to skip
_SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    ".tox", "dist", "build", ".cache", ".mypy_cache", ".pytest_cache",
}


# ---------------------------------------------------------------------------
# SecretScanner
# ---------------------------------------------------------------------------


def _db_path() -> Path:
    data_dir = Path(os.getenv(_DB_ENV, _DEFAULT_DB_DIR))
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / "secret_scanner.db"


class SecretScanner:
    """Regex-based secret scanner with SQLite-backed rotation tracking."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._db_path = Path(db_path) if db_path else _db_path()
        self._compiled: List[tuple[SecretPattern, re.Pattern[str], List[re.Pattern[str]]]] = []
        self._init_db()
        self._load_patterns()

    # ------------------------------------------------------------------
    # DB bootstrap
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(_THREAD_LOCAL, "secret_scanner_conn"):
            conn = sqlite3.connect(str(self._db_path))
            conn.execute("PRAGMA journal_mode=WAL")
            conn.row_factory = sqlite3.Row
            _THREAD_LOCAL.secret_scanner_conn = conn
        return _THREAD_LOCAL.secret_scanner_conn

    def _init_db(self) -> None:
        conn = self._conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS detected_secrets (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                matched_text_masked TEXT NOT NULL,
                severity TEXT NOT NULL,
                commit_sha TEXT,
                author TEXT,
                detected_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                org_id TEXT NOT NULL DEFAULT 'default',
                content_hash TEXT
            );

            CREATE TABLE IF NOT EXISTS rotation_records (
                id TEXT PRIMARY KEY,
                secret_id TEXT NOT NULL,
                rotated_at TEXT NOT NULL,
                rotated_by TEXT NOT NULL,
                new_key_prefix TEXT,
                FOREIGN KEY (secret_id) REFERENCES detected_secrets(id)
            );

            CREATE TABLE IF NOT EXISTS custom_patterns (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                pattern TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'high',
                false_positive_patterns TEXT NOT NULL DEFAULT '[]',
                org_id TEXT NOT NULL DEFAULT 'default',
                created_at TEXT NOT NULL
            );
            """
        )
        conn.commit()

    # ------------------------------------------------------------------
    # Pattern management
    # ------------------------------------------------------------------

    def _load_patterns(self) -> None:
        """Compile built-in + custom patterns."""
        self._compiled = []
        all_patterns = list(_BUILTIN_PATTERNS)

        # Load custom patterns from DB
        try:
            conn = self._conn()
            rows = conn.execute("SELECT * FROM custom_patterns").fetchall()
            import json as _json
            for row in rows:
                fp_raw = row["false_positive_patterns"]
                try:
                    fp_list = _json.loads(fp_raw) if fp_raw else []
                except Exception:
                    fp_list = []
                all_patterns.append(
                    SecretPattern(
                        type=SecretType(row["type"]),
                        pattern=row["pattern"],
                        description=row["description"],
                        severity=row["severity"],
                        false_positive_patterns=fp_list,
                    )
                )
        except Exception:
            pass

        for sp in all_patterns:
            try:
                compiled_re = re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)
                compiled_fp = [re.compile(fp, re.IGNORECASE) for fp in sp.false_positive_patterns]
                self._compiled.append((sp, compiled_re, compiled_fp))
            except re.error as exc:
                logger.warning("Invalid pattern for %s: %s — %s", sp.type, sp.pattern, exc)

    def get_patterns(self) -> List[SecretPattern]:
        """Return all active detection patterns."""
        return [sp for sp, _, _ in self._compiled]

    def add_custom_pattern(self, pattern: SecretPattern, org_id: str = "default") -> None:
        """Persist a custom pattern and reload compiled patterns."""
        import json as _json
        conn = self._conn()
        conn.execute(
            """
            INSERT INTO custom_patterns
                (id, type, pattern, description, severity, false_positive_patterns, org_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                pattern.type.value,
                pattern.pattern,
                pattern.description,
                pattern.severity,
                _json.dumps(pattern.false_positive_patterns),
                org_id,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
        self._load_patterns()

    # ------------------------------------------------------------------
    # Masking
    # ------------------------------------------------------------------

    @staticmethod
    def _mask_secret(text: str) -> str:
        """Return first 4 + last 4 chars; middle replaced with ***."""
        if len(text) <= 8:
            return "****"
        return text[:4] + "***" + text[-4:]

    # ------------------------------------------------------------------
    # Core scanning
    # ------------------------------------------------------------------

    def _is_false_positive(
        self,
        match_text: str,
        fp_patterns: List[re.Pattern[str]],
    ) -> bool:
        for fp in fp_patterns:
            if fp.search(match_text):
                return True
        return False

    def _dedup_key(self, file_path: str, line_number: int, secret_type: SecretType, masked: str) -> str:
        raw = f"{file_path}:{line_number}:{secret_type}:{masked}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def scan_text(
        self,
        text: str,
        file_path: str,
        commit_sha: Optional[str] = None,
        author: Optional[str] = None,
        org_id: str = "default",
    ) -> List[DetectedSecret]:
        """Scan text content and return detected secrets."""
        found: List[DetectedSecret] = []
        seen_hashes: set[str] = set()
        text.splitlines()

        for sp, compiled_re, compiled_fp in self._compiled:
            for m in compiled_re.finditer(text):
                match_text = m.group(0)

                # Use first capturing group value if available (for named variable patterns)
                full_match = match_text
                if m.lastindex and m.lastindex >= 1:
                    captured = m.group(1)
                    if captured:
                        match_text = captured

                if self._is_false_positive(full_match, compiled_fp):
                    continue
                if self._is_false_positive(match_text, compiled_fp):
                    continue

                # Determine line number
                start_pos = m.start()
                line_num = text[:start_pos].count("\n") + 1

                masked = self._mask_secret(match_text)
                dedup = self._dedup_key(file_path, line_num, sp.type, masked)
                if dedup in seen_hashes:
                    continue
                seen_hashes.add(dedup)

                secret = DetectedSecret(
                    type=sp.type,
                    file_path=file_path,
                    line_number=line_num,
                    matched_text_masked=masked,
                    severity=sp.severity,
                    commit_sha=commit_sha,
                    author=author,
                    org_id=org_id,
                )
                self._persist_secret(secret, dedup)
                found.append(secret)

        _tg_emit("secret_scanner.scan_text", {"file_path": file_path, "org_id": org_id, "secrets_found": len(found)})
        return found

    def _persist_secret(self, secret: DetectedSecret, content_hash: str) -> None:
        conn = self._conn()
        # Check if already exists by content_hash to avoid duplicate inserts
        existing = conn.execute(
            "SELECT id, status FROM detected_secrets WHERE content_hash = ?",
            (content_hash,),
        ).fetchone()
        if existing:
            # Update the id so the caller gets the canonical one
            secret.__dict__["id"] = existing["id"]
            secret.__dict__["status"] = existing["status"]
            return
        conn.execute(
            """
            INSERT INTO detected_secrets
                (id, type, file_path, line_number, matched_text_masked,
                 severity, commit_sha, author, detected_at, status, org_id, content_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                secret.id,
                secret.type.value,
                secret.file_path,
                secret.line_number,
                secret.matched_text_masked,
                secret.severity,
                secret.commit_sha,
                secret.author,
                secret.detected_at.isoformat(),
                secret.status.value,
                secret.org_id,
                content_hash,
            ),
        )
        conn.commit()

    def scan_file(self, file_path: str, org_id: str = "default") -> List[DetectedSecret]:
        """Scan a single file and return detected secrets."""
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            logger.debug("scan_file: path does not exist or is not a file: %s", file_path)
            return []
        if p.suffix.lower() in _SKIP_EXTENSIONS:
            return []
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("scan_file: cannot read %s: %s", file_path, exc)
            return []
        return self.scan_text(text, str(p), org_id=org_id)

    def scan_directory(
        self,
        dir_path: str,
        exclude_patterns: Optional[List[str]] = None,
        org_id: str = "default",
    ) -> List[DetectedSecret]:
        """Recursively scan a directory and return all detected secrets."""
        root = Path(dir_path)
        if not root.is_dir():
            logger.warning("scan_directory: not a directory: %s", dir_path)
            return []

        compiled_excludes: List[re.Pattern[str]] = []
        for ep in (exclude_patterns or []):
            try:
                compiled_excludes.append(re.compile(ep))
            except re.error:
                pass

        all_secrets: List[DetectedSecret] = []

        for file_path in root.rglob("*"):
            if not file_path.is_file():
                continue
            # Skip hidden / build dirs
            parts = file_path.relative_to(root).parts
            if any(p.startswith(".") or p in _SKIP_DIRS for p in parts):
                continue
            if file_path.suffix.lower() in _SKIP_EXTENSIONS:
                continue
            rel = str(file_path.relative_to(root))
            if any(exc.search(rel) for exc in compiled_excludes):
                continue

            secrets = self.scan_file(str(file_path), org_id=org_id)
            all_secrets.extend(secrets)

        return all_secrets

    def scan_diff(
        self,
        diff_text: str,
        commit_sha: Optional[str] = None,
        author: Optional[str] = None,
        org_id: str = "default",
    ) -> List[DetectedSecret]:
        """Scan a git diff, considering only added lines (+)."""
        current_file = "unknown"
        line_counter = 0
        all_secrets: List[DetectedSecret] = []

        for line in diff_text.splitlines():
            if line.startswith("--- ") or line.startswith("+++ "):
                if line.startswith("+++ "):
                    # Extract file path from diff header
                    current_file = line[4:].strip()
                    if current_file.startswith("b/"):
                        current_file = current_file[2:]
                line_counter = 0
                continue
            if line.startswith("@@ "):
                # Extract new-file start line from hunk header
                m = re.search(r"\+(\d+)", line)
                if m:
                    line_counter = int(m.group(1)) - 1
                continue
            if line.startswith("+") and not line.startswith("+++"):
                line_counter += 1
                added_content = line[1:]  # strip leading +
                secrets = self.scan_text(
                    added_content,
                    current_file,
                    commit_sha=commit_sha,
                    author=author,
                    org_id=org_id,
                )
                all_secrets.extend(secrets)
            elif not line.startswith("-"):
                line_counter += 1

        return all_secrets

    # ------------------------------------------------------------------
    # Status management
    # ------------------------------------------------------------------

    def mark_false_positive(self, secret_id: str) -> bool:
        """Mark a secret as a false positive. Returns True if found."""
        conn = self._conn()
        cursor = conn.execute(
            "UPDATE detected_secrets SET status = ? WHERE id = ?",
            (SecretStatus.FALSE_POSITIVE.value, secret_id),
        )
        conn.commit()
        found = cursor.rowcount > 0
        if found:
            _tg_emit("secret_scanner.mark_false_positive", {"secret_id": secret_id})
        return found

    def mark_rotated(self, secret_id: str, rotated_by: str, new_key_prefix: Optional[str] = None) -> bool:
        """Mark a secret as rotated and record the rotation. Returns True if found."""
        conn = self._conn()
        cursor = conn.execute(
            "UPDATE detected_secrets SET status = ? WHERE id = ?",
            (SecretStatus.ROTATED.value, secret_id),
        )
        if cursor.rowcount == 0:
            conn.commit()
            return False

        conn.execute(
            """
            INSERT INTO rotation_records (id, secret_id, rotated_at, rotated_by, new_key_prefix)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                secret_id,
                datetime.now(timezone.utc).isoformat(),
                rotated_by,
                new_key_prefix,
            ),
        )
        conn.commit()
        _tg_emit("secret_scanner.mark_rotated", {"secret_id": secret_id, "rotated_by": rotated_by})
        return True

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def _row_to_secret(self, row: sqlite3.Row) -> DetectedSecret:
        return DetectedSecret(
            id=row["id"],
            type=SecretType(row["type"]),
            file_path=row["file_path"],
            line_number=row["line_number"],
            matched_text_masked=row["matched_text_masked"],
            severity=row["severity"],
            commit_sha=row["commit_sha"],
            author=row["author"],
            detected_at=datetime.fromisoformat(row["detected_at"]),
            status=SecretStatus(row["status"]),
            org_id=row["org_id"],
        )

    def get_active_secrets(self, org_id: str = "default") -> List[DetectedSecret]:
        """Return all unrotated, non-false-positive secrets for an org."""
        conn = self._conn()
        rows = conn.execute(
            "SELECT * FROM detected_secrets WHERE org_id = ? AND status = ?",
            (org_id, SecretStatus.ACTIVE.value),
        ).fetchall()
        return [self._row_to_secret(r) for r in rows]

    def get_rotation_status(self, org_id: str = "default") -> Dict[str, Any]:
        """Return counts of rotated vs active secrets for an org."""
        conn = self._conn()
        rows = conn.execute(
            "SELECT status, COUNT(*) as cnt FROM detected_secrets WHERE org_id = ? GROUP BY status",
            (org_id,),
        ).fetchall()
        counts: Dict[str, int] = {r["status"]: r["cnt"] for r in rows}
        total = sum(counts.values())
        return {
            "org_id": org_id,
            "total": total,
            "active": counts.get(SecretStatus.ACTIVE.value, 0),
            "rotated": counts.get(SecretStatus.ROTATED.value, 0),
            "false_positive": counts.get(SecretStatus.FALSE_POSITIVE.value, 0),
            "rotation_rate": (
                round(counts.get(SecretStatus.ROTATED.value, 0) / total * 100, 1)
                if total > 0
                else 0.0
            ),
        }

    # ------------------------------------------------------------------
    # Pre-commit hook config
    # ------------------------------------------------------------------

    def generate_precommit_config(self) -> str:
        """Generate a .pre-commit-config.yaml that runs this scanner."""
        return """\
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks
        name: Gitleaks — detect secrets
        description: Detect hardcoded secrets using Gitleaks
        language: golang
        pass_filenames: false
        args:
          - protect
          - --staged
          - --redact
          - --verbose

  - repo: local
    hooks:
      - id: fixops-secret-scanner
        name: FixOps Regex Secret Scanner
        entry: python -c "
import sys, json
from core.secret_scanner import SecretScanner
scanner = SecretScanner()
secrets = []
for f in sys.argv[1:]:
    secrets.extend(scanner.scan_file(f))
active = [s for s in secrets if s.status.value == 'active']
if active:
    print(f'[FixOps] {len(active)} secret(s) detected:')
    for s in active:
        print(f'  {s.file_path}:{s.line_number} [{s.type.value}] {s.matched_text_masked}')
    sys.exit(1)
"
        language: python
        types: [text]
        pass_filenames: true
"""
