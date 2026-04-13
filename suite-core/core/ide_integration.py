"""IDE integration module — inline SAST scanning for VS Code / JetBrains."""

import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from pydantic import BaseModel


class IDEFinding(BaseModel):
    file_path: str
    line_start: int
    line_end: int
    severity: str
    title: str
    description: str
    fix_suggestion: Optional[str] = None
    cwe_id: Optional[str] = None
    rule_id: str


class IDESession(BaseModel):
    id: str
    user_email: str
    ide_type: str
    project_path: str
    started_at: str
    last_active: str
    findings_shown: int = 0
    fixes_applied: int = 0
    org_id: str


SAST_PATTERNS = [
    ("sql_injection", re.compile(r"(execute|cursor\.execute)\s*\(\s*[\"'].*%"), "HIGH", "SQL Injection", "String formatting in SQL query", "CWE-89", "Use parameterized queries"),
    ("eval_exec", re.compile(r"\b(eval|exec)\s*\("), "HIGH", "Dangerous eval/exec", "Use of eval() or exec() can execute arbitrary code", "CWE-95", "Replace with safe alternatives"),
    ("hardcoded_password", re.compile(r"(?i)(password|passwd|secret|api_key)\s*=\s*[\"'][^\"']{4,}[\"']"), "HIGH", "Hardcoded Secret", "Credentials should not be hardcoded", "CWE-798", "Use environment variables"),
    ("insecure_random", re.compile(r"\brandom\.(random|randint|choice)\b"), "MEDIUM", "Insecure Random", "random module is not cryptographically secure", "CWE-330", "Use secrets module instead"),
    ("path_traversal", re.compile(r"open\s*\(.*\+"), "HIGH", "Path Traversal Risk", "User input may be concatenated into file path", "CWE-22", "Validate and sanitize file paths"),
    ("xss_innerhtml", re.compile(r"\.innerHTML\s*="), "HIGH", "XSS via innerHTML", "Setting innerHTML with untrusted data causes XSS", "CWE-79", "Use textContent or sanitize input"),
    ("command_injection", re.compile(r"\b(os\.system|subprocess\.call)\s*\("), "HIGH", "Command Injection", "Shell commands with user input can be injected", "CWE-78", "Use subprocess.run with shell=False"),
    ("weak_crypto", re.compile(r"\b(md5|sha1)\s*\("), "MEDIUM", "Weak Cryptography", "MD5/SHA1 are cryptographically broken", "CWE-327", "Use SHA-256 or stronger"),
    ("debug_logging", re.compile(r"(?i)\bprint\s*\(.*(?:password|secret|token)"), "LOW", "Sensitive Data in Logs", "Sensitive data may be logged", "CWE-532", "Remove or mask sensitive values"),
    ("no_verify_ssl", re.compile(r"verify\s*=\s*False"), "MEDIUM", "SSL Verification Disabled", "Disabling SSL verification allows MITM attacks", "CWE-295", "Set verify=True"),
    ("js_eval", re.compile(r"\beval\s*\("), "HIGH", "JavaScript eval()", "eval() executes arbitrary code", "CWE-95", "Use JSON.parse or safe alternatives"),
    ("document_write", re.compile(r"document\.write\s*\("), "MEDIUM", "document.write XSS", "document.write can introduce XSS vulnerabilities", "CWE-79", "Use DOM manipulation methods"),
]


class IDEIntegration:
    def __init__(self, db_path: str = ":memory:"):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_email TEXT NOT NULL,
                    ide_type TEXT NOT NULL,
                    project_path TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    last_active TEXT NOT NULL,
                    findings_shown INTEGER DEFAULT 0,
                    fixes_applied INTEGER DEFAULT 0,
                    org_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS fix_events (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    finding_rule_id TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                );
            """)

    def scan_file(self, content: str, file_path: str, language: str) -> List[IDEFinding]:
        findings = []
        lines = content.split("\n")
        for line_num, line in enumerate(lines, 1):
            for rule_id, pattern, severity, title, desc, cwe, fix in SAST_PATTERNS:
                if pattern.search(line):
                    findings.append(IDEFinding(
                        file_path=file_path, line_start=line_num, line_end=line_num,
                        severity=severity, title=title, description=desc,
                        fix_suggestion=fix, cwe_id=cwe, rule_id=rule_id,
                    ))
        return findings

    def scan_diff(self, diff_text: str) -> List[IDEFinding]:
        findings = []
        current_file = "unknown"
        for line in diff_text.split("\n"):
            if line.startswith("+++ b/"):
                current_file = line[6:]
            elif line.startswith("+") and not line.startswith("+++"):
                for rule_id, pattern, severity, title, desc, cwe, fix in SAST_PATTERNS:
                    if pattern.search(line):
                        findings.append(IDEFinding(
                            file_path=current_file, line_start=0, line_end=0,
                            severity=severity, title=title, description=desc,
                            fix_suggestion=fix, cwe_id=cwe, rule_id=rule_id,
                        ))
        return findings

    def get_fix_for_finding(self, finding: IDEFinding) -> Dict:
        return {"finding_id": finding.rule_id, "suggestion": finding.fix_suggestion or "No automated fix", "cwe": finding.cwe_id, "severity": finding.severity}

    def register_session(self, user_email: str, ide_type: str, project_path: str, org_id: str) -> IDESession:
        now = datetime.now(timezone.utc).isoformat()
        session = IDESession(id=str(uuid.uuid4()), user_email=user_email, ide_type=ide_type, project_path=project_path, started_at=now, last_active=now, org_id=org_id)
        with self._lock:
            self._conn.execute("INSERT INTO sessions (id,user_email,ide_type,project_path,started_at,last_active,findings_shown,fixes_applied,org_id) VALUES (?,?,?,?,?,?,?,?,?)",
                               (session.id, session.user_email, session.ide_type, session.project_path, session.started_at, session.last_active, 0, 0, session.org_id))
            self._conn.commit()
        return session

    def heartbeat(self, session_id: str):
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute("UPDATE sessions SET last_active=? WHERE id=?", (now, session_id))
            self._conn.commit()

    def record_fix_applied(self, session_id: str, rule_id: str):
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute("INSERT INTO fix_events (id,session_id,finding_rule_id,applied_at) VALUES (?,?,?,?)", (str(uuid.uuid4()), session_id, rule_id, now))
            self._conn.execute("UPDATE sessions SET fixes_applied=fixes_applied+1 WHERE id=?", (session_id,))
            self._conn.commit()

    def get_active_sessions(self, org_id: str) -> List[Dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM sessions WHERE org_id=? ORDER BY last_active DESC", (org_id,)).fetchall()
        return [dict(r) for r in rows]

    def get_ide_stats(self, org_id: str) -> Dict:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) as s, COALESCE(SUM(findings_shown),0) as f, COALESCE(SUM(fixes_applied),0) as x FROM sessions WHERE org_id=?", (org_id,)).fetchone()
        return {"sessions": row[0], "findings_shown": row[1], "fixes_applied": row[2]}

    def get_patterns(self) -> List[Dict]:
        return [{"rule_id": r[0], "severity": r[2], "title": r[3], "cwe": r[5]} for r in SAST_PATTERNS]
