"""
Security Knowledge Base — SQLite FTS5-backed searchable wiki.

Stores articles on vulnerabilities, remediation guides, best practices,
compliance notes, architecture patterns, and incident response playbooks.
Seeded with 15+ built-in articles covering OWASP Top 10 + common CWEs.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from collections import Counter
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums & models
# ---------------------------------------------------------------------------


class ArticleCategory(str, Enum):
    VULNERABILITY = "vulnerability"
    REMEDIATION = "remediation"
    BEST_PRACTICE = "best_practice"
    COMPLIANCE = "compliance"
    ARCHITECTURE = "architecture"
    INCIDENT_RESPONSE = "incident_response"


class Article(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    content: str  # Markdown
    category: ArticleCategory
    tags: List[str] = Field(default_factory=list)
    cwe_ids: List[str] = Field(default_factory=list)
    owasp_ids: List[str] = Field(default_factory=list)
    language: Optional[str] = None  # python/javascript/java/go
    framework: Optional[str] = None
    severity_context: Optional[str] = None
    version: int = 1
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    author: str = "system"
    org_id: str = "default"


class SearchResult(BaseModel):
    article_id: str
    title: str
    snippet: str
    relevance_score: float
    tags: List[str]


# ---------------------------------------------------------------------------
# Helper — snippet extraction
# ---------------------------------------------------------------------------


def _make_snippet(content: str, query: str, max_len: int = 200) -> str:
    """Extract a relevant snippet from content around the first query term hit."""
    lower_content = content.lower()
    first_term = query.split()[0].lower() if query.split() else ""
    pos = lower_content.find(first_term) if first_term else -1
    if pos == -1:
        return content[:max_len].rstrip() + ("..." if len(content) > max_len else "")
    start = max(0, pos - 40)
    end = min(len(content), pos + max_len - 40)
    snippet = content[start:end].strip()
    if start > 0:
        snippet = "..." + snippet
    if end < len(content):
        snippet = snippet + "..."
    return snippet


# ---------------------------------------------------------------------------
# Built-in seed articles
# ---------------------------------------------------------------------------

_SEED_ARTICLES: List[Dict[str, Any]] = [
    {
        "title": "SQL Injection (CWE-89)",
        "category": ArticleCategory.VULNERABILITY,
        "tags": ["sql", "injection", "database", "owasp-a03"],
        "cwe_ids": ["CWE-89"],
        "owasp_ids": ["A03:2021"],
        "severity_context": "critical",
        "content": """## SQL Injection

SQL Injection occurs when untrusted data is sent to an interpreter as part of a command or query.

### Impact
- Complete database compromise
- Authentication bypass
- Data exfiltration or destruction

### Detection
- Look for unsanitized user input in SQL queries
- Search for string concatenation in database calls

### Remediation
1. Use parameterized queries / prepared statements
2. Use an ORM that escapes input automatically
3. Apply input validation and allowlisting
4. Implement least-privilege database accounts

### Example (Python — SQLite)
```python
# BAD
cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")

# GOOD
cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))
```
""",
    },
    {
        "title": "Cross-Site Scripting (XSS) — CWE-79",
        "category": ArticleCategory.VULNERABILITY,
        "tags": ["xss", "javascript", "web", "owasp-a03"],
        "cwe_ids": ["CWE-79"],
        "owasp_ids": ["A03:2021"],
        "severity_context": "high",
        "content": """## Cross-Site Scripting (XSS)

XSS flaws occur when an application includes untrusted data in a web page without proper validation or escaping.

### Types
- **Reflected XSS** — payload in the request, reflected back immediately
- **Stored XSS** — payload persisted in the database
- **DOM-based XSS** — payload executed via client-side JavaScript

### Remediation
1. Escape all output (HTML, JS, CSS, URL contexts separately)
2. Use Content Security Policy (CSP) headers
3. Use modern frameworks that auto-escape (React, Angular)
4. Validate and sanitize input server-side

### CSP Header Example
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'
```
""",
    },
    {
        "title": "Broken Access Control (OWASP A01:2021)",
        "category": ArticleCategory.VULNERABILITY,
        "tags": ["access-control", "authorization", "idor", "owasp-a01"],
        "cwe_ids": ["CWE-284", "CWE-285", "CWE-639"],
        "owasp_ids": ["A01:2021"],
        "severity_context": "critical",
        "content": """## Broken Access Control

Access control enforces policy such that users cannot act outside of their intended permissions.

### Common Flaws
- Insecure Direct Object References (IDOR)
- Missing function-level access control
- Privilege escalation (vertical and horizontal)
- CORS misconfiguration

### Remediation
1. Deny by default — require explicit grants
2. Enforce server-side access checks on every request
3. Use UUIDs instead of sequential IDs
4. Log and alert on repeated access failures
5. Rate-limit API endpoints

### Example (Python/FastAPI)
```python
@router.get("/users/{user_id}")
async def get_user(user_id: str, current_user = Depends(get_current_user)):
    if current_user.id != user_id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Forbidden")
    return db.get_user(user_id)
```
""",
    },
    {
        "title": "Cryptographic Failures (OWASP A02:2021)",
        "category": ArticleCategory.VULNERABILITY,
        "tags": ["cryptography", "encryption", "tls", "owasp-a02"],
        "cwe_ids": ["CWE-327", "CWE-328", "CWE-330"],
        "owasp_ids": ["A02:2021"],
        "severity_context": "high",
        "content": """## Cryptographic Failures

Failures related to cryptography often lead to exposure of sensitive data.

### Common Issues
- Weak algorithms (MD5, SHA1, DES, RC4)
- Hardcoded secrets/keys
- Missing encryption in transit (HTTP instead of HTTPS)
- Weak key generation

### Remediation
1. Use TLS 1.2+ for all data in transit
2. Use AES-256-GCM or ChaCha20-Poly1305 for data at rest
3. Use bcrypt/Argon2 for password hashing
4. Never store secrets in code — use environment variables or a vault
5. Rotate keys and certificates regularly
""",
    },
    {
        "title": "Insecure Design (OWASP A04:2021)",
        "category": ArticleCategory.ARCHITECTURE,
        "tags": ["design", "threat-modeling", "architecture", "owasp-a04"],
        "cwe_ids": ["CWE-209", "CWE-256"],
        "owasp_ids": ["A04:2021"],
        "severity_context": "high",
        "content": """## Insecure Design

Insecure design is a broad category representing different weaknesses, expressed as "missing or ineffective control design."

### Remediation
1. Establish a secure development lifecycle (SDL)
2. Perform threat modeling for every feature
3. Apply secure design principles: least privilege, defense in depth, fail securely
4. Write unit and integration tests for security controls
5. Limit resource consumption per user

### Threat Modeling Steps
1. Decompose the application
2. Identify threats using STRIDE
3. Rank threats by risk
4. Determine countermeasures
""",
    },
    {
        "title": "Security Misconfiguration (OWASP A05:2021)",
        "category": ArticleCategory.VULNERABILITY,
        "tags": ["misconfiguration", "hardening", "defaults", "owasp-a05"],
        "cwe_ids": ["CWE-16"],
        "owasp_ids": ["A05:2021"],
        "severity_context": "medium",
        "content": """## Security Misconfiguration

Missing appropriate security hardening across the application stack.

### Common Issues
- Default credentials unchanged
- Unnecessary features enabled
- Verbose error messages exposing stack traces
- Missing security headers
- Cloud storage buckets open to the public

### Remediation
1. Implement a repeatable hardening process
2. Remove or disable unused features, components, and documentation
3. Review and update security configurations as part of patch management
4. Set `debug=False` in production
5. Implement security headers: HSTS, X-Frame-Options, X-Content-Type-Options

### Security Headers Example (Python/FastAPI)
```python
from fastapi.middleware.trustedhost import TrustedHostMiddleware
app.add_middleware(
    TrustedHostMiddleware, allowed_hosts=["example.com"]
)
```
""",
    },
    {
        "title": "Vulnerable and Outdated Components (OWASP A06:2021)",
        "category": ArticleCategory.BEST_PRACTICE,
        "tags": ["dependencies", "sca", "patching", "owasp-a06"],
        "cwe_ids": ["CWE-1104"],
        "owasp_ids": ["A06:2021"],
        "severity_context": "medium",
        "content": """## Vulnerable and Outdated Components

Using components with known vulnerabilities can undermine application defenses.

### Remediation
1. Subscribe to security bulletins for components used
2. Regularly audit dependencies with tools (pip-audit, npm audit, snyk)
3. Remove unused dependencies
4. Pin dependency versions and use a lock file
5. Monitor CVE databases for your dependency tree

### Automation
```bash
# Python
pip-audit

# Node.js
npm audit fix

# GitHub Dependabot
# Add .github/dependabot.yml to auto-create PRs
```
""",
    },
    {
        "title": "Identification and Authentication Failures (OWASP A07:2021)",
        "category": ArticleCategory.VULNERABILITY,
        "tags": ["authentication", "session", "mfa", "owasp-a07"],
        "cwe_ids": ["CWE-287", "CWE-297", "CWE-384"],
        "owasp_ids": ["A07:2021"],
        "severity_context": "high",
        "content": """## Identification and Authentication Failures

Confirmation of the user's identity, authentication, and session management.

### Common Issues
- Weak passwords allowed
- Missing multi-factor authentication
- Weak session tokens
- Sessions not invalidated on logout

### Remediation
1. Implement MFA for all privileged accounts
2. Use secure, random session tokens (>= 128 bits)
3. Implement account lockout after failed attempts
4. Use bcrypt/Argon2 for password storage
5. Invalidate sessions on logout and password change

### Secure Session Example
```python
import secrets
session_token = secrets.token_urlsafe(32)  # 256-bit token
```
""",
    },
    {
        "title": "Software and Data Integrity Failures (OWASP A08:2021)",
        "category": ArticleCategory.VULNERABILITY,
        "tags": ["integrity", "ci-cd", "supply-chain", "owasp-a08"],
        "cwe_ids": ["CWE-494", "CWE-829"],
        "owasp_ids": ["A08:2021"],
        "severity_context": "high",
        "content": """## Software and Data Integrity Failures

Code and infrastructure that does not protect against integrity violations.

### Common Issues
- Unsigned software updates
- Insecure deserialization
- Dependency confusion attacks
- Unsigned CI/CD pipeline steps

### Remediation
1. Use digital signatures for software updates
2. Verify integrity of dependencies via checksums
3. Ensure CI/CD pipelines have integrity controls
4. Use serialization formats that don't allow object instantiation
5. Review deserialization code carefully
""",
    },
    {
        "title": "Security Logging and Monitoring Failures (OWASP A09:2021)",
        "category": ArticleCategory.BEST_PRACTICE,
        "tags": ["logging", "monitoring", "siem", "owasp-a09"],
        "cwe_ids": ["CWE-778"],
        "owasp_ids": ["A09:2021"],
        "severity_context": "medium",
        "content": """## Security Logging and Monitoring Failures

Insufficient logging allows attackers to further attack systems and maintain persistence.

### What to Log
- Authentication events (success and failure)
- Access control failures
- Server-side input validation failures
- High-value transactions

### Remediation
1. Ensure all authentication, access control, and server-side input validation failures are logged
2. Log in a format consumable by SIEM solutions
3. Set up alerting for suspicious activity
4. Protect logs from tampering (write-once storage)

### Example (Python/structlog)
```python
import structlog
logger = structlog.get_logger()
logger.warning("auth_failed", user=username, ip=request.client.host)
```
""",
    },
    {
        "title": "Server-Side Request Forgery (SSRF) — OWASP A10:2021",
        "category": ArticleCategory.VULNERABILITY,
        "tags": ["ssrf", "server-side", "network", "owasp-a10"],
        "cwe_ids": ["CWE-918"],
        "owasp_ids": ["A10:2021"],
        "severity_context": "high",
        "content": """## Server-Side Request Forgery (SSRF)

SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.

### Impact
- Internal network scanning
- Cloud metadata service access (AWS IMDSv1)
- Bypassing firewalls and access controls

### Remediation
1. Validate and sanitize all client-supplied input URLs
2. Use an allowlist of permitted domains/IPs
3. Disable HTTP redirections
4. Enforce network-layer controls (firewall, VPC policies)
5. Block access to cloud metadata endpoints (169.254.169.254)

### Example Allowlist (Python)
```python
from urllib.parse import urlparse
ALLOWED_HOSTS = {"api.trusted.com", "data.partner.com"}
parsed = urlparse(user_url)
if parsed.hostname not in ALLOWED_HOSTS:
    raise ValueError("Domain not allowed")
```
""",
    },
    {
        "title": "Path Traversal (CWE-22) Remediation Guide",
        "category": ArticleCategory.REMEDIATION,
        "tags": ["path-traversal", "file-inclusion", "filesystem"],
        "cwe_ids": ["CWE-22", "CWE-23"],
        "owasp_ids": ["A03:2021"],
        "severity_context": "high",
        "content": """## Path Traversal Remediation

Path traversal allows attackers to access files outside the intended directory.

### Remediation Steps
1. Validate file paths against an allowlist of safe base directories
2. Use `os.path.realpath()` and check the prefix
3. Never pass user input directly to file system operations
4. Apply file system permissions as a defense-in-depth layer

### Secure File Access (Python)
```python
import os

BASE_DIR = "/var/app/uploads"

def safe_open(filename: str):
    safe_path = os.path.realpath(os.path.join(BASE_DIR, filename))
    if not safe_path.startswith(BASE_DIR):
        raise ValueError("Path traversal detected")
    return open(safe_path)
```
""",
    },
    {
        "title": "Secrets Management Best Practices",
        "category": ArticleCategory.BEST_PRACTICE,
        "tags": ["secrets", "credentials", "vault", "environment"],
        "cwe_ids": ["CWE-312", "CWE-798"],
        "owasp_ids": ["A02:2021"],
        "severity_context": "critical",
        "content": """## Secrets Management Best Practices

### Never
- Hardcode secrets in source code
- Commit `.env` files to version control
- Log secrets or put them in error messages
- Transmit secrets in URLs

### Always
- Use environment variables for secrets
- Use a secrets manager (Vault, AWS Secrets Manager, GCP Secret Manager)
- Rotate secrets regularly and on suspected compromise
- Use short-lived credentials where possible
- Add `.env` to `.gitignore`

### Pre-commit Hook to Prevent Secret Leaks
```bash
pip install detect-secrets
detect-secrets scan --baseline .secrets.baseline
```
""",
    },
    {
        "title": "Container Security Hardening",
        "category": ArticleCategory.BEST_PRACTICE,
        "tags": ["docker", "containers", "kubernetes", "hardening"],
        "cwe_ids": ["CWE-250"],
        "owasp_ids": ["A05:2021"],
        "severity_context": "medium",
        "content": """## Container Security Hardening

### Dockerfile Best Practices
1. Use minimal base images (distroless, alpine)
2. Run as non-root user
3. Use multi-stage builds to exclude build tools
4. Pin image versions with SHA digests
5. Scan images with Trivy or Grype

### Runtime Security
- Apply seccomp/AppArmor profiles
- Use read-only root filesystems
- Drop all Linux capabilities then add only required ones
- Never run privileged containers

### Example Secure Dockerfile
```dockerfile
FROM python:3.12-slim AS base
RUN addgroup --system app && adduser --system --group app
USER app
COPY --chown=app:app . /app
WORKDIR /app
CMD ["python", "main.py"]
```
""",
    },
    {
        "title": "Incident Response — Data Breach Playbook",
        "category": ArticleCategory.INCIDENT_RESPONSE,
        "tags": ["incident-response", "data-breach", "playbook", "forensics"],
        "cwe_ids": [],
        "owasp_ids": [],
        "severity_context": "critical",
        "content": """## Data Breach Incident Response Playbook

### Phase 1 — Identification (0-1 hour)
1. Confirm the breach is real (not a false positive)
2. Identify affected systems and data
3. Assemble the incident response team
4. Open incident ticket and begin timeline

### Phase 2 — Containment (1-4 hours)
1. Isolate affected systems
2. Revoke compromised credentials
3. Preserve forensic evidence (disk images, logs)
4. Block attacker's IP ranges / methods

### Phase 3 — Eradication (4-24 hours)
1. Remove malware / backdoors
2. Patch the exploited vulnerability
3. Reset all potentially compromised credentials

### Phase 4 — Recovery
1. Restore systems from clean backups
2. Verify systems are clean before returning to production
3. Increase monitoring

### Phase 5 — Post-Incident
1. Conduct root cause analysis
2. Update threat model
3. Notify affected parties and regulators as required
4. Update runbooks
""",
    },
    {
        "title": "SOC 2 Type II Compliance Checklist",
        "category": ArticleCategory.COMPLIANCE,
        "tags": ["soc2", "compliance", "audit", "controls"],
        "cwe_ids": [],
        "owasp_ids": [],
        "severity_context": None,
        "content": """## SOC 2 Type II Compliance Checklist

### Security (CC6)
- [ ] Access controls implemented and reviewed quarterly
- [ ] MFA enforced for all privileged access
- [ ] Encryption at rest and in transit
- [ ] Vulnerability management program active
- [ ] Security awareness training completed annually

### Availability (A1)
- [ ] Uptime SLA defined (99.9%+)
- [ ] Disaster recovery plan tested annually
- [ ] Capacity monitoring in place

### Confidentiality (C1)
- [ ] Data classification policy defined
- [ ] Sensitive data identified and protected
- [ ] Data retention and destruction policy

### Change Management
- [ ] All changes go through approved process
- [ ] Change records maintained
- [ ] Rollback procedures documented

### Incident Management
- [ ] Incident response plan documented and tested
- [ ] Incidents logged and tracked to resolution
""",
    },
]


# ---------------------------------------------------------------------------
# Knowledge Base
# ---------------------------------------------------------------------------


class SecurityKnowledgeBase:
    """SQLite FTS5-backed security knowledge base."""

    def __init__(self, db_path: str = "data/security_kb.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._seed_if_empty()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS articles (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    category TEXT NOT NULL,
                    tags TEXT NOT NULL DEFAULT '[]',
                    cwe_ids TEXT NOT NULL DEFAULT '[]',
                    owasp_ids TEXT NOT NULL DEFAULT '[]',
                    language TEXT,
                    framework TEXT,
                    severity_context TEXT,
                    version INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    author TEXT NOT NULL DEFAULT 'system',
                    org_id TEXT NOT NULL DEFAULT 'default'
                );

                CREATE TABLE IF NOT EXISTS article_versions (
                    id TEXT PRIMARY KEY,
                    article_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    category TEXT NOT NULL,
                    tags TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    author TEXT NOT NULL,
                    FOREIGN KEY (article_id) REFERENCES articles(id)
                );

                CREATE VIRTUAL TABLE IF NOT EXISTS articles_fts USING fts5(
                    id UNINDEXED,
                    title,
                    content,
                    tags,
                    cwe_ids,
                    owasp_ids,
                    category UNINDEXED,
                    content='articles',
                    content_rowid='rowid'
                );

                CREATE TRIGGER IF NOT EXISTS articles_ai AFTER INSERT ON articles BEGIN
                    INSERT INTO articles_fts(rowid, id, title, content, tags, cwe_ids, owasp_ids, category)
                    VALUES (new.rowid, new.id, new.title, new.content, new.tags, new.cwe_ids, new.owasp_ids, new.category);
                END;

                CREATE TRIGGER IF NOT EXISTS articles_ad AFTER DELETE ON articles BEGIN
                    INSERT INTO articles_fts(articles_fts, rowid, id, title, content, tags, cwe_ids, owasp_ids, category)
                    VALUES ('delete', old.rowid, old.id, old.title, old.content, old.tags, old.cwe_ids, old.owasp_ids, old.category);
                END;

                CREATE TRIGGER IF NOT EXISTS articles_au AFTER UPDATE ON articles BEGIN
                    INSERT INTO articles_fts(articles_fts, rowid, id, title, content, tags, cwe_ids, owasp_ids, category)
                    VALUES ('delete', old.rowid, old.id, old.title, old.content, old.tags, old.cwe_ids, old.owasp_ids, old.category);
                    INSERT INTO articles_fts(rowid, id, title, content, tags, cwe_ids, owasp_ids, category)
                    VALUES (new.rowid, new.id, new.title, new.content, new.tags, new.cwe_ids, new.owasp_ids, new.category);
                END;
            """)
            conn.commit()
        finally:
            conn.close()

    def _row_to_article(self, row: sqlite3.Row) -> Article:
        d = dict(row)
        d["tags"] = json.loads(d["tags"])
        d["cwe_ids"] = json.loads(d["cwe_ids"])
        d["owasp_ids"] = json.loads(d["owasp_ids"])
        return Article(**d)

    def _seed_if_empty(self) -> None:
        conn = self._connect()
        try:
            count = conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
        finally:
            conn.close()
        if count == 0:
            for seed in _SEED_ARTICLES:
                article = Article(
                    title=seed["title"],
                    content=seed["content"],
                    category=seed["category"],
                    tags=seed.get("tags", []),
                    cwe_ids=seed.get("cwe_ids", []),
                    owasp_ids=seed.get("owasp_ids", []),
                    severity_context=seed.get("severity_context"),
                    author="system",
                    org_id="default",
                )
                self.add_article(article)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add_article(self, article: Article) -> Article:
        """Persist a new article and return it."""
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO articles
                    (id, title, content, category, tags, cwe_ids, owasp_ids,
                     language, framework, severity_context, version,
                     created_at, updated_at, author, org_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    article.id,
                    article.title,
                    article.content,
                    article.category.value,
                    json.dumps(article.tags),
                    json.dumps(article.cwe_ids),
                    json.dumps(article.owasp_ids),
                    article.language,
                    article.framework,
                    article.severity_context,
                    article.version,
                    article.created_at.isoformat(),
                    article.updated_at.isoformat(),
                    article.author,
                    article.org_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return article

    def get_article(self, article_id: str) -> Article:
        """Return an article by ID; raises KeyError if not found."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM articles WHERE id = ?", (article_id,)
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            raise KeyError(f"Article not found: {article_id}")
        return self._row_to_article(row)

    def update_article(self, article_id: str, updates: Dict[str, Any]) -> Article:
        """Update article fields, increment version, archive old version."""
        current = self.get_article(article_id)

        # Archive current version
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO article_versions
                    (id, article_id, version, title, content, category, tags, updated_at, author)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    current.id,
                    current.version,
                    current.title,
                    current.content,
                    current.category.value,
                    json.dumps(current.tags),
                    current.updated_at.isoformat(),
                    current.author,
                ),
            )

            new_version = current.version + 1
            now = datetime.now(timezone.utc).isoformat()

            # Build SET clause dynamically from allowed fields
            allowed = {
                "title", "content", "category", "tags", "cwe_ids", "owasp_ids",
                "language", "framework", "severity_context", "author",
            }
            set_parts: List[str] = ["version = ?", "updated_at = ?"]
            params: List[Any] = [new_version, now]

            for key, val in updates.items():
                if key not in allowed:
                    continue
                if key == "category" and isinstance(val, ArticleCategory):
                    val = val.value
                if key in ("tags", "cwe_ids", "owasp_ids") and isinstance(val, list):
                    val = json.dumps(val)
                set_parts.append(f"{key} = ?")
                params.append(val)

            params.append(article_id)
            conn.execute(
                f"UPDATE articles SET {', '.join(set_parts)} WHERE id = ?",  # noqa: S608  # nosec B608
                params,
            )
            conn.commit()
        finally:
            conn.close()

        return self.get_article(article_id)

    def delete_article(self, article_id: str) -> None:
        """Delete an article and its version history."""
        conn = self._connect()
        try:
            conn.execute("DELETE FROM article_versions WHERE article_id = ?", (article_id,))
            conn.execute("DELETE FROM articles WHERE id = ?", (article_id,))
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Search & lookup
    # ------------------------------------------------------------------

    def search(
        self,
        query: str,
        category: Optional[ArticleCategory] = None,
        tags: Optional[List[str]] = None,
        limit: int = 20,
    ) -> List[SearchResult]:
        """FTS5 full-text search across title, content, tags, CWE/OWASP IDs."""
        conn = self._connect()
        try:
            # Sanitize query for FTS5 — escape special chars
            fts_query = " ".join(
                f'"{word}"' if any(c in word for c in '+-*:^()') else word
                for word in query.split()
                if word
            )
            if not fts_query:
                return []

            sql = """
                SELECT a.*, fts.rank
                FROM articles_fts fts
                JOIN articles a ON a.id = fts.id
                WHERE articles_fts MATCH ?
            """
            params: List[Any] = [fts_query]

            if category is not None:
                sql += " AND a.category = ?"
                params.append(category.value)

            sql += " ORDER BY fts.rank LIMIT ?"
            params.append(limit)

            rows = conn.execute(sql, params).fetchall()
        finally:
            conn.close()

        results: List[SearchResult] = []
        for row in rows:
            d = dict(row)
            # FTS5 rank is negative (lower = better match)
            score = float(abs(d.get("rank", 1.0) or 1.0))
            article_tags = json.loads(d["tags"])

            # Optional tag filter (post-filter)
            if tags:
                if not any(t in article_tags for t in tags):
                    continue

            results.append(
                SearchResult(
                    article_id=d["id"],
                    title=d["title"],
                    snippet=_make_snippet(d["content"], query),
                    relevance_score=score,
                    tags=article_tags,
                )
            )
        return results

    def get_by_cwe(self, cwe_id: str) -> List[Article]:
        """Return all articles that reference a given CWE ID."""
        conn = self._connect()
        try:
            rows = conn.execute("SELECT * FROM articles").fetchall()
        finally:
            conn.close()
        result: List[Article] = []
        for row in rows:
            cwe_ids = json.loads(row["cwe_ids"])
            if cwe_id in cwe_ids:
                result.append(self._row_to_article(row))
        return result

    def get_by_owasp(self, owasp_id: str) -> List[Article]:
        """Return all articles that reference a given OWASP category ID."""
        conn = self._connect()
        try:
            rows = conn.execute("SELECT * FROM articles").fetchall()
        finally:
            conn.close()
        result: List[Article] = []
        for row in rows:
            owasp_ids = json.loads(row["owasp_ids"])
            if owasp_id in owasp_ids:
                result.append(self._row_to_article(row))
        return result

    def get_for_finding(self, finding: Dict[str, Any]) -> List[Article]:
        """Return articles relevant to a finding, matched by CWE IDs, tags, or category."""
        matched: Dict[str, Article] = {}

        cwe_ids: List[str] = finding.get("cwe_ids", [])
        for cwe_id in cwe_ids:
            for art in self.get_by_cwe(cwe_id):
                matched[art.id] = art

        # Also try tags from the finding
        finding_tags: List[str] = finding.get("tags", [])
        if finding_tags:
            for tag in finding_tags:
                results = self.search(tag, limit=5)
                for r in results:
                    if r.article_id not in matched:
                        try:
                            matched[r.article_id] = self.get_article(r.article_id)
                        except KeyError:
                            pass

        # Category-based fallback
        if not matched:
            severity = finding.get("severity", "").lower()
            cat_map = {
                "critical": ArticleCategory.VULNERABILITY,
                "high": ArticleCategory.VULNERABILITY,
                "medium": ArticleCategory.BEST_PRACTICE,
                "low": ArticleCategory.BEST_PRACTICE,
            }
            cat = cat_map.get(severity)
            if cat:
                matched_list = self.list_articles(category=cat, limit=5)
                for art in matched_list:
                    matched[art.id] = art

        return list(matched.values())

    def list_articles(
        self,
        category: Optional[ArticleCategory] = None,
        tags: Optional[List[str]] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Article]:
        """List articles with optional category/tag filters."""
        conn = self._connect()
        try:
            sql = "SELECT * FROM articles"
            params: List[Any] = []
            if category is not None:
                sql += " WHERE category = ?"
                params.append(category.value)
            sql += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            rows = conn.execute(sql, params).fetchall()
        finally:
            conn.close()

        articles = [self._row_to_article(r) for r in rows]

        if tags:
            articles = [a for a in articles if any(t in a.tags for t in tags)]

        return articles

    def get_tags(self) -> List[str]:
        """Return all unique tags across all articles, sorted by frequency."""
        conn = self._connect()
        try:
            rows = conn.execute("SELECT tags FROM articles").fetchall()
        finally:
            conn.close()
        counter: Counter = Counter()
        for row in rows:
            for tag in json.loads(row["tags"]):
                counter[tag] += 1
        return [tag for tag, _ in counter.most_common()]

    def get_article_versions(self, article_id: str) -> List[Dict[str, Any]]:
        """Return version history for an article (oldest first)."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM article_versions WHERE article_id = ? ORDER BY version ASC",
                (article_id,),
            ).fetchall()
        finally:
            conn.close()
        versions = []
        for row in rows:
            d = dict(row)
            d["tags"] = json.loads(d["tags"])
            versions.append(d)
        return versions

    def get_kb_stats(self) -> Dict[str, Any]:
        """Return summary statistics about the knowledge base."""
        conn = self._connect()
        try:
            total = conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
            by_category_rows = conn.execute(
                "SELECT category, COUNT(*) as cnt FROM articles GROUP BY category"
            ).fetchall()
            all_tags_rows = conn.execute("SELECT tags FROM articles").fetchall()
        finally:
            conn.close()

        by_category = {row["category"]: row["cnt"] for row in by_category_rows}

        tag_counter: Counter = Counter()
        for row in all_tags_rows:
            for tag in json.loads(row["tags"]):
                tag_counter[tag] += 1

        return {
            "total_articles": total,
            "by_category": by_category,
            "top_tags": [tag for tag, _ in tag_counter.most_common(10)],
            "tag_count": len(tag_counter),
        }
