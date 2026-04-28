"""
ALdeci Sandbox PoC Verifier — Docker-isolated exploit verification.

Inspired by DeepAudit's Verification Agent pattern (AGPL-3.0 — clean-room reimplementation).
DeepAudit proved that Docker sandbox PoC execution can discover real CVEs (49 confirmed).

This module provides:
  1. Docker sandbox isolation for running PoC scripts
  2. Multi-language support (Python, Bash, Node.js, Go, curl-based)
  3. Self-correction: if PoC fails, auto-generates alternative approaches
  4. Integrates with MPTE Step 10 (AUTOFIX) and Brain Pipeline Step 9 (MICRO-PENTEST)
  5. Evidence collection with signed verification results

Cherry-picked concepts from DeepAudit (clean-room implemented):
  - Docker container isolation for PoC execution (DeepAudit: tools/sandbox.py)
  - Self-correction loop on failure (DeepAudit: agents/verification_agent.py)
  - Structured verification results with confidence scoring

Vision Pillars: V5 (MPTE Verification), V10 (CTEM Full Loop with Proof), V9 (Air-Gapped)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess  # nosec B404
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:
    _get_tg_bus = None  # type: ignore


def _tg_emit(event_type: str, payload: dict) -> None:
    try:
        if _get_tg_bus is None:
            return
        bus = _get_tg_bus()
        if bus:
            bus.emit(event_type, payload)
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════
# Data models
# ═══════════════════════════════════════════════════════════════════════════

class VerificationStatus(str, Enum):
    VERIFIED_EXPLOITABLE = "verified_exploitable"
    NOT_EXPLOITABLE = "not_exploitable"
    PARTIAL = "partial"            # Some conditions met, not fully exploitable
    TIMEOUT = "timeout"
    ERROR = "error"
    SANDBOX_UNAVAILABLE = "sandbox_unavailable"


class PoCLanguage(str, Enum):
    PYTHON = "python"
    BASH = "bash"
    NODEJS = "nodejs"
    CURL = "curl"
    GO = "go"


@dataclass
class PoCScript:
    """A proof-of-concept script to verify exploitability."""
    language: PoCLanguage
    code: str
    description: str = ""
    cve_id: str = ""
    target_url: str = ""
    expected_indicators: List[str] = field(default_factory=list)
    timeout_seconds: int = 30
    requires_network: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VerificationResult:
    """Result of a sandbox PoC verification."""
    verification_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: VerificationStatus = VerificationStatus.ERROR
    finding_id: str = ""
    cve_id: str = ""
    poc_language: str = ""
    exploitable: bool = False
    confidence: float = 0.0
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    execution_time_ms: float = 0.0
    indicators_matched: List[str] = field(default_factory=list)
    indicators_total: int = 0
    container_id: str = ""
    attempt: int = 1
    max_attempts: int = 3
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    evidence_hash: str = ""
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verification_id": self.verification_id,
            "status": self.status.value if isinstance(self.status, VerificationStatus) else self.status,
            "finding_id": self.finding_id,
            "cve_id": self.cve_id,
            "exploitable": self.exploitable,
            "confidence": self.confidence,
            "execution_time_ms": self.execution_time_ms,
            "indicators_matched": self.indicators_matched,
            "indicators_total": self.indicators_total,
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "timestamp": self.timestamp,
            "evidence_hash": self.evidence_hash,
            "exit_code": self.exit_code,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Sandbox Verifier Engine
# ═══════════════════════════════════════════════════════════════════════════

class SandboxVerifier:
    """
    Execute PoC scripts in Docker sandbox to verify exploit viability.

    Architecture:
      1. PoC script is written to a temp directory
      2. Docker container is launched with:
         - Read-only filesystem (except /tmp)
         - No network access (unless explicitly required)
         - Memory limit (128MB default)
         - CPU limit (0.5 cores)
         - Timeout enforcement
      3. Output is captured and analyzed
      4. Self-correction: if attempt fails with fixable error, script is adjusted and retried
      5. Evidence is hashed for cryptographic proof chain

    Safety:
      - Scripts run in ephemeral containers that are destroyed after execution
      - No host filesystem access beyond the script itself
      - Network is disabled by default (--network=none)
      - Resource limits prevent DoS
    """

    # Docker images per language (minimal, no extra packages)
    DOCKER_IMAGES = {
        PoCLanguage.PYTHON: "python:3.12-slim",
        PoCLanguage.BASH: "alpine:3.19",
        PoCLanguage.NODEJS: "node:20-slim",
        PoCLanguage.CURL: "alpine:3.19",
        PoCLanguage.GO: "golang:1.22-alpine",
    }

    # Script file extensions
    EXTENSIONS = {
        PoCLanguage.PYTHON: ".py",
        PoCLanguage.BASH: ".sh",
        PoCLanguage.NODEJS: ".js",
        PoCLanguage.CURL: ".sh",
        PoCLanguage.GO: ".go",
    }

    # Execution commands
    COMMANDS = {
        PoCLanguage.PYTHON: ["python3", "/poc/script.py"],
        PoCLanguage.BASH: ["sh", "/poc/script.sh"],
        PoCLanguage.NODEJS: ["node", "/poc/script.js"],
        PoCLanguage.CURL: ["sh", "/poc/script.sh"],
        PoCLanguage.GO: ["go", "run", "/poc/script.go"],
    }

    # Maximum PoC script size (bytes) — prevent DoS via huge scripts
    MAX_POC_SIZE = 64 * 1024  # 64 KB

    # Dangerous patterns blocked in PoC code (defense-in-depth beyond Docker isolation)
    _BLOCKED_PATTERNS = [
        r"import\s+os\s*;\s*os\.system",  # Direct OS command via import
        r"__import__\s*\(\s*['\"]os",  # Dynamic OS import
        r"subprocess\.call.*shell\s*=\s*True",  # Shell injection via subprocess
        r"eval\s*\(\s*input",  # Eval of user input
        r"exec\s*\(\s*input",  # Exec of user input
        r"/dev/sd[a-z]",  # Direct disk access
        r"mkfs\.",  # Filesystem formatting
        r"dd\s+if=",  # Raw disk I/O
        r":(){ :|:& };:",  # Fork bomb
        r"\bkill\s+-9\s+1\b",  # Kill init
        r"rm\s+-rf\s+/[^t]",  # rm -rf / (except /tmp)
    ]

    def __init__(
        self,
        memory_limit: str = "128m",
        cpu_limit: float = 0.5,
        max_attempts: int = 3,
        docker_available: Optional[bool] = None,
    ):
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.max_attempts = max_attempts
        self._docker_available = docker_available
        self._results_store: List[VerificationResult] = []
        # Compile blocked patterns once
        import re
        self._compiled_blocks = [
            re.compile(p, re.IGNORECASE) for p in self._BLOCKED_PATTERNS
        ]

    @property
    def docker_available(self) -> bool:
        """Check if Docker is available on this system."""
        if self._docker_available is not None:
            return self._docker_available
        try:
            result = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True, text=True, timeout=5,
            )
            self._docker_available = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self._docker_available = False
        return self._docker_available

    def _validate_poc_code(self, code: str, poc: PoCScript) -> Optional[str]:
        """Validate PoC code for safety before execution.

        Returns error message if code is rejected, None if OK.
        Defense-in-depth: Docker isolation is the primary control,
        but this catches obviously malicious payloads early.
        """
        # Size limit
        if len(code) > self.MAX_POC_SIZE:
            return f"PoC script exceeds size limit ({len(code)} > {self.MAX_POC_SIZE} bytes)"

        # Empty code
        if not code.strip():
            return "PoC script is empty"

        # Blocked patterns
        for pattern in self._compiled_blocks:
            if pattern.search(code):
                return f"PoC contains blocked pattern: {pattern.pattern[:40]}..."

        return None

    def verify(
        self,
        poc: PoCScript,
        finding_id: str = "",
    ) -> VerificationResult:
        """
        Execute a PoC script in a Docker sandbox and return verification result.

        Self-correction loop: up to max_attempts with error analysis between attempts.
        """
        if not self.docker_available:
            return VerificationResult(
                status=VerificationStatus.SANDBOX_UNAVAILABLE,
                finding_id=finding_id,
                cve_id=poc.cve_id,
                error_message="Docker not available. Install Docker for sandbox verification.",
            )

        # Validate PoC code before execution
        validation_err = self._validate_poc_code(poc.code, poc)
        if validation_err:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                finding_id=finding_id,
                cve_id=poc.cve_id,
                error_message=f"PoC rejected: {validation_err}",
            )

        last_result = None
        current_code = poc.code

        for attempt in range(1, self.max_attempts + 1):
            result = self._execute_in_sandbox(
                poc=poc,
                code_override=current_code,
                finding_id=finding_id,
                attempt=attempt,
            )
            last_result = result

            # If successful or not fixable, stop
            if result.status == VerificationStatus.VERIFIED_EXPLOITABLE:
                break
            if result.status == VerificationStatus.TIMEOUT:
                break
            if attempt >= self.max_attempts:
                break

            # Self-correction: analyze failure and try to fix
            corrected = self._self_correct(poc, current_code, result)
            if corrected and corrected != current_code:
                # Re-validate corrected code — self-correction must not bypass safety
                corr_err = self._validate_poc_code(corrected, poc)
                if corr_err:
                    logger.warning(
                        "Self-corrected PoC rejected: %s (cve=%s)", corr_err, poc.cve_id
                    )
                    break
                logger.info("Self-correcting PoC (attempt %d): %s", attempt + 1, poc.cve_id)
                current_code = corrected
            else:
                break  # No correction possible

        # Store result
        if last_result:
            self._results_store.append(last_result)

        final = last_result or VerificationResult(
            status=VerificationStatus.ERROR,
            finding_id=finding_id,
            error_message="No execution attempted",
        )
        _tg_emit("sandbox_verifier.verification_complete", {
            "finding_id": finding_id,
            "status": final.status.value if hasattr(final.status, "value") else str(final.status),
            "cve_id": poc.cve_id,
        })
        return final

    def _execute_in_sandbox(
        self,
        poc: PoCScript,
        code_override: str,
        finding_id: str,
        attempt: int,
    ) -> VerificationResult:
        """Execute a single PoC attempt in Docker sandbox."""
        result = VerificationResult(
            finding_id=finding_id,
            cve_id=poc.cve_id,
            poc_language=poc.language.value if isinstance(poc.language, PoCLanguage) else poc.language,
            attempt=attempt,
            max_attempts=self.max_attempts,
        )

        tmpdir = tempfile.mkdtemp(prefix="aldeci_poc_")
        os.chmod(tmpdir, 0o700)  # Restrict to owner only  # nosemgrep: insecure-file-permissions
        try:
            # Write script to temp directory with restrictive permissions
            ext = self.EXTENSIONS.get(poc.language, ".sh")
            script_path = os.path.join(tmpdir, f"script{ext}")
            with open(script_path, "w") as f:
                f.write(code_override)
            os.chmod(script_path, 0o700)  # Owner-only execute (not world-readable)  # nosemgrep: insecure-file-permissions

            # Build docker command
            image = self.DOCKER_IMAGES.get(poc.language, "alpine:3.19")
            cmd = self.COMMANDS.get(poc.language, ["sh", f"/poc/script{ext}"])

            docker_cmd = [
                "docker", "run", "--rm",
                "--user", "65534:65534",  # Run as nobody — never root in container
                "--memory", self.memory_limit,
                "--memory-swap", self.memory_limit,  # Prevent swap usage
                f"--cpus={self.cpu_limit}",
                "--cap-drop=ALL",  # Drop all Linux capabilities
                "--read-only",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",  # nosec B108
                "-v", f"{tmpdir}:/poc:ro",
                "--security-opt", "no-new-privileges",
                "--pids-limit", "30",  # Reduced from 50
                "--ulimit", "nofile=256:256",  # Limit open file descriptors
            ]

            # Network control
            if not poc.requires_network:
                docker_cmd.extend(["--network", "none"])

            docker_cmd.append(image)
            docker_cmd.extend(cmd)

            # Execute with timeout
            t0 = time.time()
            try:
                proc = subprocess.run(
                    docker_cmd,
                    capture_output=True,
                    text=True,
                    timeout=poc.timeout_seconds,
                )
                result.stdout = proc.stdout[:5000]
                result.stderr = proc.stderr[:5000]
                result.exit_code = proc.returncode
            except subprocess.TimeoutExpired:
                result.status = VerificationStatus.TIMEOUT
                result.error_message = f"Timeout after {poc.timeout_seconds}s"
                return result
            except FileNotFoundError:
                result.status = VerificationStatus.ERROR
                result.error_message = "Docker runtime not found"
                return result
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
                result.status = VerificationStatus.ERROR
                # Only expose exception type, not message (may leak paths/secrets)
                result.error_message = f"Execution error: {type(e).__name__}"
                logger.error("Sandbox execution failed: %s", e, exc_info=True)
                return result

            result.execution_time_ms = round((time.time() - t0) * 1000, 1)

            # Analyze output for exploitation indicators
            result = self._analyze_output(result, poc)

            # Generate evidence hash
            evidence_payload = json.dumps({
                "verification_id": result.verification_id,
                "cve_id": poc.cve_id,
                "finding_id": finding_id,
                "status": result.status.value,
                "stdout_hash": hashlib.sha256(result.stdout.encode()).hexdigest(),
                "timestamp": result.timestamp,
            }, sort_keys=True)
            result.evidence_hash = hashlib.sha256(evidence_payload.encode()).hexdigest()

        finally:
            # Clean up temp directory
            shutil.rmtree(tmpdir, ignore_errors=True)

        return result

    def _analyze_output(self, result: VerificationResult, poc: PoCScript) -> VerificationResult:
        """Analyze PoC output to determine exploitability."""
        combined_output = (result.stdout + result.stderr).lower()

        # Check expected indicators
        matched = []
        for indicator in poc.expected_indicators:
            if indicator.lower() in combined_output:
                matched.append(indicator)
        result.indicators_matched = matched
        result.indicators_total = len(poc.expected_indicators)

        # Determine exploitability
        if poc.expected_indicators:
            match_ratio = len(matched) / len(poc.expected_indicators)
            if match_ratio >= 0.8:
                result.status = VerificationStatus.VERIFIED_EXPLOITABLE
                result.exploitable = True
                result.confidence = min(0.95, match_ratio)
            elif match_ratio >= 0.4:
                result.status = VerificationStatus.PARTIAL
                result.exploitable = False
                result.confidence = match_ratio * 0.8
            else:
                result.status = VerificationStatus.NOT_EXPLOITABLE
                result.exploitable = False
                result.confidence = 1.0 - match_ratio
        else:
            # No explicit indicators — use exit code heuristic
            if result.exit_code == 0:
                # Generic success indicators
                success_words = ["vulnerable", "exploitable", "success", "confirmed", "pwned", "injected", "rce"]
                found = [w for w in success_words if w in combined_output]
                if found:
                    result.status = VerificationStatus.VERIFIED_EXPLOITABLE
                    result.exploitable = True
                    result.confidence = min(0.85, 0.5 + len(found) * 0.1)
                    result.indicators_matched = found
                else:
                    result.status = VerificationStatus.PARTIAL
                    result.confidence = 0.5
            else:
                result.status = VerificationStatus.NOT_EXPLOITABLE
                result.confidence = 0.7

        return result

    def _self_correct(
        self,
        poc: PoCScript,
        current_code: str,
        failed_result: VerificationResult,
    ) -> Optional[str]:
        """
        Analyze a failed PoC execution and attempt to generate a corrected script.

        Self-correction patterns (inspired by DeepAudit's verification agent):
        1. ModuleNotFoundError → add pip install to script header
        2. Connection refused → add retry with delay
        3. Permission denied → adjust file paths to /tmp
        4. Syntax errors → attempt trivial fixes
        """
        stderr = failed_result.stderr.lower()

        # Pattern 1: Missing Python module — HARDENED: whitelist only safe packages
        _SAFE_MODULES = frozenset({
            "requests", "urllib3", "httpx", "aiohttp", "pycurl",
            "paramiko", "cryptography", "pyjwt", "jwt",
            "beautifulsoup4", "bs4", "lxml", "html5lib",
            "pyyaml", "toml", "configparser",
            "dnspython", "scapy", "impacket", "nmap",
        })
        if "modulenotfounderror" in stderr or "no module named" in stderr:
            import re
            match = re.search(r"no module named ['\"]?(\w+)", stderr)
            if match and poc.language == PoCLanguage.PYTHON:
                module = match.group(1).lower()
                if module not in _SAFE_MODULES:
                    logger.warning(
                        "Self-correction rejected: module '%s' not in whitelist", module
                    )
                    return None
                # Use shlex.quote for safety even though we validate above
                import shlex
                safe_module = shlex.quote(module)
                pip_line = f"import subprocess; subprocess.check_call(['pip', 'install', {safe_module!r}, '-q'])\n"
                return pip_line + current_code

        # Pattern 2: Connection refused — add retry
        if "connection refused" in stderr or "errno 111" in stderr:
            if poc.language == PoCLanguage.PYTHON and "import time" not in current_code:
                retry_wrapper = (
                    "import time\n"
                    "for _retry in range(3):\n"
                    "    try:\n"
                    f"        {current_code.replace(chr(10), chr(10) + '        ')}\n"
                    "        break\n"
                    "    except ConnectionRefusedError:\n"
                    "        time.sleep(2)\n"
                )
                return retry_wrapper

        # Pattern 3: Permission denied — redirect to /tmp
        if "permission denied" in stderr:
            return current_code.replace("/var/", "/tmp/var/").replace("/etc/", "/tmp/etc/")  # nosec B108

        # Pattern 4: Command not found in bash — HARDENED: whitelist safe commands
        _SAFE_COMMANDS = frozenset({
            "curl", "wget", "nmap", "nc", "netcat", "ncat",
            "openssl", "dig", "nslookup", "host",
            "jq", "xmlstarlet", "python3", "perl",
            "ssh", "scp", "nikto", "sqlmap",
        })
        if "command not found" in stderr and poc.language in (PoCLanguage.BASH, PoCLanguage.CURL):
            import re
            match = re.search(r"(\w+): (command )?not found", stderr)
            if match:
                missing_cmd = match.group(1).lower()
                if missing_cmd not in _SAFE_COMMANDS:
                    logger.warning(
                        "Self-correction rejected: command '%s' not in whitelist",
                        missing_cmd,
                    )
                    return None
                import shlex
                install_line = f"apk add --no-cache {shlex.quote(missing_cmd)} 2>/dev/null || true\n"
                return install_line + current_code

        return None

    def verify_finding(
        self,
        finding: Dict[str, Any],
        target_url: str = "",
    ) -> VerificationResult:
        """
        Generate and execute a PoC for a specific finding.

        Auto-generates a basic PoC script based on the finding's CVE/CWE.
        For complex exploits, provide a custom PoCScript via verify().
        """
        cve_id = finding.get("cve_id", "")
        cwe_id = finding.get("cwe_id", "")
        title = finding.get("title", "")
        url = target_url or finding.get("file_path", "")

        poc = self._generate_basic_poc(cve_id, cwe_id, title, url)
        return self.verify(poc, finding_id=finding.get("id", ""))

    @staticmethod
    def _sanitize_template_str(s: str, max_len: int = 200) -> str:
        """Sanitize a string before embedding in a PoC code template.

        Prevents shell/code injection when user-controlled values (CVE IDs,
        titles, URLs) are interpolated into generated scripts.

        Defense-in-depth: _validate_poc_code catches many patterns, but
        preventing injection at the template level is safer.
        """
        import re as _re
        if not s:
            return ""
        # Truncate first
        s = s[:max_len]
        # Remove characters that could break out of strings or inject commands
        # Allow: alphanumeric, spaces, hyphens, dots, colons, slashes, underscores, =, ?, &, #, @, %
        s = _re.sub(r"[^a-zA-Z0-9 \-\./:_=?&#@%+,]", "", s)
        return s

    def _generate_basic_poc(
        self, cve_id: str, cwe_id: str, title: str, target_url: str
    ) -> PoCScript:
        """Generate a basic PoC script based on CWE category.

        SECURITY: All user-controlled values are sanitized before embedding
        in code templates to prevent shell/code injection.
        """
        # Sanitize all user-controlled inputs before template embedding
        cve_id = self._sanitize_template_str(cve_id, max_len=30)
        title = self._sanitize_template_str(title, max_len=120)
        target_url = self._sanitize_template_str(target_url, max_len=2048)

        cwe_num = ""
        if cwe_id:
            import re
            m = re.search(r"\d+", cwe_id)
            cwe_num = m.group(0) if m else ""

        # CWE-based PoC templates
        if cwe_num in ("79", "80"):  # XSS
            return PoCScript(
                language=PoCLanguage.CURL,
                code=f"""#!/bin/sh
echo "Testing for XSS: {cve_id or title}"
# Inject test payloads
PAYLOAD='<script>alert(1)</script>'
RESPONSE=$(curl -s -o /dev/null -w "%{{http_code}}" "{target_url}?q=$PAYLOAD" 2>/dev/null || echo "000")
echo "HTTP Status: $RESPONSE"
if echo "$RESPONSE" | grep -q "200"; then
    echo "VULNERABLE: Server accepted XSS payload"
else
    echo "NOT_VULNERABLE: Server rejected payload"
fi
""",
                description=f"XSS verification for {cve_id}",
                cve_id=cve_id,
                target_url=target_url,
                expected_indicators=["VULNERABLE"],
                requires_network=True,
            )

        elif cwe_num in ("89",):  # SQL Injection
            return PoCScript(
                language=PoCLanguage.PYTHON,
                code=f"""import urllib.request, urllib.parse
print("Testing for SQL Injection: {cve_id or title}")
target = "{target_url}"
payloads = ["' OR '1'='1", "1; DROP TABLE test--", "' UNION SELECT NULL--"]
for payload in payloads:
    try:
        url = f"{{target}}?id={{urllib.parse.quote(payload)}}"
        req = urllib.request.Request(url, headers={{"User-Agent": "ALdeci-MPTE/1.0"}})
        resp = urllib.request.urlopen(req, timeout=5)
        body = resp.read().decode("utf-8", errors="ignore")
        if "error" in body.lower() or "sql" in body.lower() or resp.status == 200:
            print(f"VULNERABLE: SQL injection indicator with payload: {{payload[:20]}}")
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
        print(f"Error: {{e}}")
print("Verification complete")
""",
                description=f"SQLi verification for {cve_id}",
                cve_id=cve_id,
                target_url=target_url,
                expected_indicators=["VULNERABLE"],
                requires_network=True,
            )

        elif cwe_num in ("78", "77"):  # Command Injection
            return PoCScript(
                language=PoCLanguage.BASH,
                code=f"""#!/bin/sh
echo "Testing for Command Injection: {cve_id or title}"
# Safe detection — only checks if injection is possible, does NOT execute harmful commands
PAYLOAD='; echo ALDECI_CANARY_12345'
RESPONSE=$(curl -s "{target_url}" -d "cmd=$PAYLOAD" 2>/dev/null || echo "")
if echo "$RESPONSE" | grep -q "ALDECI_CANARY_12345"; then
    echo "VULNERABLE: Command injection confirmed"
else
    echo "NOT_VULNERABLE: No command injection detected"
fi
""",
                description=f"Command Injection verification for {cve_id}",
                cve_id=cve_id,
                target_url=target_url,
                expected_indicators=["VULNERABLE"],
                requires_network=True,
            )

        else:
            # Generic availability/response check
            return PoCScript(
                language=PoCLanguage.PYTHON,
                code=f"""import urllib.request
print("Generic vulnerability check: {cve_id or title}")
target = "{target_url}"
if target:
    try:
        req = urllib.request.Request(target, headers={{"User-Agent": "ALdeci-MPTE/1.0"}})
        resp = urllib.request.urlopen(req, timeout=10)
        print(f"Target reachable: HTTP {{resp.status}}")
        headers = dict(resp.getheaders())
        # Check security headers
        missing = []
        for h in ["X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options"]:
            if h not in headers:
                missing.append(h)
        if missing:
            print(f"VULNERABLE: Missing security headers: {{', '.join(missing)}}")
        else:
            print("NOT_VULNERABLE: Security headers present")
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
        print(f"Error reaching target: {{e}}")
else:
    print("No target URL provided — static analysis only")
    print("NOT_VULNERABLE: Cannot verify without target")
""",
                description=f"Generic verification for {cve_id}",
                cve_id=cve_id,
                target_url=target_url,
                expected_indicators=["VULNERABLE", "Missing security headers"],
                requires_network=True,
            )

    def get_results(self) -> List[Dict[str, Any]]:
        """Return all stored verification results."""
        return [r.to_dict() for r in self._results_store]

    def get_stats(self) -> Dict[str, Any]:
        """Return verification statistics."""
        total = len(self._results_store)
        if total == 0:
            return {"total": 0}
        exploitable = sum(1 for r in self._results_store if r.exploitable)
        return {
            "total_verifications": total,
            "exploitable": exploitable,
            "not_exploitable": total - exploitable,
            "exploitable_rate": round(exploitable / total, 3) if total else 0,
            "avg_execution_ms": round(sum(r.execution_time_ms for r in self._results_store) / total, 1),
            "by_status": {
                s.value: sum(1 for r in self._results_store if r.status == s)
                for s in VerificationStatus
            },
            "docker_available": self.docker_available,
        }

    def sandbox_verify_findings(
        self,
        findings: List[Dict[str, Any]],
        target_urls: List[str],
        *,
        max_findings: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Verify a batch of MPTE findings by running PoCs in sandbox.

        Used by _run_builtin_vulnerability_scan to add sandbox-verified evidence
        to confirmed-vulnerable findings.  Only HIGH/CRITICAL findings are selected
        to keep the scan time reasonable.

        Returns a list of dicts: { finding_index, verification_result }.
        """
        verified: List[Dict[str, Any]] = []
        candidates = [
            (i, f) for i, f in enumerate(findings)
            if f.get("severity", "").lower() in ("high", "critical")
            or f.get("vulnerable", False)
        ]
        # Cap to avoid long-running sandbox sessions
        candidates = candidates[:max_findings]

        for idx, finding in candidates:
            target = finding.get("target", finding.get("target_url", ""))
            if not target and target_urls:
                target = target_urls[0]
            result = self.verify_finding(finding, target_url=target)
            verified.append({
                "finding_index": idx,
                "title": finding.get("title", finding.get("cve_id", "unknown")),
                "verification": result.to_dict(),
            })

        return verified


# ═══════════════════════════════════════════════════════════════════════════
# Sandboxed Reachability Probe
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ReachabilityResult:
    """Result of a sandboxed reachability probe."""
    target: str = ""
    reachable: bool = False
    method: str = "sandboxed_probe"
    latency_ms: float = 0.0
    http_status: Optional[int] = None
    open_ports: List[int] = field(default_factory=list)
    tls_valid: Optional[bool] = None
    server_header: str = ""
    confidence: float = 0.0
    error: str = ""
    evidence_hash: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "target": self.target,
            "reachable": self.reachable,
            "method": self.method,
            "latency_ms": self.latency_ms,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }
        if self.http_status is not None:
            d["http_status"] = self.http_status
        if self.open_ports:
            d["open_ports"] = self.open_ports
        if self.tls_valid is not None:
            d["tls_valid"] = self.tls_valid
        if self.server_header:
            d["server_header"] = self.server_header
        if self.error:
            d["error"] = self.error
        if self.evidence_hash:
            d["evidence_hash"] = self.evidence_hash
        return d


class SandboxedReachabilityProbe:
    """
    Run reachability checks inside a Docker sandbox.

    Instead of making network requests from the host process (risk: SSRF,
    host IP exposure, firewall bypass), all probes run inside ephemeral
    Docker containers with:
      - Network access enabled (required for probes)
      - Read-only filesystem
      - 64MB memory / 0.25 CPU
      - 15-second timeout per target
      - No privilege escalation

    Probe script performs:
      1. TCP connect to target port (80/443/custom)
      2. HTTP/HTTPS HEAD request with redirect follow
      3. TLS certificate validation
      4. Common port scan (top 10 ports)
      5. Server header extraction

    Vision Pillars: V5 (MPTE), V9 (Air-Gapped — uses stdlib curl/wget), V10 (Evidence)
    """

    PROBE_SCRIPT = '''#!/bin/sh
set -e
TARGET="$1"
echo "PROBE_START"
echo "target=$TARGET"

# Extract host and port from URL
HOST=$(echo "$TARGET" | sed -E 's|https?://||' | cut -d'/' -f1 | cut -d':' -f1)
PORT=$(echo "$TARGET" | sed -E 's|https?://||' | cut -d'/' -f1 | grep -oE ':[0-9]+' | tr -d ':')
SCHEME=$(echo "$TARGET" | grep -oE '^https?' || echo "http")

if [ -z "$PORT" ]; then
    if [ "$SCHEME" = "https" ]; then PORT=443; else PORT=80; fi
fi

# 1. TCP connect test
echo "=== TCP_CONNECT ==="
T0=$(date +%s%N 2>/dev/null || date +%s)
if nc -z -w 5 "$HOST" "$PORT" 2>/dev/null; then
    T1=$(date +%s%N 2>/dev/null || date +%s)
    echo "tcp_reachable=true"
    echo "tcp_port=$PORT"
else
    echo "tcp_reachable=false"
    echo "tcp_port=$PORT"
fi

# 2. HTTP HEAD request
echo "=== HTTP_HEAD ==="
HTTP_OUT=$(wget --spider -S -T 5 -t 1 "$TARGET" 2>&1 || true)
HTTP_STATUS=$(echo "$HTTP_OUT" | grep -oE 'HTTP/[0-9.]+ [0-9]+' | tail -1 | grep -oE '[0-9]+$' || echo "0")
SERVER=$(echo "$HTTP_OUT" | grep -i "^  Server:" | head -1 | sed 's/^  Server: //' || echo "")
echo "http_status=$HTTP_STATUS"
echo "server=$SERVER"

# 3. TLS check (only for https)
if [ "$SCHEME" = "https" ]; then
    echo "=== TLS_CHECK ==="
    if echo | timeout 5 openssl s_client -connect "$HOST:$PORT" -servername "$HOST" 2>/dev/null | grep -q "Verify return code: 0"; then
        echo "tls_valid=true"
    else
        echo "tls_valid=false"
    fi
fi

# 4. Top-port scan (fast — 10 common ports)
echo "=== PORT_SCAN ==="
for P in 22 80 443 8080 8443 3306 5432 6379 27017 9200; do
    if nc -z -w 2 "$HOST" "$P" 2>/dev/null; then
        echo "open_port=$P"
    fi
done

echo "PROBE_END"
'''

    def __init__(
        self,
        memory_limit: str = "64m",
        cpu_limit: float = 0.25,
        timeout: int = 20,
        docker_available: Optional[bool] = None,
    ):
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.timeout = timeout
        self._docker_available = docker_available

    @property
    def docker_available(self) -> bool:
        if self._docker_available is not None:
            return self._docker_available
        try:
            result = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True, text=True, timeout=5,
            )
            self._docker_available = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self._docker_available = False
        return self._docker_available

    def probe(self, target: str) -> ReachabilityResult:
        """
        Run a sandboxed reachability probe against a single target.
        Returns structured ReachabilityResult with evidence hash.
        """
        result = ReachabilityResult(target=target)

        if not self.docker_available:
            result.method = "sandbox_unavailable"
            result.error = "Docker not available for sandboxed probes"
            return result

        tmpdir = tempfile.mkdtemp(prefix="aldeci_probe_")
        try:
            # Write probe script
            script_path = os.path.join(tmpdir, "probe.sh")
            with open(script_path, "w") as f:
                f.write(self.PROBE_SCRIPT)
            os.chmod(script_path, 0o700)  # nosemgrep: insecure-file-permissions

            docker_cmd = [
                "docker", "run", "--rm",
                "--memory", self.memory_limit,
                f"--cpus={self.cpu_limit}",
                "--read-only",
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",  # nosec B108
                "-v", f"{tmpdir}:/probe:ro",
                "--security-opt", "no-new-privileges",
                "--pids-limit", "30",
                # Network ENABLED for reachability probes
                "alpine:3.19",
                "sh", "/probe/probe.sh", target,
            ]

            t0 = time.time()
            try:
                proc = subprocess.run(
                    docker_cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                )
                output = proc.stdout
                result.latency_ms = round((time.time() - t0) * 1000, 1)
            except subprocess.TimeoutExpired:
                result.error = f"Probe timeout after {self.timeout}s"
                return result
            except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
                result.error = str(e)
                return result

            # Parse structured output
            result = self._parse_probe_output(output, result)

            # Generate evidence hash
            evidence = json.dumps({
                "target": target,
                "reachable": result.reachable,
                "http_status": result.http_status,
                "open_ports": result.open_ports,
                "timestamp": result.timestamp,
            }, sort_keys=True)
            result.evidence_hash = hashlib.sha256(evidence.encode()).hexdigest()

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        return result

    def probe_multiple(self, targets: List[str]) -> List[ReachabilityResult]:
        """Probe multiple targets sequentially."""
        return [self.probe(t) for t in targets]

    def _parse_probe_output(self, output: str, result: ReachabilityResult) -> ReachabilityResult:
        """Parse the structured output from the probe shell script."""
        lines = output.strip().splitlines()
        open_ports: List[int] = []

        for line in lines:
            line = line.strip()
            if line.startswith("tcp_reachable=true"):
                result.reachable = True
                result.confidence = 0.9
            elif line.startswith("tcp_reachable=false"):
                result.reachable = False
                result.confidence = 0.8
            elif line.startswith("http_status="):
                try:
                    status = int(line.split("=", 1)[1])
                    result.http_status = status if status > 0 else None
                    if 200 <= status < 500:
                        result.reachable = True
                        result.confidence = 0.95
                except ValueError:
                    pass
            elif line.startswith("server="):
                result.server_header = line.split("=", 1)[1].strip()
            elif line.startswith("tls_valid=true"):
                result.tls_valid = True
            elif line.startswith("tls_valid=false"):
                result.tls_valid = False
            elif line.startswith("open_port="):
                try:
                    open_ports.append(int(line.split("=", 1)[1]))
                except ValueError:
                    pass

        result.open_ports = open_ports
        return result


# ═══════════════════════════════════════════════════════════════════════════
# FastAPI Router for Sandbox Verification
# ═══════════════════════════════════════════════════════════════════════════

class PoCRequest(BaseModel):
    """Request model for PoC verification."""
    language: str = Field(default="python", description="Script language: python, bash, nodejs, curl, go")
    code: str = Field(..., description="PoC script code")
    cve_id: str = Field(default="", description="CVE identifier")
    target_url: str = Field(default="", description="Target URL for network-based PoCs")
    expected_indicators: list[str] = Field(default_factory=list, description="Strings expected in output if exploitable")
    timeout_seconds: int = Field(default=30, ge=5, le=120)
    requires_network: bool = Field(default=False)
    finding_id: str = Field(default="")


class FindingVerifyRequest(BaseModel):
    """Request model for finding verification."""
    finding: dict[str, Any] = Field(..., description="Finding object to verify")
    target_url: str = Field(default="", description="Target URL")


class ReachabilityProbeRequest(BaseModel):
    """Request model for reachability probing."""
    targets: list[str] = Field(..., description="Target URLs or host:port to probe")
    cve_id: str = Field(default="", description="CVE being checked for reachability")
    asset_ids: list[str] = Field(default_factory=list, description="Asset IDs for correlation")


def create_sandbox_router():
    """Create a FastAPI router for sandbox verification endpoints."""
    from fastapi import APIRouter, HTTPException

    sandbox_router = APIRouter(
        prefix="/api/v1/sandbox",
        tags=["sandbox-verification"],
    )

    _verifier = SandboxVerifier()

    @sandbox_router.post("/verify")
    async def run_poc_verification(req: PoCRequest):
        """Execute a PoC script in Docker sandbox and return verification result."""
        try:
            lang = PoCLanguage(req.language.lower())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Unsupported language: {req.language}")

        poc = PoCScript(
            language=lang,
            code=req.code,
            cve_id=req.cve_id,
            target_url=req.target_url,
            expected_indicators=req.expected_indicators,
            timeout_seconds=req.timeout_seconds,
            requires_network=req.requires_network,
        )
        result = _verifier.verify(poc, finding_id=req.finding_id)
        return result.to_dict()

    @sandbox_router.post("/verify-finding")
    async def verify_finding(req: FindingVerifyRequest):
        """Auto-generate and execute a PoC based on finding CVE/CWE."""
        result = _verifier.verify_finding(req.finding, target_url=req.target_url)
        return result.to_dict()

    @sandbox_router.get("/results")
    async def get_results():
        """Return all verification results from this session."""
        return {"results": _verifier.get_results(), "count": len(_verifier._results_store)}

    @sandbox_router.get("/stats")
    async def get_stats():
        """Return sandbox verification statistics."""
        return _verifier.get_stats()

    @sandbox_router.get("/health")
    async def sandbox_health():
        """Check Docker sandbox availability."""
        return {
            "docker_available": _verifier.docker_available,
            "memory_limit": _verifier.memory_limit,
            "cpu_limit": _verifier.cpu_limit,
            "max_attempts": _verifier.max_attempts,
        }

    @sandbox_router.get("/status")
    async def sandbox_status():
        """Status alias for Docker sandbox (mirrors /health)."""
        return {
            "status": "operational" if _verifier.docker_available else "degraded",
            "engine": "sandbox-verifier",
            "version": "1.0.0",
            "docker_available": _verifier.docker_available,
            "memory_limit": _verifier.memory_limit,
            "cpu_limit": _verifier.cpu_limit,
            "max_attempts": _verifier.max_attempts,
        }

    # ── Sandboxed Reachability Endpoints ────────────────────────────

    _probe = SandboxedReachabilityProbe()

    @sandbox_router.post("/reachability")
    async def sandboxed_reachability(req: ReachabilityProbeRequest):
        """Run reachability probes inside Docker sandbox.

        Instead of probing from the host (SSRF risk), all network checks
        run in ephemeral Docker containers with resource limits.
        """
        if not _probe.docker_available:
            return {
                "status": "sandbox_unavailable",
                "cve_id": req.cve_id,
                "error": "Docker not available — install Docker for sandboxed reachability",
                "results": [],
            }

        results = _probe.probe_multiple(req.targets)
        result_dicts = [r.to_dict() for r in results]

        # Correlate with asset_ids if provided
        if req.asset_ids:
            for i, rd in enumerate(result_dicts):
                if i < len(req.asset_ids):
                    rd["asset_id"] = req.asset_ids[i]

        return {
            "status": "analyzed",
            "cve_id": req.cve_id,
            "source": "sandboxed_probe",
            "targets_probed": len(req.targets),
            "reachable_count": sum(1 for r in results if r.reachable),
            "results": result_dicts,
        }

    @sandbox_router.post("/reachability/single")
    async def sandboxed_reachability_single(target: str):
        """Probe a single target URL from Docker sandbox."""
        result = _probe.probe(target)
        return result.to_dict()

    return sandbox_router
