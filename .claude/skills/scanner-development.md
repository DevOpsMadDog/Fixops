# Skill: Scanner Development — Hardening & Extending 8 Native Scanners

> How to harden existing scanners and add new scanner capabilities to ALdeci's native engine suite.

## The 8 Native Scanners

| Scanner | Engine File | LOC | What It Scans |
|---------|-------------|-----|---------------|
| **SAST** | `suite-core/core/sast_engine.py` | 465 | Source code patterns (injection, XSS, etc.) |
| **DAST** | `suite-core/core/dast_engine.py` | 533 | Running apps (HTTP probes) |
| **Secrets** | `suite-core/core/secrets_scanner.py` | 775 | Hardcoded credentials, API keys, tokens |
| **Container** | `suite-core/core/container_scanner.py` | 410 | Docker images (layers, packages, configs) |
| **CSPM/IaC** | `suite-core/core/cspm_engine.py` | 586 | Terraform, CloudFormation, K8s manifests |
| **API Fuzzer** | `suite-attack/api/api_fuzzer_router.py` | ~200 | API endpoints (fuzzing) |
| **Malware** | `suite-attack/api/malware_router.py` | ~200 | Binary/file analysis |
| **LLM Monitor** | `suite-core/api/llm_monitor_router.py` | ~200 | LLM prompt injection, data exfiltration |

All scanners MUST work **air-gapped** (zero external dependencies).

## Scanner Architecture Pattern

Every scanner follows this pattern:

```python
"""Scanner engine base pattern."""
import structlog
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from datetime import datetime, timezone

logger = structlog.get_logger()


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class ScanResult:
    scan_id: str
    scanner_type: str
    status: ScanStatus
    findings: list = field(default_factory=list)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None
    metadata: dict = field(default_factory=dict)


class BaseScanner:
    """Base class for all native scanners."""

    SCANNER_TYPE: str = "base"
    MAX_SCAN_TIME_SECONDS: int = 300  # 5 min default timeout

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.log = logger.bind(scanner=self.SCANNER_TYPE)

    async def scan(self, target: dict) -> ScanResult:
        """Execute scan against target.
        
        Args:
            target: Dict with keys specific to scanner type
        Returns:
            ScanResult with findings
        """
        scan_id = self._generate_scan_id()
        self.log.info("scan_started", scan_id=scan_id, target=self._sanitize_target(target))

        result = ScanResult(
            scan_id=scan_id,
            scanner_type=self.SCANNER_TYPE,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        try:
            findings = await self._execute_scan(target)
            result.findings = findings
            result.status = ScanStatus.COMPLETED
        except TimeoutError:
            result.status = ScanStatus.TIMEOUT
            result.error = f"Scan timed out after {self.MAX_SCAN_TIME_SECONDS}s"
            self.log.warning("scan_timeout", scan_id=scan_id)
        except Exception as e:
            result.status = ScanStatus.FAILED
            result.error = str(e)
            self.log.error("scan_failed", scan_id=scan_id, error=str(e))

        result.completed_at = datetime.now(timezone.utc).isoformat()
        self.log.info("scan_completed", scan_id=scan_id, status=result.status, finding_count=len(result.findings))
        return result

    async def _execute_scan(self, target: dict) -> list:
        """Override in subclass. Performs the actual scan logic."""
        raise NotImplementedError

    def _sanitize_target(self, target: dict) -> dict:
        """Remove sensitive data from target before logging."""
        sanitized = dict(target)
        for key in ("password", "token", "secret", "api_key", "credentials"):
            if key in sanitized:
                sanitized[key] = "***REDACTED***"
        return sanitized

    def _generate_scan_id(self) -> str:
        import uuid
        return f"{self.SCANNER_TYPE}-{uuid.uuid4().hex[:12]}"
```

## Input Validation (CRITICAL for Scanners)

Scanners accept untrusted input. Validate EVERYTHING:

```python
from pydantic import BaseModel, Field, field_validator
import re


class SASTScanRequest(BaseModel):
    """Input validation for SAST scans."""
    source_path: str = Field(..., max_length=500)
    language: str = Field(..., pattern="^(python|javascript|typescript|java|go|rust|csharp)$")
    rules: list[str] = Field(default_factory=list, max_length=100)
    max_file_size_kb: int = Field(default=1024, ge=1, le=10240)

    @field_validator("source_path")
    @classmethod
    def validate_source_path(cls, v: str) -> str:
        # Prevent path traversal
        if ".." in v or v.startswith("/etc") or v.startswith("/proc"):
            raise ValueError("Invalid source path — path traversal detected")
        # Only allow alphanumeric, hyphens, underscores, dots, slashes
        if not re.match(r'^[a-zA-Z0-9/_.\-]+$', v):
            raise ValueError("Source path contains invalid characters")
        return v


class DASTScanRequest(BaseModel):
    """Input validation for DAST scans."""
    target_url: str = Field(..., pattern=r"^https?://[a-zA-Z0-9][a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=]+$")
    scan_depth: int = Field(default=3, ge=1, le=10)
    follow_redirects: bool = Field(default=True)
    timeout_seconds: int = Field(default=300, ge=30, le=3600)

    @field_validator("target_url")
    @classmethod
    def validate_not_internal(cls, v: str) -> str:
        """Prevent SSRF — block internal addresses."""
        from urllib.parse import urlparse
        import ipaddress

        parsed = urlparse(v)
        hostname = parsed.hostname or ""

        # Block internal ranges
        blocked = ["localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254", "metadata.google"]
        if hostname in blocked:
            raise ValueError(f"Scanning internal addresses is not allowed: {hostname}")

        # Block private IPs
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                raise ValueError(f"Scanning private IP addresses is not allowed: {hostname}")
        except ValueError:
            pass  # hostname is not an IP, that's fine

        return v


class SecretsScanRequest(BaseModel):
    """Input validation for Secrets scanning."""
    source_path: str = Field(..., max_length=500)
    include_patterns: list[str] = Field(default_factory=list, max_length=50)
    exclude_patterns: list[str] = Field(default=["*.lock", "*.min.js", "node_modules/*"], max_length=50)
    max_file_count: int = Field(default=10000, ge=1, le=100000)
```

## Adding a New Scanner

### Step 1: Create the engine

```python
# suite-core/core/my_scanner.py

class MyScanner(BaseScanner):
    SCANNER_TYPE = "my_scanner"
    MAX_SCAN_TIME_SECONDS = 600

    async def _execute_scan(self, target: dict) -> list:
        findings = []
        # Your scan logic here
        # ...
        return findings
```

### Step 2: Create the router

```python
# suite-core/api/my_scanner_router.py or suite-attack/api/my_scanner_router.py

from fastapi import APIRouter, Depends
from core.my_scanner import MyScanner

router = APIRouter(prefix="/api/v1/my-scanner", tags=["my-scanner"])

@router.post("/scan", response_model=ScanResultResponse)
async def start_scan(
    body: MyScanRequest,
    org_id: str = Depends(get_current_org),
):
    scanner = MyScanner()
    result = await scanner.scan(body.dict())
    return result

@router.get("/scans/{scan_id}", response_model=ScanResultResponse)
async def get_scan_result(
    scan_id: str = Path(..., pattern="^[a-zA-Z0-9_-]+$"),
    org_id: str = Depends(get_current_org),
):
    ...
```

### Step 3: Mount in app.py

```python
# In suite-api/apps/api/app.py (inside create_app):
from api.my_scanner_router import router as my_scanner_router
app.include_router(my_scanner_router, dependencies=[Depends(_verify_api_key)])
```

### Step 4: Wire into Brain Pipeline

```python
# In brain_pipeline.py, Step 1 (CONNECT):
async def _connect(self, sources: dict) -> list:
    findings = []
    # ... existing scanner connections ...
    
    if "my_scanner" in sources:
        my_findings = await self.my_scanner.scan(sources["my_scanner"])
        findings.extend(my_findings.findings)
    
    return findings
```

### Step 5: Write tests

```python
# tests/test_my_scanner.py
import pytest
from core.my_scanner import MyScanner

class TestMyScanner:
    @pytest.mark.asyncio
    async def test_scan_returns_findings(self):
        scanner = MyScanner()
        result = await scanner.scan({"target": "test_data"})
        assert result.status.value == "completed"
        assert isinstance(result.findings, list)

    @pytest.mark.asyncio
    async def test_scan_handles_invalid_target(self):
        scanner = MyScanner()
        result = await scanner.scan({"target": None})
        assert result.status.value == "failed"
```

## Hardening Existing Scanners — Checklist

For each of the 8 existing scanners:

- [ ] Input validation with Pydantic models (no raw string paths)
- [ ] Path traversal prevention (`..` in file paths)
- [ ] SSRF prevention (DAST/API Fuzzer — block internal IPs)
- [ ] Resource limits (max files, max file size, timeout)
- [ ] Structured logging at scan start, end, and for each finding
- [ ] Async execution (don't block the event loop)
- [ ] Error categorization (timeout vs failure vs invalid input)
- [ ] Test coverage (happy path, invalid input, timeout, large input)

## Validation

```bash
# Verify all scanner engines import:
for scanner in sast_engine dast_engine secrets_scanner container_scanner cspm_engine; do
    python -c "from core.${scanner} import *; print('OK: ${scanner}')" 2>&1
done

# Run scanner tests:
python -m pytest tests/ -k "scanner or sast or dast or secret or container or cspm" -v --timeout=10

# Check for path traversal vulnerabilities:
grep -rn "os.path.join\|open(" suite-core/core/sast_engine.py suite-core/core/secrets_scanner.py | grep -v __pycache__
# Every file open should validate input path first
```
