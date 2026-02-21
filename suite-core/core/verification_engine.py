"""Multi-Stage Verification Engine for CVE Testing.

Implements a 4-stage verification pipeline to eliminate false positives:
  Stage 1: Product Detection - Is the target actually running the vulnerable product?
  Stage 2: Version Fingerprinting - Is the detected version in the vulnerable range?
  Stage 3: Exploit Verification - Does the exploit payload actually trigger the vulnerability?
  Stage 4: Differential Confirmation - Does malicious input produce different behavior than benign?

Evidence-based confidence scoring:
  Product detected:     +0.15
  Version matched:      +0.25
  Exploit verified:     +0.35
  Differential confirmed: +0.25
  MINIMUM 0.60 to flag as vulnerable (requires exploit OR version+differential)
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class VerificationStage(str, Enum):
    """Stages of the verification pipeline."""

    PRODUCT_DETECTION = "product_detection"
    VERSION_FINGERPRINT = "version_fingerprint"
    EXPLOIT_VERIFICATION = "exploit_verification"
    DIFFERENTIAL_CONFIRMATION = "differential_confirmation"


@dataclass
class StageResult:
    """Result from a single verification stage."""

    stage: VerificationStage
    passed: bool
    confidence_contribution: float
    evidence: Dict[str, Any] = field(default_factory=dict)
    detail: str = ""


@dataclass
class VerificationResult:
    """Aggregated result of the multi-stage verification pipeline."""

    vulnerable: bool
    confidence: float
    stages: List[StageResult] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    verification_chain: str = ""

    def summary(self) -> str:
        stages_str = " → ".join(
            f"{s.stage.value}({'✓' if s.passed else '✗'})" for s in self.stages
        )
        return f"[{self.confidence:.0%}] {stages_str}"


# Confidence weights per stage
CONFIDENCE_WEIGHTS = {
    VerificationStage.PRODUCT_DETECTION: 0.15,
    VerificationStage.VERSION_FINGERPRINT: 0.25,
    VerificationStage.EXPLOIT_VERIFICATION: 0.35,
    VerificationStage.DIFFERENTIAL_CONFIRMATION: 0.25,
}

MINIMUM_CONFIDENCE_THRESHOLD = 0.60


@dataclass
class ProductSignature:
    """Signature for detecting a specific product."""

    name: str
    header_patterns: Dict[str, str] = field(default_factory=dict)
    body_patterns: List[str] = field(default_factory=list)
    url_paths: List[str] = field(default_factory=list)
    cookie_patterns: List[str] = field(default_factory=list)
    status_code_hints: Dict[str, int] = field(default_factory=dict)


@dataclass
class VersionRange:
    """Defines a vulnerable version range for a product."""

    product: str
    min_version: Optional[str] = None
    max_version: Optional[str] = None
    fixed_version: Optional[str] = None
    version_regex: str = ""
    extract_from: str = "header"


# ═══════════════════════════════════════════════════════════════════
# Common Product Signatures
# ═══════════════════════════════════════════════════════════════════

PRODUCT_SIGNATURES: Dict[str, ProductSignature] = {
    "apache_log4j": ProductSignature(
        name="Apache Log4j",
        body_patterns=[r"log4j", r"org\.apache\.logging"],
        url_paths=["/"],
    ),
    "spring_framework": ProductSignature(
        name="Spring Framework",
        header_patterns={"X-Application-Context": r".*"},
        body_patterns=[r"Whitelabel Error Page", r"org\.springframework"],
        url_paths=["/actuator", "/actuator/env", "/actuator/health"],
        status_code_hints={"/actuator/health": 200},
    ),
    "microsoft_exchange": ProductSignature(
        name="Microsoft Exchange",
        header_patterns={"X-OWA-Version": r".*", "X-FEServer": r".*"},
        url_paths=["/owa/auth/logon.aspx", "/ecp/", "/autodiscover/autodiscover.xml"],
    ),
    "citrix_netscaler": ProductSignature(
        name="Citrix NetScaler/ADC",
        body_patterns=[r"citrix", r"netscaler", r"ns_vip"],
        url_paths=["/vpn/index.html", "/logon/LogonPoint/tmindex.html"],
    ),
    "apache_struts": ProductSignature(
        name="Apache Struts",
        body_patterns=[r"\.action", r"struts", r"org\.apache\.struts"],
        url_paths=["/struts/webconsole.html"],
    ),
    "fortinet_fortios": ProductSignature(
        name="Fortinet FortiOS",
        body_patterns=[r"fortinet", r"fortigate", r"fgt_lang"],
        url_paths=["/remote/login", "/remote/fgt_lang"],
    ),
    "cisco_ios_xe": ProductSignature(
        name="Cisco IOS XE",
        body_patterns=[r"cisco", r"ios.?xe", r"webui"],
        url_paths=["/webui"],
    ),
    "ivanti_connect": ProductSignature(
        name="Ivanti Connect Secure",
        body_patterns=[r"pulse", r"ivanti", r"connect.?secure"],
        url_paths=["/dana-na/auth/url_default/welcome.cgi"],
    ),
    "papercut": ProductSignature(
        name="PaperCut MF/NG",
        body_patterns=[r"papercut", r"print.?management"],
        url_paths=["/app", "/admin"],
        cookie_patterns=[r"papercut"],
    ),
    "connectwise": ProductSignature(
        name="ConnectWise ScreenConnect",
        body_patterns=[r"screenconnect", r"connectwise"],
        url_paths=["/Administration", "/Host"],
    ),
    "goanywhere": ProductSignature(
        name="Fortra GoAnywhere MFT",
        body_patterns=[r"goanywhere", r"fortra"],
        url_paths=["/goanywhere/images/favicon.ico"],
    ),
    "openssl": ProductSignature(
        name="OpenSSL",
        header_patterns={"Server": r"openssl"},
        body_patterns=[],
    ),
    "nginx": ProductSignature(
        name="Nginx",
        header_patterns={"Server": r"nginx"},
        body_patterns=[r"nginx"],
    ),
    "apache_httpd": ProductSignature(
        name="Apache HTTP Server",
        header_patterns={"Server": r"Apache"},
        body_patterns=[r"Apache"],
    ),
}


# ═══════════════════════════════════════════════════════════════════
# Differential Analysis Helpers
# ═══════════════════════════════════════════════════════════════════


def _response_fingerprint(resp: httpx.Response) -> Dict[str, Any]:
    """Create a fingerprint of an HTTP response for differential comparison."""
    body = resp.content
    return {
        "status_code": resp.status_code,
        "content_length": len(body),
        "content_hash": hashlib.sha256(body).hexdigest()[:16],
        "headers_count": len(resp.headers),
        "content_type": resp.headers.get("content-type", ""),
    }


def _compute_diff_score(
    benign_fp: Dict[str, Any], malicious_fp: Dict[str, Any]
) -> float:
    """Compute a normalized difference score between two response fingerprints.

    Returns 0.0 (identical) to 1.0 (completely different).
    """
    score = 0.0
    weights = {
        "status_code": 0.35,
        "content_length": 0.25,
        "content_hash": 0.25,
        "content_type": 0.15,
    }

    if benign_fp["status_code"] != malicious_fp["status_code"]:
        score += weights["status_code"]

    bl = benign_fp["content_length"]
    ml = malicious_fp["content_length"]
    if bl > 0:
        length_ratio = abs(bl - ml) / max(bl, ml, 1)
        score += weights["content_length"] * min(1.0, length_ratio)
    elif ml > 0:
        score += weights["content_length"]

    if benign_fp["content_hash"] != malicious_fp["content_hash"]:
        score += weights["content_hash"]

    if benign_fp["content_type"] != malicious_fp["content_type"]:
        score += weights["content_type"]

    return min(1.0, score)


async def _measure_timing(
    client: httpx.AsyncClient,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 10.0,
) -> float:
    """Measure response time in seconds."""
    start = time.monotonic()
    try:
        await client.get(url, headers=headers or {}, timeout=timeout)
    except Exception:
        pass
    return time.monotonic() - start


def _version_compare(v1: str, v2: str) -> int:
    """Compare two version strings. Returns -1, 0, or 1."""

    def _normalize(v: str) -> List:
        parts = []
        for seg in re.split(r"[.\-_]", v):
            match = re.match(r"^(\d+)(.*)", seg)
            if match:
                parts.append(int(match.group(1)))
                if match.group(2):
                    parts.append(match.group(2))
            else:
                parts.append(seg)
        return parts

    p1, p2 = _normalize(v1), _normalize(v2)
    for a, b in zip(p1, p2):
        if type(a) is type(b):
            if a < b:
                return -1
            elif a > b:
                return 1
        else:
            sa, sb = str(a), str(b)
            if sa < sb:
                return -1
            elif sa > sb:
                return 1
    if len(p1) < len(p2):
        return -1
    elif len(p1) > len(p2):
        return 1
    return 0


def _version_in_range(
    version: str, min_ver: Optional[str], max_ver: Optional[str]
) -> bool:
    """Check if version falls within a vulnerable range (inclusive)."""
    if min_ver and _version_compare(version, min_ver) < 0:
        return False
    if max_ver and _version_compare(version, max_ver) > 0:
        return False
    return True


# ═══════════════════════════════════════════════════════════════════
# Core Verification Engine
# ═══════════════════════════════════════════════════════════════════


class VerificationEngine:
    """Multi-stage vulnerability verification engine.

    Eliminates false positives through a rigorous 4-stage pipeline.
    Each stage contributes evidence-weighted confidence. Only flags
    a target as vulnerable when confidence ≥ 0.60 (requires at least
    exploit verification OR version match + differential confirmation).
    """

    def __init__(self, client: httpx.AsyncClient, target_url: str):
        self.client = client
        self.target_url = target_url
        self._stages: List[StageResult] = []
        self._evidence: Dict[str, Any] = {"verification_stages": []}
        self._confidence = 0.0

    async def run_stage_1_product_detection(
        self, signature: ProductSignature
    ) -> StageResult:
        """Stage 1: Detect if target runs the vulnerable product."""
        detected = False
        detail_parts = []

        try:
            # Check response headers
            resp = await self.client.get(self.target_url, timeout=8.0)
            for header_name, pattern in signature.header_patterns.items():
                val = resp.headers.get(header_name, "")
                if val and re.search(pattern, val, re.IGNORECASE):
                    detected = True
                    detail_parts.append(f"Header {header_name}={val}")

            # Check response body
            body_lower = resp.text[:10000].lower()
            for bp in signature.body_patterns:
                if re.search(bp, body_lower, re.IGNORECASE):
                    detected = True
                    detail_parts.append(f"Body match: {bp}")
                    break

            # Check known URL paths
            from urllib.parse import urljoin

            for path in signature.url_paths[:3]:
                try:
                    path_resp = await self.client.get(
                        urljoin(self.target_url, path), timeout=5.0
                    )
                    expected_status = signature.status_code_hints.get(path, 200)
                    if path_resp.status_code == expected_status:
                        # Only count as detected if body also hints at product
                        path_body = path_resp.text[:5000].lower()
                        if any(
                            re.search(bp, path_body, re.IGNORECASE)
                            for bp in signature.body_patterns
                        ):
                            detected = True
                            detail_parts.append(
                                f"Path {path} (HTTP {path_resp.status_code})"
                            )
                except Exception:
                    pass

            # Check cookies
            for cookie_p in signature.cookie_patterns:
                for header_val in [
                    v
                    for k, v in resp.headers.multi_items()
                    if k.lower() == "set-cookie"
                ]:
                    if re.search(cookie_p, header_val, re.IGNORECASE):
                        detected = True
                        detail_parts.append(f"Cookie match: {cookie_p}")

        except Exception as e:
            detail_parts.append(f"Error: {e}")

        contribution = (
            CONFIDENCE_WEIGHTS[VerificationStage.PRODUCT_DETECTION] if detected else 0.0
        )
        result = StageResult(
            stage=VerificationStage.PRODUCT_DETECTION,
            passed=detected,
            confidence_contribution=contribution,
            evidence={"product": signature.name, "indicators": detail_parts},
            detail=f"{'Detected' if detected else 'Not detected'}: {signature.name}",
        )
        self._stages.append(result)
        self._confidence += contribution
        self._evidence["verification_stages"].append(
            {
                "stage": result.stage.value,
                "passed": result.passed,
                "confidence": result.confidence_contribution,
                "detail": result.detail,
            }
        )
        return result

    async def run_stage_2_version_fingerprint(
        self, version_range: VersionRange
    ) -> StageResult:
        """Stage 2: Fingerprint the product version and check if it's in vulnerable range."""
        version_found = ""
        in_range = False
        detail_parts = []

        try:
            resp = await self.client.get(self.target_url, timeout=8.0)

            # Extract version from headers
            if version_range.extract_from == "header":
                server = resp.headers.get("Server", "")
                x_powered = resp.headers.get("X-Powered-By", "")
                for hdr_val in [server, x_powered]:
                    if hdr_val and version_range.version_regex:
                        m = re.search(version_range.version_regex, hdr_val)
                        if m:
                            version_found = m.group(1) if m.lastindex else m.group(0)
                            detail_parts.append(f"Version from header: {version_found}")
                            break

            # Extract version from body
            if not version_found and version_range.extract_from == "body":
                body = resp.text[:20000]
                if version_range.version_regex:
                    m = re.search(version_range.version_regex, body)
                    if m:
                        version_found = m.group(1) if m.lastindex else m.group(0)
                        detail_parts.append(f"Version from body: {version_found}")

            # Extract from specific endpoint paths
            if not version_found:
                for path in ["/api/version", "/version", "/api/v1/version"]:
                    try:
                        from urllib.parse import urljoin

                        vr = await self.client.get(
                            urljoin(self.target_url, path), timeout=5.0
                        )
                        if vr.status_code == 200 and version_range.version_regex:
                            m = re.search(version_range.version_regex, vr.text[:5000])
                            if m:
                                version_found = (
                                    m.group(1) if m.lastindex else m.group(0)
                                )
                                detail_parts.append(
                                    f"Version from {path}: {version_found}"
                                )
                                break
                    except Exception:
                        pass

            # Check version range
            if version_found:
                in_range = _version_in_range(
                    version_found, version_range.min_version, version_range.max_version
                )
                if version_range.fixed_version:
                    if _version_compare(version_found, version_range.fixed_version) < 0:
                        in_range = True
                        detail_parts.append(
                            f"Below fix version {version_range.fixed_version}"
                        )
                    else:
                        in_range = False
                        detail_parts.append(
                            f"At or above fix version {version_range.fixed_version}"
                        )
                detail_parts.append(f"In vulnerable range: {in_range}")
            else:
                detail_parts.append("Version not detected")

        except Exception as e:
            detail_parts.append(f"Error: {e}")

        contribution = (
            CONFIDENCE_WEIGHTS[VerificationStage.VERSION_FINGERPRINT]
            if in_range
            else 0.0
        )
        result = StageResult(
            stage=VerificationStage.VERSION_FINGERPRINT,
            passed=in_range,
            confidence_contribution=contribution,
            evidence={
                "version_detected": version_found,
                "in_vulnerable_range": in_range,
            },
            detail=f"Version: {version_found or 'unknown'} | Vulnerable: {in_range}",
        )
        self._stages.append(result)
        self._confidence += contribution
        self._evidence["verification_stages"].append(
            {
                "stage": result.stage.value,
                "passed": result.passed,
                "confidence": result.confidence_contribution,
                "detail": result.detail,
            }
        )
        self._evidence["version_detected"] = version_found
        return result

    async def run_stage_3_exploit_verification(
        self, exploit_payloads: List[Dict[str, Any]]
    ) -> StageResult:
        """Stage 3: Send actual exploit payloads and verify they trigger the vulnerability.

        Each payload dict should have:
          - method: str (GET/POST/PUT)
          - path: str (URL path)
          - headers: dict (optional)
          - body: str (optional)
          - success_indicators: list of patterns that indicate exploit worked
          - failure_indicators: list of patterns that indicate exploit did NOT work
        """
        exploit_confirmed = False
        detail_parts = []
        payload_results = []

        from urllib.parse import urljoin

        for i, payload in enumerate(exploit_payloads):
            try:
                method = payload.get("method", "GET").upper()
                path = payload.get("path", "/")
                hdrs = payload.get("headers", {})
                body = payload.get("body")
                url = urljoin(self.target_url, path)

                if method == "GET":
                    resp = await self.client.get(url, headers=hdrs, timeout=10.0)
                elif method == "POST":
                    resp = await self.client.post(
                        url, headers=hdrs, content=body, timeout=10.0
                    )
                elif method == "PUT":
                    resp = await self.client.put(
                        url, headers=hdrs, content=body, timeout=10.0
                    )
                else:
                    resp = await self.client.request(
                        method, url, headers=hdrs, content=body, timeout=10.0
                    )

                resp_text = resp.text[:10000]
                payload_result = {
                    "payload_index": i,
                    "status_code": resp.status_code,
                    "response_length": len(resp.content),
                }

                # Check success indicators (exploit worked)
                for pattern in payload.get("success_indicators", []):
                    if re.search(pattern, resp_text, re.IGNORECASE):
                        exploit_confirmed = True
                        payload_result["matched_indicator"] = pattern
                        detail_parts.append(
                            f"Payload {i}: exploit indicator matched '{pattern}'"
                        )
                        break

                # Check failure indicators (definitively NOT vulnerable)
                for pattern in payload.get("failure_indicators", []):
                    if re.search(pattern, resp_text, re.IGNORECASE):
                        payload_result["blocked_by"] = pattern
                        detail_parts.append(f"Payload {i}: blocked by '{pattern}'")
                        break

                payload_results.append(payload_result)
            except httpx.TimeoutException:
                # Timeout can sometimes indicate successful exploitation (e.g., time-based)
                if payload.get("timeout_is_success"):
                    exploit_confirmed = True
                    detail_parts.append(f"Payload {i}: timeout (indicates success)")
                payload_results.append({"payload_index": i, "error": "timeout"})
            except Exception as e:
                payload_results.append({"payload_index": i, "error": str(e)})

        contribution = (
            CONFIDENCE_WEIGHTS[VerificationStage.EXPLOIT_VERIFICATION]
            if exploit_confirmed
            else 0.0
        )
        result = StageResult(
            stage=VerificationStage.EXPLOIT_VERIFICATION,
            passed=exploit_confirmed,
            confidence_contribution=contribution,
            evidence={
                "payloads_sent": len(exploit_payloads),
                "payload_results": payload_results,
            },
            detail=f"{'Exploit confirmed' if exploit_confirmed else 'Exploit not confirmed'} ({len(exploit_payloads)} payloads)",
        )
        self._stages.append(result)
        self._confidence += contribution
        self._evidence["verification_stages"].append(
            {
                "stage": result.stage.value,
                "passed": result.passed,
                "confidence": result.confidence_contribution,
                "detail": result.detail,
            }
        )
        return result

    async def run_stage_4_differential_confirmation(
        self, benign_request: Dict[str, Any], malicious_request: Dict[str, Any]
    ) -> StageResult:
        """Stage 4: Compare responses between benign and malicious requests.

        If malicious input produces observably different behavior than benign,
        it confirms the vulnerability is real (not a generic/false detection).

        Each request dict: {method, path, headers, body}
        """
        confirmed = False
        detail_parts = []
        diff_data = {}

        try:
            from urllib.parse import urljoin

            # Send benign request
            benign_url = urljoin(self.target_url, benign_request.get("path", "/"))
            benign_resp = await self.client.request(
                benign_request.get("method", "GET"),
                benign_url,
                headers=benign_request.get("headers", {}),
                content=benign_request.get("body"),
                timeout=10.0,
            )
            benign_fp = _response_fingerprint(benign_resp)

            # Send malicious request
            mal_url = urljoin(self.target_url, malicious_request.get("path", "/"))
            mal_resp = await self.client.request(
                malicious_request.get("method", "GET"),
                mal_url,
                headers=malicious_request.get("headers", {}),
                content=malicious_request.get("body"),
                timeout=10.0,
            )
            mal_fp = _response_fingerprint(mal_resp)

            # Compute differential score
            diff_score = _compute_diff_score(benign_fp, mal_fp)
            diff_data = {
                "benign_fingerprint": benign_fp,
                "malicious_fingerprint": mal_fp,
                "diff_score": round(diff_score, 4),
            }

            # Threshold: diff_score > 0.30 indicates meaningfully different behavior
            if diff_score > 0.30:
                confirmed = True
                detail_parts.append(
                    f"Differential score {diff_score:.2f} > 0.30 threshold"
                )
            else:
                detail_parts.append(
                    f"Differential score {diff_score:.2f} <= 0.30 (no meaningful difference)"
                )

            # Timing-based differential
            benign_time = await _measure_timing(
                self.client, benign_url, benign_request.get("headers")
            )
            mal_time = await _measure_timing(
                self.client, mal_url, malicious_request.get("headers")
            )
            time_diff = abs(mal_time - benign_time)
            diff_data["timing"] = {
                "benign_ms": round(benign_time * 1000),
                "malicious_ms": round(mal_time * 1000),
                "diff_ms": round(time_diff * 1000),
            }

            if (
                time_diff > 2.0
            ):  # >2 seconds difference suggests time-based exploitation
                confirmed = True
                detail_parts.append(f"Timing anomaly: {time_diff:.1f}s difference")

        except Exception as e:
            detail_parts.append(f"Error: {e}")

        contribution = (
            CONFIDENCE_WEIGHTS[VerificationStage.DIFFERENTIAL_CONFIRMATION]
            if confirmed
            else 0.0
        )
        result = StageResult(
            stage=VerificationStage.DIFFERENTIAL_CONFIRMATION,
            passed=confirmed,
            confidence_contribution=contribution,
            evidence=diff_data,
            detail=f"{'Differential confirmed' if confirmed else 'No differential'}: {'; '.join(detail_parts)}",
        )
        self._stages.append(result)
        self._confidence += contribution
        self._evidence["verification_stages"].append(
            {
                "stage": result.stage.value,
                "passed": result.passed,
                "confidence": result.confidence_contribution,
                "detail": result.detail,
            }
        )
        return result

    def finalize(self) -> VerificationResult:
        """Aggregate all stage results into final verdict.

        Rules:
        - Confidence must be >= MINIMUM_CONFIDENCE_THRESHOLD (0.60)
        - This requires AT LEAST one of:
          * Exploit verification passed (0.35) + product detected (0.15) = 0.50 + anything else
          * Version match (0.25) + differential (0.25) + product (0.15) = 0.65
        - Without exploit verification or (version + differential), cannot reach threshold
        """
        vulnerable = self._confidence >= MINIMUM_CONFIDENCE_THRESHOLD

        # Build verification chain string
        chain_parts = []
        for s in self._stages:
            icon = "✓" if s.passed else "✗"
            chain_parts.append(f"{s.stage.value}({icon})")
        chain = " → ".join(chain_parts)

        self._evidence["final_confidence"] = round(self._confidence, 4)
        self._evidence["threshold"] = MINIMUM_CONFIDENCE_THRESHOLD
        self._evidence["verdict"] = "VULNERABLE" if vulnerable else "NOT_VULNERABLE"

        return VerificationResult(
            vulnerable=vulnerable,
            confidence=round(self._confidence, 4),
            stages=self._stages,
            evidence=self._evidence,
            verification_chain=chain,
        )


__all__ = [
    "VerificationEngine",
    "VerificationStage",
    "VerificationResult",
    "StageResult",
    "ProductSignature",
    "VersionRange",
    "PRODUCT_SIGNATURES",
    "CONFIDENCE_WEIGHTS",
    "MINIMUM_CONFIDENCE_THRESHOLD",
]
