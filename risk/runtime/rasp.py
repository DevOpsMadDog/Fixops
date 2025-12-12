"""FixOps RASP (Runtime Application Self-Protection) Engine

Proprietary runtime protection that blocks attacks in real-time.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class AttackType(Enum):
    """Attack types blocked by RASP."""

    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    DESERIALIZATION = "deserialization"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    AUTHORIZATION_BYPASS = "authorization_bypass"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    MALICIOUS_PAYLOAD = "malicious_payload"


class ProtectionAction(Enum):
    """Protection actions."""

    BLOCK = "block"  # Block the request
    LOG = "log"  # Log but allow
    ALERT = "alert"  # Alert security team
    RATE_LIMIT = "rate_limit"  # Rate limit the request


@dataclass
class RASPIncident:
    """RASP security incident."""

    attack_type: AttackType
    action_taken: ProtectionAction
    source_ip: str
    user_id: Optional[str] = None
    request_path: str = ""
    request_method: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    blocked: bool = False
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = 1.0  # 0.0 to 1.0


@dataclass
class RASPConfig:
    """RASP configuration."""

    enabled: bool = True
    mode: str = "blocking"  # blocking, monitoring, learning
    block_sql_injection: bool = True
    block_command_injection: bool = True
    block_xss: bool = True
    block_path_traversal: bool = True
    block_deserialization: bool = True
    rate_limit_enabled: bool = True
    rate_limit_requests_per_minute: int = 100
    whitelist_ips: List[str] = field(default_factory=list)
    blacklist_ips: List[str] = field(default_factory=list)
    alert_on_block: bool = True


class RASPRuleEngine:
    """Proprietary RASP rule engine."""

    def __init__(self, config: RASPConfig):
        """Initialize RASP rule engine."""
        self.config = config
        self.rate_limit_tracker: Dict[str, List[float]] = {}

    def evaluate_request(
        self,
        source_ip: str,
        request_path: str,
        request_method: str,
        request_headers: Dict[str, str],
        request_body: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> Optional[RASPIncident]:
        """Evaluate request for attacks."""
        if not self.config.enabled:
            return None

        # Check IP whitelist/blacklist
        if source_ip in self.config.blacklist_ips:
            return RASPIncident(
                attack_type=AttackType.MALICIOUS_PAYLOAD,
                action_taken=ProtectionAction.BLOCK,
                source_ip=source_ip,
                user_id=user_id,
                request_path=request_path,
                request_method=request_method,
                blocked=True,
            )

        if source_ip in self.config.whitelist_ips:
            return None  # Whitelisted, skip checks

        # Rate limiting
        if self.config.rate_limit_enabled:
            if self._check_rate_limit(source_ip):
                return RASPIncident(
                    attack_type=AttackType.RATE_LIMIT_EXCEEDED,
                    action_taken=ProtectionAction.RATE_LIMIT,
                    source_ip=source_ip,
                    user_id=user_id,
                    request_path=request_path,
                    request_method=request_method,
                    blocked=True,
                )

        # Check for SQL injection
        if self.config.block_sql_injection:
            if self._detect_sql_injection(request_path, request_body):
                return RASPIncident(
                    attack_type=AttackType.SQL_INJECTION,
                    action_taken=ProtectionAction.BLOCK,
                    source_ip=source_ip,
                    user_id=user_id,
                    request_path=request_path,
                    request_method=request_method,
                    request_body=request_body,
                    blocked=True,
                )

        # Check for command injection
        if self.config.block_command_injection:
            if self._detect_command_injection(request_path, request_body):
                return RASPIncident(
                    attack_type=AttackType.COMMAND_INJECTION,
                    action_taken=ProtectionAction.BLOCK,
                    source_ip=source_ip,
                    user_id=user_id,
                    request_path=request_path,
                    request_method=request_method,
                    request_body=request_body,
                    blocked=True,
                )

        # Check for XSS
        if self.config.block_xss:
            if self._detect_xss(request_path, request_body):
                return RASPIncident(
                    attack_type=AttackType.XSS,
                    action_taken=ProtectionAction.BLOCK,
                    source_ip=source_ip,
                    user_id=user_id,
                    request_path=request_path,
                    request_method=request_method,
                    request_body=request_body,
                    blocked=True,
                )

        # Check for path traversal
        if self.config.block_path_traversal:
            if self._detect_path_traversal(request_path, request_body):
                return RASPIncident(
                    attack_type=AttackType.PATH_TRAVERSAL,
                    action_taken=ProtectionAction.BLOCK,
                    source_ip=source_ip,
                    user_id=user_id,
                    request_path=request_path,
                    request_method=request_method,
                    request_body=request_body,
                    blocked=True,
                )

        return None  # No attack detected

    def _check_rate_limit(self, source_ip: str) -> bool:
        """Check if source IP exceeds rate limit."""
        current_time = time.time()

        if source_ip not in self.rate_limit_tracker:
            self.rate_limit_tracker[source_ip] = []

        # Remove old entries (older than 1 minute)
        self.rate_limit_tracker[source_ip] = [
            t for t in self.rate_limit_tracker[source_ip] if current_time - t < 60
        ]

        # Check if limit exceeded
        if (
            len(self.rate_limit_tracker[source_ip])
            >= self.config.rate_limit_requests_per_minute
        ):
            return True

        # Add current request
        self.rate_limit_tracker[source_ip].append(current_time)
        return False

    def _detect_sql_injection(
        self, request_path: str, request_body: Optional[str]
    ) -> bool:
        """Proprietary SQL injection detection."""
        sql_patterns = [
            "UNION SELECT",
            "OR 1=1",
            "OR '1'='1'",
            "'; DROP TABLE",
            "'; DELETE FROM",
            "'; INSERT INTO",
            "'; UPDATE",
        ]

        text_to_check = f"{request_path} {request_body or ''}".upper()

        return any(pattern in text_to_check for pattern in sql_patterns)

    def _detect_command_injection(
        self, request_path: str, request_body: Optional[str]
    ) -> bool:
        """Proprietary command injection detection."""
        command_patterns = [
            "; ls",
            "; cat",
            "; rm",
            "| whoami",
            "| id",
            "`whoami`",
            "$(whoami)",
            "&&",
            "||",
        ]

        text_to_check = f"{request_path} {request_body or ''}"

        return any(pattern in text_to_check for pattern in command_patterns)

    def _detect_xss(self, request_path: str, request_body: Optional[str]) -> bool:
        """Proprietary XSS detection."""
        xss_patterns = [
            "<script",
            "javascript:",
            "onerror=",
            "onclick=",
            "onload=",
            "eval(",
            "document.cookie",
        ]

        text_to_check = f"{request_path} {request_body or ''}".lower()

        return any(pattern in text_to_check for pattern in xss_patterns)

    def _detect_path_traversal(
        self, request_path: str, request_body: Optional[str]
    ) -> bool:
        """Proprietary path traversal detection."""
        path_patterns = [
            "../",
            "..\\",
            "/etc/passwd",
            "/etc/shadow",
            "/proc/",
            "..%2F",
            "..%5C",
        ]

        text_to_check = f"{request_path} {request_body or ''}"

        return any(pattern in text_to_check for pattern in path_patterns)


@dataclass
class RASPResult:
    """RASP protection result."""

    incidents: List[RASPIncident]
    total_incidents: int
    blocked_requests: int
    incidents_by_type: Dict[str, int]
    protection_enabled: bool
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class RASPProtector:
    """FixOps RASP Protector - Proprietary runtime protection."""

    def __init__(self, config: Optional[RASPConfig] = None):
        """Initialize RASP protector."""
        self.config = config or RASPConfig()
        self.rule_engine = RASPRuleEngine(self.config)
        self.incidents: List[RASPIncident] = []

    def protect_request(
        self,
        source_ip: str,
        request_path: str,
        request_method: str,
        request_headers: Dict[str, str],
        request_body: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> tuple[bool, Optional[RASPIncident]]:
        """Protect request from attacks. Returns (should_block, incident)."""
        if not self.config.enabled:
            return (False, None)

        incident = self.rule_engine.evaluate_request(
            source_ip=source_ip,
            request_path=request_path,
            request_method=request_method,
            request_headers=request_headers,
            request_body=request_body,
            user_id=user_id,
        )

        if incident:
            self.incidents.append(incident)

            if self.config.alert_on_block and incident.blocked:
                logger.warning(
                    f"RASP blocked attack: {incident.attack_type.value} from {source_ip}"
                )

            return (incident.blocked, incident)

        return (False, None)

    def get_protection_stats(self) -> RASPResult:
        """Get RASP protection statistics."""
        blocked = sum(1 for i in self.incidents if i.blocked)

        incidents_by_type: Dict[str, int] = {}
        for incident in self.incidents:
            attack_type = incident.attack_type.value
            incidents_by_type[attack_type] = incidents_by_type.get(attack_type, 0) + 1

        return RASPResult(
            incidents=self.incidents,
            total_incidents=len(self.incidents),
            blocked_requests=blocked,
            incidents_by_type=incidents_by_type,
            protection_enabled=self.config.enabled,
        )

    def clear_incidents(self) -> None:
        """Clear incidents."""
        self.incidents.clear()
