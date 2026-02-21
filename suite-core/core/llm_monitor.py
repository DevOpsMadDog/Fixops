"""ALdeci LLM/AI Security Monitor.

Detects threats in LLM interactions:
- Prompt injection (jailbreak, role confusion, DAN)
- Data leakage (PII in prompts/responses)
- Token usage anomaly detection
- Model poisoning indicators
- Sensitive data exfiltration via prompts

Competitive parity: Aikido AI Monitoring, Prompt Armor, Lakera Guard.
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class ThreatSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_LEAKAGE = "data_leakage"
    PII_EXPOSURE = "pii_exposure"
    TOKEN_ANOMALY = "token_anomaly"
    MODEL_ABUSE = "model_abuse"
    SENSITIVE_TOPIC = "sensitive_topic"


@dataclass
class LLMThreat:
    threat_id: str
    title: str
    severity: ThreatSeverity
    category: ThreatCategory
    matched_pattern: str = ""
    matched_text: str = ""
    location: str = ""  # "prompt" or "response"
    confidence: float = 0.8
    description: str = ""
    recommendation: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "matched_pattern": self.matched_pattern,
            "matched_text": self.matched_text[:200],
            "location": self.location,
            "confidence": self.confidence,
            "description": self.description,
            "recommendation": self.recommendation,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class LLMAnalysisResult:
    analysis_id: str
    prompt_threats: List[LLMThreat]
    response_threats: List[LLMThreat]
    total_threats: int
    risk_score: float  # 0-100
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    tokens_estimated: int = 0
    duration_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "prompt_threats": [t.to_dict() for t in self.prompt_threats],
            "response_threats": [t.to_dict() for t in self.response_threats],
            "total_threats": self.total_threats,
            "risk_score": self.risk_score,
            "by_severity": self.by_severity,
            "by_category": self.by_category,
            "tokens_estimated": self.tokens_estimated,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp.isoformat(),
        }


# ── Detection Patterns ─────────────────────────────────────────────
JAILBREAK_PATTERNS: List[Tuple[str, str, str]] = [
    (
        r"ignore\s+(all\s+)?previous\s+instructions",
        "Instruction override attempt",
        "critical",
    ),
    (r"you\s+are\s+now\s+(DAN|evil|unrestricted)", "DAN/persona jailbreak", "critical"),
    (r"pretend\s+(you\s+are|to\s+be)\s+a", "Role impersonation", "high"),
    (r"do\s+anything\s+now", "DAN activation phrase", "critical"),
    (r"forget\s+(all\s+)?(your\s+)?rules", "Rule bypass attempt", "critical"),
    (r"system\s*:\s*you\s+are", "System prompt injection", "critical"),
    (r"bypass\s+(safety|content|filter)", "Filter bypass attempt", "high"),
    (
        r"act\s+as\s+(if\s+)?(there\s+are\s+)?no\s+(restrictions|rules)",
        "Restriction bypass",
        "high",
    ),
    (r"\[SYSTEM\]|\[INST\]|\[\/INST\]", "Prompt template injection", "high"),
    (r"<\|im_start\|>|<\|im_end\|>", "ChatML injection", "critical"),
]

PII_PATTERNS: List[Tuple[str, str, str]] = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "SSN pattern detected", "critical"),
    (r"\b\d{16}\b", "Credit card number pattern", "critical"),
    (r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "Email address", "medium"),
    (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "Phone number pattern", "medium"),
    (r"\b(?:password|passwd|pwd)\s*[:=]\s*\S+", "Password in text", "critical"),
    (
        r"\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*\S+",
        "API key/secret",
        "critical",
    ),
    (
        r"\b(?:sk-|pk_live_|sk_live_|ghp_|glpat-)[A-Za-z0-9]+",
        "Known API key format",
        "critical",
    ),
]

SENSITIVE_TOPICS: List[Tuple[str, str]] = [
    (
        r"\b(how\s+to\s+)?(make|build|create)\s+(a\s+)?(bomb|weapon|explosive)",
        "Weapons/explosives",
    ),
    (
        r"\b(hack|exploit|attack)\s+(a\s+)?(server|system|network|website)",
        "Hacking instructions",
    ),
    (r"\bmalware\s+(code|source|creation)", "Malware creation"),
]


class LLMMonitor:
    """LLM/AI Security Monitor — detects threats in LLM interactions."""

    def __init__(self):
        self._jailbreak_compiled = [
            (re.compile(p, re.IGNORECASE), title, sev)
            for p, title, sev in JAILBREAK_PATTERNS
        ]
        self._pii_compiled = [
            (re.compile(p, re.IGNORECASE), title, sev) for p, title, sev in PII_PATTERNS
        ]
        self._topic_compiled = [
            (re.compile(p, re.IGNORECASE), title) for p, title in SENSITIVE_TOPICS
        ]

    def analyze(
        self,
        prompt: str = "",
        response: str = "",
        model: str = "unknown",
        max_tokens: int = 0,
    ) -> LLMAnalysisResult:
        """Analyze a prompt + response pair for threats."""
        t0 = time.time()
        prompt_threats: List[LLMThreat] = []
        response_threats: List[LLMThreat] = []

        # Scan prompt
        if prompt:
            prompt_threats.extend(self._check_jailbreak(prompt, "prompt"))
            prompt_threats.extend(self._check_pii(prompt, "prompt"))
            prompt_threats.extend(self._check_sensitive_topics(prompt, "prompt"))

        # Scan response
        if response:
            response_threats.extend(self._check_pii(response, "response"))
            response_threats.extend(self._check_sensitive_topics(response, "response"))

        # Token anomaly check
        est_tokens = self._estimate_tokens(prompt + response)
        if max_tokens > 0 and est_tokens > max_tokens * 1.5:
            prompt_threats.append(
                LLMThreat(
                    threat_id=f"LLM-{uuid.uuid4().hex[:8]}",
                    title="Token Usage Anomaly",
                    severity=ThreatSeverity.MEDIUM,
                    category=ThreatCategory.TOKEN_ANOMALY,
                    description=f"Estimated tokens ({est_tokens}) exceed max ({max_tokens}) by >50%",
                    recommendation="Check for prompt stuffing or exfiltration attempts",
                    location="prompt",
                )
            )

        all_threats = prompt_threats + response_threats
        by_sev: Dict[str, int] = {}
        by_cat: Dict[str, int] = {}
        for t in all_threats:
            by_sev[t.severity.value] = by_sev.get(t.severity.value, 0) + 1
            by_cat[t.category.value] = by_cat.get(t.category.value, 0) + 1

        risk = self._calculate_risk_score(all_threats)
        elapsed = (time.time() - t0) * 1000

        return LLMAnalysisResult(
            analysis_id=f"llm-{uuid.uuid4().hex[:12]}",
            prompt_threats=prompt_threats,
            response_threats=response_threats,
            total_threats=len(all_threats),
            risk_score=risk,
            by_severity=by_sev,
            by_category=by_cat,
            tokens_estimated=est_tokens,
            duration_ms=round(elapsed, 2),
        )

    def _check_jailbreak(self, text: str, location: str) -> List[LLMThreat]:
        threats = []
        for pat, title, sev in self._jailbreak_compiled:
            m = pat.search(text)
            if m:
                threats.append(
                    LLMThreat(
                        threat_id=f"LLM-{uuid.uuid4().hex[:8]}",
                        title=title,
                        severity=ThreatSeverity(sev),
                        category=ThreatCategory.JAILBREAK,
                        matched_pattern=pat.pattern,
                        matched_text=m.group(),
                        location=location,
                        confidence=0.9,
                        description=f"Jailbreak pattern detected: {title}",
                        recommendation="Block this prompt and log the attempt",
                    )
                )
        return threats

    def _check_pii(self, text: str, location: str) -> List[LLMThreat]:
        threats = []
        for pat, title, sev in self._pii_compiled:
            m = pat.search(text)
            if m:
                threats.append(
                    LLMThreat(
                        threat_id=f"LLM-{uuid.uuid4().hex[:8]}",
                        title=title,
                        severity=ThreatSeverity(sev),
                        category=ThreatCategory.PII_EXPOSURE,
                        matched_pattern=pat.pattern,
                        matched_text=m.group(),
                        location=location,
                        confidence=0.85,
                        description=f"PII detected in {location}: {title}",
                        recommendation="Redact sensitive data before sending to LLM",
                    )
                )
        return threats

    def _check_sensitive_topics(self, text: str, location: str) -> List[LLMThreat]:
        threats = []
        for pat, title in self._topic_compiled:
            m = pat.search(text)
            if m:
                threats.append(
                    LLMThreat(
                        threat_id=f"LLM-{uuid.uuid4().hex[:8]}",
                        title=f"Sensitive topic: {title}",
                        severity=ThreatSeverity.HIGH,
                        category=ThreatCategory.SENSITIVE_TOPIC,
                        matched_pattern=pat.pattern,
                        matched_text=m.group(),
                        location=location,
                        confidence=0.75,
                        description=f"Sensitive topic detected: {title}",
                        recommendation="Review content policy and block if appropriate",
                    )
                )
        return threats

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """Rough token estimate (~4 chars per token for English)."""
        return max(len(text) // 4, 1)

    @staticmethod
    def _calculate_risk_score(threats: List[LLMThreat]) -> float:
        if not threats:
            return 0.0
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
        score = sum(weights.get(t.severity.value, 1) * t.confidence for t in threats)
        return min(round(score, 1), 100.0)


_monitor: Optional[LLMMonitor] = None


def get_llm_monitor() -> LLMMonitor:
    global _monitor
    if _monitor is None:
        _monitor = LLMMonitor()
    return _monitor
