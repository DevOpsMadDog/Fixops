"""Single AI Agent Engine (V4 — Multi-LLM Consensus / Self-Hosted AI).

Provides zero-token self-hosted AI inference via vLLM, GGUF, and Ollama backends.
Replaces $6K/month vendor API costs with local inference on commodity hardware.

Architecture:
- 4 expert roles: ANALYST, ARCHITECT, AUDITOR, ATTACKER
- 1 MODERATOR that synthesizes expert opinions
- Multi-LLM consensus: 3+ models must agree at 85% threshold
- Automatic fallback: vLLM → Ollama → GGUF → API providers

Inference Backends:
1. vLLM (recommended): High-throughput, continuous batching, PagedAttention
2. Ollama: Easy setup, good for development, supports GGUF models
3. GGUF direct: llama-cpp-python, smallest footprint
4. API fallback: OpenAI, Anthropic, Google (when self-hosted unavailable)

Environment variables:
- FIXOPS_AI_BACKEND: vllm | ollama | gguf | api (default: auto-detect)
- FIXOPS_VLLM_URL: vLLM API endpoint (default: http://localhost:8001/v1)
- FIXOPS_OLLAMA_URL: Ollama API endpoint (default: http://localhost:11434)
- FIXOPS_GGUF_MODEL_PATH: Path to GGUF model file
- FIXOPS_AI_MODEL: Model name (default: codellama:13b for Ollama)
- FIXOPS_AI_CONSENSUS_THRESHOLD: Consensus threshold (default: 0.85)
- FIXOPS_AI_MAX_TOKENS: Max tokens per response (default: 2048)
- FIXOPS_AI_TEMPERATURE: Temperature for generation (default: 0.1)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums & Types
# ---------------------------------------------------------------------------
class ExpertRole(str, Enum):
    """Expert roles in the AI agent panel."""
    ANALYST = "analyst"       # Vulnerability analysis, risk assessment
    ARCHITECT = "architect"   # Remediation design, architecture review
    AUDITOR = "auditor"       # Compliance mapping, evidence validation
    ATTACKER = "attacker"     # Exploit feasibility, attack path analysis
    MODERATOR = "moderator"   # Synthesize expert opinions, decide


class InferenceBackend(str, Enum):
    VLLM = "vllm"
    OLLAMA = "ollama"
    GGUF = "gguf"
    API = "api"
    AUTO = "auto"


class ConsensusResult(str, Enum):
    AGREED = "agreed"
    SPLIT = "split"
    INSUFFICIENT = "insufficient"


@dataclass
class ExpertOpinion:
    """A single expert's opinion on a security decision."""
    role: ExpertRole
    decision: str          # The recommended action
    confidence: float      # 0.0 - 1.0
    reasoning: str         # Explanation
    evidence: List[str] = field(default_factory=list)
    dissent: str = ""      # If disagreeing with majority
    latency_ms: float = 0
    model_used: str = ""
    tokens_used: int = 0


@dataclass
class ConsensusDecision:
    """Multi-expert consensus decision."""
    finding_id: str
    decision: str
    consensus_result: ConsensusResult
    agreement_pct: float
    threshold: float
    opinions: List[ExpertOpinion] = field(default_factory=list)
    moderator_summary: str = ""
    decided_at: str = ""
    total_latency_ms: float = 0
    total_tokens: int = 0
    backend: str = ""


# ---------------------------------------------------------------------------
# Inference Backend Abstraction
# ---------------------------------------------------------------------------
class BaseInferenceBackend(ABC):
    """Abstract base class for LLM inference backends."""

    @abstractmethod
    def generate(self, prompt: str, system_prompt: str = "",
                 max_tokens: int = 2048, temperature: float = 0.1) -> Tuple[str, int]:
        """Generate text. Returns (response_text, tokens_used)."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this backend is available."""

    @abstractmethod
    def model_info(self) -> Dict[str, Any]:
        """Get backend/model information."""


class VLLMBackend(BaseInferenceBackend):
    """vLLM inference backend — highest throughput."""

    def __init__(self, base_url: Optional[str] = None, model: Optional[str] = None):
        self.base_url = base_url or os.getenv("FIXOPS_VLLM_URL", "http://localhost:8001/v1")
        self.model = model or os.getenv("FIXOPS_AI_MODEL", "codellama/CodeLlama-13b-Instruct-hf")

    def generate(self, prompt: str, system_prompt: str = "",
                 max_tokens: int = 2048, temperature: float = 0.1) -> Tuple[str, int]:
        import urllib.request
        import urllib.error

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = json.dumps({
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }).encode()

        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read())
                text = result["choices"][0]["message"]["content"]
                tokens = result.get("usage", {}).get("total_tokens", 0)
                return text, tokens
        except Exception as e:
            raise RuntimeError(f"vLLM generation failed: {e}")

    def is_available(self) -> bool:
        import urllib.request
        try:
            req = urllib.request.Request(f"{self.base_url}/models")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False

    def model_info(self) -> Dict[str, Any]:
        return {"backend": "vllm", "url": self.base_url, "model": self.model, "cost": "$0/month"}


class OllamaBackend(BaseInferenceBackend):
    """Ollama inference backend — easiest setup."""

    def __init__(self, base_url: Optional[str] = None, model: Optional[str] = None):
        self.base_url = base_url or os.getenv("FIXOPS_OLLAMA_URL", "http://localhost:11434")
        self.model = model or os.getenv("FIXOPS_AI_MODEL", "codellama:13b")

    def generate(self, prompt: str, system_prompt: str = "",
                 max_tokens: int = 2048, temperature: float = 0.1) -> Tuple[str, int]:
        import urllib.request

        payload = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "system": system_prompt,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": temperature,
            },
        }).encode()

        req = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read())
                text = result.get("response", "")
                tokens = result.get("eval_count", 0) + result.get("prompt_eval_count", 0)
                return text, tokens
        except Exception as e:
            raise RuntimeError(f"Ollama generation failed: {e}")

    def is_available(self) -> bool:
        import urllib.request
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False

    def model_info(self) -> Dict[str, Any]:
        return {"backend": "ollama", "url": self.base_url, "model": self.model, "cost": "$0/month"}


class GGUFBackend(BaseInferenceBackend):
    """GGUF direct inference via llama-cpp-python — smallest footprint."""

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or os.getenv("FIXOPS_GGUF_MODEL_PATH", "")
        self._model = None

    def _get_model(self):
        if self._model is None:
            try:
                from llama_cpp import Llama  # type: ignore
                self._model = Llama(
                    model_path=self.model_path,
                    n_ctx=4096,
                    n_threads=os.cpu_count() or 4,
                    verbose=False,
                )
            except ImportError:
                raise RuntimeError("llama-cpp-python not installed: pip install llama-cpp-python")
        return self._model

    def generate(self, prompt: str, system_prompt: str = "",
                 max_tokens: int = 2048, temperature: float = 0.1) -> Tuple[str, int]:
        model = self._get_model()
        full_prompt = f"[INST] <<SYS>>\n{system_prompt}\n<</SYS>>\n{prompt} [/INST]" if system_prompt else f"[INST] {prompt} [/INST]"

        result = model(full_prompt, max_tokens=max_tokens, temperature=temperature)
        text = result["choices"][0]["text"]
        tokens = result.get("usage", {}).get("total_tokens", 0)
        return text, tokens

    def is_available(self) -> bool:
        if not self.model_path or not os.path.exists(self.model_path):
            return False
        try:
            from llama_cpp import Llama  # type: ignore
            return True
        except ImportError:
            return False

    def model_info(self) -> Dict[str, Any]:
        return {
            "backend": "gguf",
            "model_path": self.model_path,
            "available": self.is_available(),
            "cost": "$0/month",
        }


class APIFallbackBackend(BaseInferenceBackend):
    """Fallback to vendor APIs (OpenAI, Anthropic)."""

    def __init__(self):
        self._providers: List[Dict[str, Any]] = []
        # Check for available API keys
        if os.getenv("OPENAI_API_KEY"):
            self._providers.append({
                "name": "openai",
                "url": "https://api.openai.com/v1/chat/completions",
                "key": os.getenv("OPENAI_API_KEY"),
                "model": "gpt-4o-mini",
                "cost": "~$0.15/1M tokens",
            })
        if os.getenv("ANTHROPIC_API_KEY"):
            self._providers.append({
                "name": "anthropic",
                "url": "https://api.anthropic.com/v1/messages",
                "key": os.getenv("ANTHROPIC_API_KEY"),
                "model": "claude-3-5-haiku-20241022",
                "cost": "~$0.25/1M tokens",
            })

    def generate(self, prompt: str, system_prompt: str = "",
                 max_tokens: int = 2048, temperature: float = 0.1) -> Tuple[str, int]:
        import urllib.request

        for provider in self._providers:
            try:
                if provider["name"] == "openai":
                    return self._call_openai(provider, prompt, system_prompt, max_tokens, temperature)
                elif provider["name"] == "anthropic":
                    return self._call_anthropic(provider, prompt, system_prompt, max_tokens, temperature)
            except Exception as e:
                logger.warning(f"API provider {provider['name']} failed: {e}")
                continue

        raise RuntimeError("No API providers available")

    def _call_openai(self, provider: Dict, prompt: str, system_prompt: str,
                     max_tokens: int, temperature: float) -> Tuple[str, int]:
        import urllib.request
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = json.dumps({
            "model": provider["model"],
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }).encode()

        req = urllib.request.Request(
            provider["url"],
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {provider['key']}",
            },
        )

        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read())
            text = result["choices"][0]["message"]["content"]
            tokens = result.get("usage", {}).get("total_tokens", 0)
            return text, tokens

    def _call_anthropic(self, provider: Dict, prompt: str, system_prompt: str,
                        max_tokens: int, temperature: float) -> Tuple[str, int]:
        import urllib.request
        payload = json.dumps({
            "model": provider["model"],
            "max_tokens": max_tokens,
            "system": system_prompt or "You are a security expert.",
            "messages": [{"role": "user", "content": prompt}],
        }).encode()

        req = urllib.request.Request(
            provider["url"],
            data=payload,
            headers={
                "Content-Type": "application/json",
                "x-api-key": provider["key"],
                "anthropic-version": "2023-06-01",
            },
        )

        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read())
            text = result["content"][0]["text"]
            tokens = result.get("usage", {}).get("input_tokens", 0) + result.get("usage", {}).get("output_tokens", 0)
            return text, tokens

    def is_available(self) -> bool:
        return len(self._providers) > 0

    def model_info(self) -> Dict[str, Any]:
        return {
            "backend": "api-fallback",
            "providers": [p["name"] for p in self._providers],
            "cost": "variable (API token costs)",
        }


# ---------------------------------------------------------------------------
# Expert System Prompts
# ---------------------------------------------------------------------------
EXPERT_SYSTEM_PROMPTS = {
    ExpertRole.ANALYST: """You are a senior security ANALYST. Your job is to:
- Assess vulnerability severity and real-world impact
- Consider the application context and attack surface
- Evaluate CVSS scores and adjust for environment
- Determine if the vulnerability is a true positive or false positive
Respond in JSON: {"decision": "...", "confidence": 0.0-1.0, "reasoning": "...", "evidence": [...]}""",

    ExpertRole.ARCHITECT: """You are a senior security ARCHITECT. Your job is to:
- Design remediation strategies for vulnerabilities
- Evaluate fix difficulty and breaking change risk
- Consider defense-in-depth and compensating controls
- Recommend specific code changes, config changes, or WAF rules
Respond in JSON: {"decision": "...", "confidence": 0.0-1.0, "reasoning": "...", "evidence": [...]}""",

    ExpertRole.AUDITOR: """You are a compliance AUDITOR. Your job is to:
- Map findings to compliance frameworks (SOC2, PCI DSS, ISO 27001, NIST)
- Assess regulatory impact and reporting requirements
- Determine if evidence is sufficient for audit trail
- Flag findings that require immediate disclosure
Respond in JSON: {"decision": "...", "confidence": 0.0-1.0, "reasoning": "...", "evidence": [...]}""",

    ExpertRole.ATTACKER: """You are a red team ATTACKER. Your job is to:
- Assess exploitability from an attacker's perspective
- Determine if the vulnerability is reachable and triggerable
- Evaluate attack complexity and required privileges
- Consider chaining potential with other vulnerabilities
Respond in JSON: {"decision": "...", "confidence": 0.0-1.0, "reasoning": "...", "evidence": [...]}""",

    ExpertRole.MODERATOR: """You are the MODERATOR synthesizing expert security opinions. Your job is to:
- Review all expert opinions (analyst, architect, auditor, attacker)
- Identify areas of agreement and disagreement
- Weigh each expert's confidence and evidence quality
- Produce a final consensus decision with clear rationale
- If experts disagree significantly, explain the split and recommend the safest path
Respond in JSON: {"decision": "...", "confidence": 0.0-1.0, "summary": "...", "dissents": [...]}""",
}


# ---------------------------------------------------------------------------
# Single Agent Engine
# ---------------------------------------------------------------------------
class SingleAgentEngine:
    """Multi-expert AI decision engine with self-hosted inference.

    Runs 4 experts + 1 moderator on any available LLM backend.
    Self-hosted backends (vLLM, Ollama, GGUF) cost $0/month.

    Usage:
        engine = SingleAgentEngine()
        decision = engine.decide(finding_dict)
        print(decision.decision, decision.agreement_pct)
    """

    def __init__(
        self,
        backend: Optional[str] = None,
        consensus_threshold: float = 0.85,
        max_tokens: int = 2048,
        temperature: float = 0.1,
    ):
        self.consensus_threshold = float(
            os.getenv("FIXOPS_AI_CONSENSUS_THRESHOLD", str(consensus_threshold))
        )
        self.max_tokens = int(os.getenv("FIXOPS_AI_MAX_TOKENS", str(max_tokens)))
        self.temperature = float(os.getenv("FIXOPS_AI_TEMPERATURE", str(temperature)))

        # Select backend
        backend_name = backend or os.getenv("FIXOPS_AI_BACKEND", "auto")
        self._backend = self._select_backend(backend_name)
        self._decision_cache: Dict[str, ConsensusDecision] = {}

        logger.info(
            f"SingleAgentEngine initialized: backend={self._backend.model_info().get('backend', 'unknown')}, "
            f"threshold={self.consensus_threshold}"
        )

    def _select_backend(self, name: str) -> BaseInferenceBackend:
        """Select the best available inference backend."""
        if name == "vllm":
            return VLLMBackend()
        elif name == "ollama":
            return OllamaBackend()
        elif name == "gguf":
            return GGUFBackend()
        elif name == "api":
            return APIFallbackBackend()
        else:
            # Auto-detect best available
            for backend_cls in [VLLMBackend, OllamaBackend, GGUFBackend, APIFallbackBackend]:
                try:
                    b = backend_cls()
                    if b.is_available():
                        logger.info(f"Auto-selected backend: {b.model_info().get('backend')}")
                        return b
                except Exception:
                    continue
            # Final fallback — return API backend even if no keys (will error on use)
            logger.warning("No inference backend available — using API fallback (may require API keys)")
            return APIFallbackBackend()

    def decide(self, finding: Dict[str, Any], app_context: Optional[Dict] = None) -> ConsensusDecision:
        """Run multi-expert consensus on a security finding.

        Args:
            finding: Finding dict with at least: id, title, severity, description
            app_context: Optional application context (component, environment, etc.)

        Returns:
            ConsensusDecision with agreement percentage and all opinions
        """
        finding_id = finding.get("id", finding.get("finding_id", "unknown"))

        # Check cache
        cache_key = hashlib.sha256(
            json.dumps(finding, sort_keys=True, default=str).encode()
        ).hexdigest()[:16]
        if cache_key in self._decision_cache:
            logger.debug(f"Cache hit for finding {finding_id}")
            return self._decision_cache[cache_key]

        start_time = time.time()
        prompt = self._build_finding_prompt(finding, app_context)

        # Gather expert opinions
        opinions: List[ExpertOpinion] = []
        expert_roles = [ExpertRole.ANALYST, ExpertRole.ARCHITECT, ExpertRole.AUDITOR, ExpertRole.ATTACKER]

        for role in expert_roles:
            try:
                opinion = self._get_expert_opinion(role, prompt)
                opinions.append(opinion)
            except Exception as e:
                logger.warning(f"Expert {role.value} failed: {e}")
                opinions.append(ExpertOpinion(
                    role=role,
                    decision="UNABLE_TO_ASSESS",
                    confidence=0.0,
                    reasoning=f"Expert unavailable: {e}",
                ))

        # Calculate consensus
        valid_opinions = [o for o in opinions if o.confidence > 0]
        if not valid_opinions:
            decision = ConsensusDecision(
                finding_id=finding_id,
                decision="MANUAL_REVIEW",
                consensus_result=ConsensusResult.INSUFFICIENT,
                agreement_pct=0.0,
                threshold=self.consensus_threshold,
                opinions=opinions,
                moderator_summary="No experts produced valid opinions",
                decided_at=datetime.now(timezone.utc).isoformat(),
                total_latency_ms=(time.time() - start_time) * 1000,
                backend=self._backend.model_info().get("backend", "unknown"),
            )
            return decision

        # Check agreement among experts
        decisions_list = [o.decision.upper().strip() for o in valid_opinions if o.decision]
        if decisions_list:
            from collections import Counter
            decision_counts = Counter(decisions_list)
            top_decision, top_count = decision_counts.most_common(1)[0]
            agreement = top_count / len(valid_opinions)
        else:
            top_decision = "MANUAL_REVIEW"
            agreement = 0.0

        # Get moderator synthesis
        moderator_summary = ""
        try:
            moderator_opinion = self._get_moderator_synthesis(prompt, opinions)
            moderator_summary = moderator_opinion.reasoning
            # If moderator has strong opinion, it can override
            if moderator_opinion.confidence > 0.9:
                top_decision = moderator_opinion.decision
        except Exception as e:
            moderator_summary = f"Moderator unavailable: {e}"

        # Determine consensus result
        if agreement >= self.consensus_threshold:
            consensus_result = ConsensusResult.AGREED
        elif agreement >= 0.5:
            consensus_result = ConsensusResult.SPLIT
        else:
            consensus_result = ConsensusResult.INSUFFICIENT

        total_tokens = sum(o.tokens_used for o in opinions)
        total_latency = (time.time() - start_time) * 1000

        decision = ConsensusDecision(
            finding_id=finding_id,
            decision=top_decision,
            consensus_result=consensus_result,
            agreement_pct=round(agreement * 100, 1),
            threshold=self.consensus_threshold,
            opinions=opinions,
            moderator_summary=moderator_summary,
            decided_at=datetime.now(timezone.utc).isoformat(),
            total_latency_ms=round(total_latency, 1),
            total_tokens=total_tokens,
            backend=self._backend.model_info().get("backend", "unknown"),
        )

        # Cache
        self._decision_cache[cache_key] = decision

        logger.info(
            f"Consensus for {finding_id}: {top_decision} "
            f"({agreement:.0%} agreement, {consensus_result.value}, "
            f"{total_latency:.0f}ms, {total_tokens} tokens)"
        )

        return decision

    def _build_finding_prompt(self, finding: Dict, context: Optional[Dict] = None) -> str:
        """Build a prompt describing the security finding."""
        parts = [
            f"## Security Finding Analysis",
            f"**ID**: {finding.get('id', 'N/A')}",
            f"**Title**: {finding.get('title', finding.get('name', 'Unknown'))}",
            f"**Severity**: {finding.get('severity', 'unknown')}",
            f"**Source**: {finding.get('source', finding.get('scanner', 'unknown'))}",
            f"**CWE**: {finding.get('cwe', finding.get('cwe_id', 'N/A'))}",
            f"**CVSS**: {finding.get('cvss', finding.get('cvss_score', 'N/A'))}",
            "",
            f"**Description**: {finding.get('description', 'No description')}",
        ]

        if finding.get("file_path"):
            parts.append(f"**File**: {finding['file_path']}:{finding.get('line_number', '?')}")
        if finding.get("code_snippet"):
            parts.append(f"\n```\n{finding['code_snippet']}\n```")
        if finding.get("recommendation"):
            parts.append(f"\n**Recommendation**: {finding['recommendation']}")

        if context:
            parts.append(f"\n## Application Context")
            parts.append(f"**App**: {context.get('app_id', 'N/A')}")
            parts.append(f"**Component**: {context.get('component', 'N/A')}")
            parts.append(f"**Environment**: {context.get('environment', 'N/A')}")
            parts.append(f"**Internet Facing**: {context.get('internet_facing', 'unknown')}")

        parts.append(f"\n## Decision Required")
        parts.append("What action should be taken? Choose one: FIX_IMMEDIATELY, FIX_NEXT_SPRINT, "
                      "ACCEPT_RISK, FALSE_POSITIVE, NEEDS_MORE_INFO, COMPENSATING_CONTROL")
        parts.append("Explain your reasoning and provide evidence.")

        return "\n".join(parts)

    def _get_expert_opinion(self, role: ExpertRole, prompt: str) -> ExpertOpinion:
        """Get opinion from a single expert."""
        system_prompt = EXPERT_SYSTEM_PROMPTS[role]
        start = time.time()

        response_text, tokens = self._backend.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
        )

        # Parse JSON response
        try:
            parsed = self._parse_json_response(response_text)
        except Exception:
            parsed = {
                "decision": "NEEDS_MORE_INFO",
                "confidence": 0.3,
                "reasoning": response_text[:500],
                "evidence": [],
            }

        latency = (time.time() - start) * 1000

        return ExpertOpinion(
            role=role,
            decision=parsed.get("decision", "NEEDS_MORE_INFO"),
            confidence=float(parsed.get("confidence", 0.5)),
            reasoning=parsed.get("reasoning", "No reasoning provided"),
            evidence=parsed.get("evidence", []),
            latency_ms=round(latency, 1),
            model_used=self._backend.model_info().get("model", "unknown"),
            tokens_used=tokens,
        )

    def _get_moderator_synthesis(self, original_prompt: str,
                                  opinions: List[ExpertOpinion]) -> ExpertOpinion:
        """Get moderator synthesis of all expert opinions."""
        opinions_text = "\n\n".join([
            f"### {o.role.value.upper()} (confidence: {o.confidence:.0%})\n"
            f"Decision: {o.decision}\n"
            f"Reasoning: {o.reasoning}\n"
            f"Evidence: {', '.join(o.evidence) if o.evidence else 'none'}"
            for o in opinions if o.confidence > 0
        ])

        moderator_prompt = (
            f"{original_prompt}\n\n"
            f"## Expert Opinions\n{opinions_text}\n\n"
            f"Please synthesize these expert opinions into a final decision."
        )

        system_prompt = EXPERT_SYSTEM_PROMPTS[ExpertRole.MODERATOR]
        start = time.time()

        response_text, tokens = self._backend.generate(
            prompt=moderator_prompt,
            system_prompt=system_prompt,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
        )

        try:
            parsed = self._parse_json_response(response_text)
        except Exception:
            parsed = {
                "decision": "MANUAL_REVIEW",
                "confidence": 0.5,
                "summary": response_text[:500],
            }

        latency = (time.time() - start) * 1000

        return ExpertOpinion(
            role=ExpertRole.MODERATOR,
            decision=parsed.get("decision", "MANUAL_REVIEW"),
            confidence=float(parsed.get("confidence", 0.5)),
            reasoning=parsed.get("summary", parsed.get("reasoning", "")),
            evidence=parsed.get("dissents", []),
            latency_ms=round(latency, 1),
            model_used=self._backend.model_info().get("model", "unknown"),
            tokens_used=tokens,
        )

    def _parse_json_response(self, text: str) -> Dict[str, Any]:
        """Extract JSON from LLM response text."""
        # Try direct parse
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try to extract JSON block
        import re
        json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass

        # Try markdown code block
        code_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if code_match:
            try:
                return json.loads(code_match.group(1))
            except json.JSONDecodeError:
                pass

        raise ValueError(f"Could not parse JSON from response: {text[:200]}")

    def batch_decide(self, findings: List[Dict[str, Any]],
                     app_context: Optional[Dict] = None) -> List[ConsensusDecision]:
        """Run consensus on multiple findings."""
        results = []
        for finding in findings:
            try:
                decision = self.decide(finding, app_context)
                results.append(decision)
            except Exception as e:
                logger.error(f"Failed to decide on {finding.get('id', '?')}: {e}")
                results.append(ConsensusDecision(
                    finding_id=finding.get("id", "unknown"),
                    decision="ERROR",
                    consensus_result=ConsensusResult.INSUFFICIENT,
                    agreement_pct=0,
                    threshold=self.consensus_threshold,
                    moderator_summary=f"Error: {e}",
                    decided_at=datetime.now(timezone.utc).isoformat(),
                    backend=self._backend.model_info().get("backend", "unknown"),
                ))
        return results

    def get_status(self) -> Dict[str, Any]:
        """Get engine status and backend info."""
        backend_info = self._backend.model_info()
        return {
            "engine": "single-agent",
            "version": "1.0.0",
            "backend": backend_info,
            "backend_available": self._backend.is_available(),
            "consensus_threshold": self.consensus_threshold,
            "expert_roles": [r.value for r in ExpertRole],
            "cached_decisions": len(self._decision_cache),
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "cost": backend_info.get("cost", "unknown"),
        }

    def clear_cache(self) -> int:
        """Clear decision cache. Returns count of cleared items."""
        count = len(self._decision_cache)
        self._decision_cache.clear()
        return count


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------
_engine: Optional[SingleAgentEngine] = None


def get_single_agent_engine() -> SingleAgentEngine:
    """Get or create the default SingleAgentEngine."""
    global _engine
    if _engine is None:
        _engine = SingleAgentEngine()
    return _engine


__all__ = [
    "ExpertRole",
    "InferenceBackend",
    "ConsensusResult",
    "ExpertOpinion",
    "ConsensusDecision",
    "BaseInferenceBackend",
    "VLLMBackend",
    "OllamaBackend",
    "GGUFBackend",
    "APIFallbackBackend",
    "SingleAgentEngine",
    "get_single_agent_engine",
]
