"""SPEC-003 acceptance tests — Local LLM Council (real air-gap inference).

Covers:
  AC-003-01: stub local backend → verdict is_real_inference=True,
             source=local_model:..., reasoning derived from stub completion.
  AC-003-02: no backend → verdict is_real_inference=False, source=heuristic,
             reasoning explicitly labelled heuristic, verdict still produced.
  AC-003-03: provider selection prefers local AirGapLLMProvider when a
             backend is present.
  AC-003-04: scripts/llm_distill_train.py --dry-run exits 0;
             DISTILLATION_THRESHOLD constant is 5000.

Run with:
    python -m pytest tests/test_local_council.py -v --timeout=15
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional
from unittest.mock import MagicMock, patch

import pytest

# Add suite paths
REPO = Path(__file__).parent.parent
for p in ["suite-core", "suite-api", "suite-integrations", "suite-evidence-risk",
          "suite-attack", "suite-feeds"]:
    pp = str(REPO / p)
    if pp not in sys.path:
        sys.path.insert(0, pp)

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------
from core.airgap_config import LLMBackend, LocalLLMConfig, LocalLLMRouter
from core.llm_council import CouncilFactory, CouncilMember, LLMCouncilEngine
from core.llm_providers import (
    AirGapLLMProvider,
    BaseLLMProvider,
    DeterministicLLMProvider,
    LLMResponse,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CANNED_COMPLETION = {
    "recommended_action": "remediate_critical",
    "confidence": 0.92,
    "reasoning": "Stub local-model reasoning: CVE-2099-9999 is trivially exploitable.",
    "mitre_techniques": ["T1190"],
    "compliance_concerns": ["PCI-DSS"],
    "attack_vectors": ["network"],
}

_CANNED_JSON_STR = json.dumps(_CANNED_COMPLETION)


def _make_ollama_response(text: str) -> Dict[str, Any]:
    """Simulate Ollama /api/chat response format."""
    return {"message": {"content": text}}


def _make_detected_config(backend: str = "ollama", model: str = "qwen2.5:7b") -> LocalLLMConfig:
    """Return a LocalLLMConfig that marks the backend as available."""
    return LocalLLMConfig(
        backend=backend,
        endpoint="http://localhost:11434",
        model_name=model,
        available=True,
    )


# ---------------------------------------------------------------------------
# AC-003-01: stub local backend → real inference verdict
# ---------------------------------------------------------------------------

class TestAC00301_RealInferenceWithStubBackend:
    """When LocalLLMRouter.detect_available_backend() returns a live config,
    AirGapLLMProvider.analyse() calls the backend and the returned verdict
    carries is_real_inference=True and source=local_model:...
    """

    def _build_provider_with_stub(self) -> AirGapLLMProvider:
        """Build an AirGapLLMProvider whose HTTP layer is monkeypatched."""
        detected_cfg = _make_detected_config()

        # Build a real router but monkeypatch detect_available_backend
        router = LocalLLMRouter()
        router.detect_available_backend = MagicMock(return_value=detected_cfg)
        router.config = detected_cfg

        provider = AirGapLLMProvider(
            name="test-airgap",
            local_llm_router=router,
        )

        # Monkeypatch the HTTP session so no real network call is made
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value=_make_ollama_response(_CANNED_JSON_STR))
        provider._session = MagicMock()
        provider._session.post = MagicMock(return_value=mock_resp)

        return provider

    def test_is_real_inference_true(self):
        """is_real_inference must be True when the stub backend responds."""
        provider = self._build_provider_with_stub()
        result = provider.analyse(
            prompt="Analyse CVE-2099-9999",
            context={"service_name": "test-svc"},
            default_action="investigate",
            default_confidence=0.5,
            default_reasoning="fallback",
        )
        assert result.is_real_inference is True, (
            f"Expected is_real_inference=True, got {result.is_real_inference}"
        )

    def test_source_is_local_model(self):
        """source must be 'local_model:<backend>:<model>'."""
        provider = self._build_provider_with_stub()
        result = provider.analyse(
            prompt="Analyse CVE-2099-9999",
            context={"service_name": "test-svc"},
            default_action="investigate",
            default_confidence=0.5,
            default_reasoning="fallback",
        )
        assert result.source.startswith("local_model:"), (
            f"Expected source starting with 'local_model:', got {result.source!r}"
        )
        # Must contain backend and model
        parts = result.source.split(":")
        assert len(parts) >= 3, f"Expected 'local_model:<backend>:<model>', got {result.source!r}"
        assert parts[1] == "ollama", f"Expected backend=ollama, got {parts[1]!r}"

    def test_reasoning_from_stub_completion(self):
        """Reasoning must derive from the canned model output, not the default."""
        provider = self._build_provider_with_stub()
        result = provider.analyse(
            prompt="Analyse CVE-2099-9999",
            context={"service_name": "test-svc"},
            default_action="investigate",
            default_confidence=0.5,
            default_reasoning="fallback-reasoning-that-must-not-appear",
        )
        assert "trivially exploitable" in result.reasoning, (
            f"Reasoning should derive from stub model output, got: {result.reasoning!r}"
        )
        assert "fallback-reasoning-that-must-not-appear" not in result.reasoning, (
            "Default reasoning leaked into model verdict"
        )

    def test_model_field_set(self):
        """model field must be the model name from the backend config."""
        provider = self._build_provider_with_stub()
        result = provider.analyse(
            prompt="Analyse CVE-2099-9999",
            context={},
            default_action="investigate",
            default_confidence=0.5,
            default_reasoning="fallback",
        )
        assert result.model is not None, "model field must not be None for real inference"
        assert result.model == "qwen2.5:7b", f"Expected 'qwen2.5:7b', got {result.model!r}"

    def test_recommended_action_from_model(self):
        """Recommended action should be parsed from the model response."""
        provider = self._build_provider_with_stub()
        result = provider.analyse(
            prompt="Analyse CVE-2099-9999",
            context={},
            default_action="investigate",
            default_confidence=0.5,
            default_reasoning="fallback",
        )
        assert result.recommended_action == "remediate_critical"
        assert abs(result.confidence - 0.92) < 0.01


# ---------------------------------------------------------------------------
# AC-003-02: no backend → labelled heuristic verdict, never hangs
# ---------------------------------------------------------------------------

class TestAC00302_HeuristicFallbackNoBackend:
    """When no local backend is available the council must still produce a
    verdict within test timeout, with is_real_inference=False and
    source='heuristic'.
    """

    def test_deterministic_provider_is_heuristic(self):
        """DeterministicLLMProvider must always return is_real_inference=False."""
        prov = DeterministicLLMProvider("det-fallback")
        result = prov.analyse(
            prompt="analyse this",
            context={},
            default_action="investigate",
            default_confidence=0.5,
            default_reasoning="heuristic default",
        )
        assert result.is_real_inference is False
        assert result.source == "heuristic"
        assert result.model is None

    def test_deterministic_reasoning_labelled(self):
        """Heuristic reasoning must contain the '[heuristic:' label."""
        prov = DeterministicLLMProvider("det-fallback")
        result = prov.analyse(
            prompt="analyse this",
            context={},
            default_action="investigate",
            default_confidence=0.5,
            default_reasoning="base-reasoning",
        )
        assert "[heuristic:" in result.reasoning, (
            f"Heuristic label missing from reasoning: {result.reasoning!r}"
        )

    def test_airgap_backend_down_fallback(self):
        """AirGapLLMProvider with a backend that times out produces heuristic fallback."""
        detected_cfg = _make_detected_config()
        router = LocalLLMRouter()
        router.detect_available_backend = MagicMock(return_value=detected_cfg)
        router.config = detected_cfg

        provider = AirGapLLMProvider(
            name="test-airgap-down",
            local_llm_router=router,
        )
        # Make the HTTP POST raise a connection error — backend is "down"
        import requests
        provider._session = MagicMock()
        provider._session.post = MagicMock(
            side_effect=requests.ConnectionError("connection refused")
        )

        result = provider.analyse(
            prompt="test",
            context={},
            default_action="defer",
            default_confidence=0.4,
            default_reasoning="base",
        )
        assert result.is_real_inference is False, (
            "Backend-down path must not claim real inference"
        )
        assert result.source == "heuristic", (
            f"Expected source='heuristic', got {result.source!r}"
        )
        assert "[heuristic:" in result.reasoning, (
            f"Heuristic label missing from reasoning: {result.reasoning!r}"
        )

    def test_council_with_no_backend_produces_verdict(self):
        """Single-member deterministic council still produces a verdict (no hang)."""
        det = DeterministicLLMProvider("det")
        council = LLMCouncilEngine(
            members=[CouncilMember(provider=det, expertise="vulnerability_assessment")],
            chairman=det,
            escalation_provider=None,
            confidence_threshold=0.0,
            max_disagreement=99,
        )
        verdict = council.convene(
            finding={"title": "Test CVE", "severity": "high", "cve_id": "CVE-0000-0001"},
            context={"service_name": "test"},
        )
        assert verdict is not None
        assert verdict.action in (
            "remediate_critical", "remediate_high", "accept_risk",
            "defer", "investigate", "false_positive", "review",
        ), f"Unexpected action: {verdict.action!r}"


# ---------------------------------------------------------------------------
# AC-003-03: provider selection prefers local when backend is present
# ---------------------------------------------------------------------------

class TestAC00303_ProviderSelectionPrefersLocal:
    """CouncilFactory.create_security_council() must return a council whose
    members use AirGapLLMProvider (not DeterministicLLMProvider) when a
    local backend is detected.
    """

    def _patch_local_backend_available(self):
        """Context manager that makes LocalLLMRouter report a live backend."""
        detected_cfg = _make_detected_config()

        def _fake_detect(self_router):
            return detected_cfg

        return patch.object(LocalLLMRouter, "detect_available_backend", _fake_detect)

    def _patch_airgap_http(self):
        """Patch AirGapLLMProvider._session.post so no real network call fires."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value=_make_ollama_response(_CANNED_JSON_STR))

        original_init = AirGapLLMProvider.__init__

        def _patched_init(self_p, *args, **kwargs):
            original_init(self_p, *args, **kwargs)
            self_p._session = MagicMock()
            self_p._session.post = MagicMock(return_value=mock_resp)

        return patch.object(AirGapLLMProvider, "__init__", _patched_init)

    def test_factory_prefers_airgap_provider(self):
        """When local backend detected, factory council members should be AirGapLLMProvider."""
        with self._patch_local_backend_available(), self._patch_airgap_http():
            # Disable air-gap mode so we're testing the auto-selection path
            with patch.dict("os.environ", {
                "FIXOPS_AIRGAP_MODE": "",
                "FIXOPS_COUNCIL_PRESET": "auto",
            }):
                factory = CouncilFactory()
                council = factory.create_security_council()

        provider_types = [type(m.provider).__name__ for m in council.members]
        assert any(t == "AirGapLLMProvider" for t in provider_types), (
            f"Expected at least one AirGapLLMProvider in council, got: {provider_types}"
        )

    def test_factory_no_backend_uses_deterministic_or_keyed(self):
        """When no local backend is reachable, factory falls through to cloud/deterministic."""
        def _fake_detect_none(self_router):
            return LocalLLMConfig(backend="none", available=False)

        with patch.object(LocalLLMRouter, "detect_available_backend", _fake_detect_none):
            with patch.dict("os.environ", {
                "FIXOPS_AIRGAP_MODE": "",
                "FIXOPS_COUNCIL_PRESET": "auto",
                # Clear any real keys so we fall to deterministic
                "OPENROUTER_API_KEY": "",
                "MULEROUTER_API_KEY": "",
                "OPENAI_API_KEY": "",
                "ANTHROPIC_API_KEY": "",
                "GOOGLE_API_KEY": "",
            }):
                factory = CouncilFactory()
                council = factory.create_security_council()

        # All members should be deterministic (no keys, no local backend)
        provider_types = [type(m.provider).__name__ for m in council.members]
        assert not any(t == "AirGapLLMProvider" for t in provider_types), (
            f"Should not have AirGapLLMProvider without a backend: {provider_types}"
        )

    def test_local_council_verdict_is_real_inference(self):
        """End-to-end: factory council with local backend produces is_real_inference=True."""
        detected_cfg = _make_detected_config()

        def _fake_detect(self_router):
            return detected_cfg

        # Build a canned HTTP response for the stub
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value=_make_ollama_response(_CANNED_JSON_STR))

        original_airgap_init = AirGapLLMProvider.__init__

        def _patched_airgap_init(self_p, *args, **kwargs):
            original_airgap_init(self_p, *args, **kwargs)
            self_p._session = MagicMock()
            self_p._session.post = MagicMock(return_value=mock_resp)

        with patch.object(LocalLLMRouter, "detect_available_backend", _fake_detect), \
             patch.object(AirGapLLMProvider, "__init__", _patched_airgap_init):
            with patch.dict("os.environ", {
                "FIXOPS_AIRGAP_MODE": "",
                "FIXOPS_COUNCIL_PRESET": "auto",
            }):
                factory = CouncilFactory()
                council = factory.create_security_council(
                    confidence_threshold=0.0,  # never escalate
                    max_disagreement=99,
                )
                verdict = council.convene(
                    finding={
                        "title": "CVE-2099-SCIF",
                        "severity": "critical",
                        "cve_id": "CVE-2099-9999",
                    },
                    context={"service_name": "test-svc"},
                )

        # The verdict from the local model should carry real inference
        # through at least one member's analysis
        raw_analyses = getattr(verdict, "raw_analyses", [])
        real_inferences = [
            a for a in raw_analyses
            if a.metadata.get("is_real_inference") or
               (a.metadata.get("source", "").startswith("local_model:"))
        ]
        assert len(real_inferences) >= 1, (
            f"Expected at least 1 real-inference analysis, "
            f"got metadata: {[a.metadata for a in raw_analyses]}"
        )


# ---------------------------------------------------------------------------
# AC-003-04: distillation threshold constant + llm_distill_train.py --help
# ---------------------------------------------------------------------------

class TestAC00304_DistillationThreshold:
    """DISTILLATION_THRESHOLD is 5000; llm_distill_train.py --dry-run exits 0."""

    def test_threshold_constant_is_5000(self):
        """DISTILLATION_THRESHOLD in llm_learning_loop must equal 5000."""
        from core.llm_learning_loop import DISTILLATION_THRESHOLD
        assert DISTILLATION_THRESHOLD == 5000, (
            f"Expected 5000, got {DISTILLATION_THRESHOLD}. "
            "SPEC-003 REQ-003-05 requires the threshold to be lowered to 5000."
        )

    def test_llm_distill_train_dry_run_exits_zero(self):
        """scripts/llm_distill_train.py --dry-run must exit with code 0."""
        import subprocess
        script = REPO / "scripts" / "llm_distill_train.py"
        assert script.exists(), f"Script not found: {script}"
        result = subprocess.run(
            [sys.executable, str(script), "--dry-run"],
            capture_output=True,
            timeout=30,
            cwd=str(REPO),
        )
        assert result.returncode == 0, (
            f"--dry-run exited with {result.returncode}.\n"
            f"stdout: {result.stdout.decode()[:500]}\n"
            f"stderr: {result.stderr.decode()[:500]}"
        )


# ---------------------------------------------------------------------------
# Honest-labelling invariant tests
# ---------------------------------------------------------------------------

class TestHonestLabellingInvariants:
    """Cross-provider invariant: a heuristic verdict must NEVER carry
    is_real_inference=True, and a real-inference verdict must NEVER carry
    source='heuristic'.
    """

    def test_base_provider_never_real_inference(self):
        """BaseLLMProvider.analyse() must always return is_real_inference=False."""
        prov = BaseLLMProvider("base")
        result = prov.analyse(
            prompt="test",
            context={},
            default_action="investigate",
            default_confidence=0.5,
            default_reasoning="default",
        )
        assert result.is_real_inference is False
        assert result.source == "heuristic"

    def test_heuristic_reasoning_label_present(self):
        """All heuristic paths must include '[heuristic:' in reasoning."""
        for cls in (BaseLLMProvider, DeterministicLLMProvider):
            prov = cls("test-prov")
            result = prov.analyse(
                prompt="test",
                context={},
                default_action="investigate",
                default_confidence=0.5,
                default_reasoning="something",
            )
            assert "[heuristic:" in result.reasoning, (
                f"{cls.__name__} did not label reasoning as heuristic: "
                f"{result.reasoning!r}"
            )

    def test_airgap_success_never_heuristic_source(self):
        """AirGapLLMProvider success path must not use source='heuristic'."""
        detected_cfg = _make_detected_config()
        router = LocalLLMRouter()
        router.detect_available_backend = MagicMock(return_value=detected_cfg)
        router.config = detected_cfg

        provider = AirGapLLMProvider(name="test-honest", local_llm_router=router)
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value=_make_ollama_response(_CANNED_JSON_STR))
        provider._session = MagicMock()
        provider._session.post = MagicMock(return_value=mock_resp)

        result = provider.analyse(
            prompt="test",
            context={},
            default_action="investigate",
            default_confidence=0.5,
            default_reasoning="fallback",
        )
        assert result.source != "heuristic", (
            "Real inference path must not carry source='heuristic'"
        )
        assert result.is_real_inference is True

    def test_no_internet_call_from_airgap_provider(self):
        """AirGapLLMProvider must only call localhost endpoints (REQ-003-06).

        The stub patches the session so we verify the called URL is localhost.
        """
        detected_cfg = _make_detected_config(
            backend="ollama", model="llama3:8b"
        )
        router = LocalLLMRouter()
        router.detect_available_backend = MagicMock(return_value=detected_cfg)
        router.config = detected_cfg

        provider = AirGapLLMProvider(name="test-local-only", local_llm_router=router)

        posted_urls: List[str] = []
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value=_make_ollama_response(_CANNED_JSON_STR))

        def _capture_post(url, **kwargs):
            posted_urls.append(url)
            return mock_resp

        provider._session = MagicMock()
        provider._session.post = _capture_post

        provider.analyse(
            prompt="test",
            context={},
            default_action="investigate",
            default_confidence=0.5,
            default_reasoning="fallback",
        )

        assert posted_urls, "No POST was made — provider did not attempt inference"
        for url in posted_urls:
            assert "localhost" in url or "127.0.0.1" in url, (
                f"REQ-003-06 violated: AirGapLLMProvider called non-localhost URL: {url!r}"
            )
