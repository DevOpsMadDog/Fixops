"""Local-backend detection is what makes the air-gapped council possible.

Under ``FIXOPS_AIRGAP_MODE=enforced`` the council refuses to start when no local LLM
backend is found — correct behaviour, since silently calling a cloud API from inside an
accreditation boundary would be far worse. That makes detection safety-critical: a false
negative does not degrade the product, it stops it booting.

Two defects made that likely, both found 2026-08-17:

1. ``_probe_endpoint`` caught ``ValueError, KeyError, RuntimeError, TypeError,
   AttributeError`` — none of which ``urlopen`` raises for a refused connection. It
   raises ``URLError`` (an ``OSError``). Probing a closed port therefore *propagated*
   and aborted the loop at the first backend, so a site running vLLM but not Ollama was
   reported as having no local backend at all and the council would refuse to start.

2. ``VLLM_DEFAULT`` pointed at ``localhost:8000`` — the port the FixOps API itself binds
   in every container we ship — so the vLLM probe interrogated our own API.
   ``llm_providers`` documented 8001 for the same thing; the two modules disagreed.
"""

from __future__ import annotations

import http.server
import threading
from contextlib import contextmanager
from typing import Iterator

import pytest

from core.airgap_config import LLMBackend, LocalLLMRouter


@contextmanager
def _serving(payload: bytes = b'{"data": []}') -> Iterator[int]:
    """Run a throwaway HTTP server and yield its port."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 — stdlib naming
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: object) -> None:  # silence test output
            return

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def test_probe_returns_false_for_a_closed_port() -> None:
    """Absence is the ordinary case; a probe must report it, never raise."""
    router = LocalLLMRouter()
    assert router._probe_endpoint("http://127.0.0.1:59999/v1/models", timeout=1.0) is False


def test_probe_returns_true_for_a_live_endpoint() -> None:
    router = LocalLLMRouter()
    with _serving() as port:
        assert router._probe_endpoint(f"http://127.0.0.1:{port}/v1/models", timeout=2.0) is True


def test_vllm_is_found_when_ollama_is_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """The exact SCIF failure: vLLM running, Ollama not.

    Before the fix the Ollama probe raised and detection never reached vLLM, so a
    correctly configured air-gapped deployment was reported as having no backend.
    """
    router = LocalLLMRouter()
    with _serving(b'{"data": [{"id": "local-model"}]}') as port:
        # Ollama pointed at a closed port; vLLM at the live one.
        monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:59998")
        monkeypatch.setenv("FIXOPS_VLLM_URL", f"http://127.0.0.1:{port}/v1")

        config = router.detect_available_backend()

    assert config.available is True, "vLLM was running but was not detected"
    assert config.backend == LLMBackend.VLLM.value


def test_no_backend_reports_unavailable_rather_than_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    router = LocalLLMRouter()
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:59998")
    monkeypatch.setenv("FIXOPS_VLLM_URL", "http://127.0.0.1:59997")
    monkeypatch.setenv("FIXOPS_LLAMACPP_URL", "http://127.0.0.1:59996")

    config = router.detect_available_backend()

    assert config.available is False
    assert config.backend == LLMBackend.NONE.value


def test_vllm_default_does_not_collide_with_our_own_api_port() -> None:
    """The API binds 8000 in every container we ship; probing it finds ourselves."""
    assert "8000" not in LocalLLMRouter.VLLM_DEFAULT, (
        "vLLM default probes the port the FixOps API itself listens on"
    )


def test_backend_urls_honour_deployment_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    """An air-gapped site runs inference on its own host, not on our defaults."""
    monkeypatch.setenv("FIXOPS_VLLM_URL", "http://gpu-host:8001/v1")
    urls = {backend: f"{base}{path}" for backend, base, path in LocalLLMRouter()._backend_urls()}
    # "/v1" must not be doubled when the documented suffix is supplied.
    assert urls[LLMBackend.VLLM] == "http://gpu-host:8001/v1/models"
