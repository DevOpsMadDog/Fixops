"""SPEC-017 — full Brain-Pipeline on ingest (config-gated, non-blocking, bounded).

Locks the debate-hardened acceptance criteria + guards:
  AC-017-01  default OFF -> dispatched=False, pipeline never constructed
  AC-017-02  FIXOPS_PIPELINE_ON_INGEST=1 -> dispatched=True, BrainPipeline.run called once w/ findings
  AC-017-03  a raising BrainPipeline.run is contained (dispatch still True, semaphore released)
  REQ (SCIF-Accreditor) enforced air-gap + no local LLM -> skipped, never constructed (no egress)
  REQ (Red-Team) per-org token-bucket rate limit drops excess dispatches
"""
from __future__ import annotations

import threading
import time

import pytest

_F = [{"id": "f1", "title": "SQLi", "severity": "high"}]


def _P():
    import apps.api.pipeline_on_ingest as P
    return P


def test_ac_017_01_disabled_never_runs(monkeypatch):
    P = _P()
    monkeypatch.delenv("FIXOPS_PIPELINE_ON_INGEST", raising=False)
    import core.brain_pipeline as BP
    called = []

    class FakeBP:
        def run(self, *a, **k):
            called.append(1)

    monkeypatch.setattr(BP, "BrainPipeline", FakeBP)
    r = P.dispatch_pipeline_on_ingest(_F, "org-a", "test")
    assert r["dispatched"] is False and r["reason"] == "disabled"
    time.sleep(0.2)
    assert called == []  # pipeline never constructed when default-off


def test_ac_017_02_enabled_runs_once(monkeypatch):
    P = _P()
    monkeypatch.setenv("FIXOPS_PIPELINE_ON_INGEST", "1")
    monkeypatch.delenv("FIXOPS_AIRGAP_MODE", raising=False)
    import core.brain_pipeline as BP
    ev = threading.Event()
    seen = {}

    class FakeBP:
        def run(self, pi):
            seen["findings"] = list(getattr(pi, "findings", []))
            ev.set()

    monkeypatch.setattr(BP, "BrainPipeline", FakeBP)
    r = P.dispatch_pipeline_on_ingest(_F, f"org-b-{time.time()}", "test")
    assert r["dispatched"] is True
    assert ev.wait(5), "background pipeline run never fired"
    assert len(seen["findings"]) == 1


def test_ac_017_03_failure_contained(monkeypatch):
    P = _P()
    monkeypatch.setenv("FIXOPS_PIPELINE_ON_INGEST", "1")
    monkeypatch.delenv("FIXOPS_AIRGAP_MODE", raising=False)
    import core.brain_pipeline as BP
    ev = threading.Event()

    class FakeBP:
        def run(self, pi):
            ev.set()
            raise RuntimeError("boom")

    monkeypatch.setattr(BP, "BrainPipeline", FakeBP)
    org = f"org-c-{time.time()}"
    r = P.dispatch_pipeline_on_ingest(_F, org, "test")
    assert r["dispatched"] is True  # dispatch itself never raises
    assert ev.wait(5)
    time.sleep(0.3)  # let the thread finish + release the semaphore
    # semaphore released after failure -> a subsequent dispatch still schedules
    r2 = P.dispatch_pipeline_on_ingest(_F, org, "test")
    assert r2["dispatched"] is True


def test_req_017_airgap_no_local_llm_skips(monkeypatch):
    P = _P()
    monkeypatch.setenv("FIXOPS_PIPELINE_ON_INGEST", "1")
    monkeypatch.setenv("FIXOPS_AIRGAP_MODE", "enforced")
    for k in ("FIXOPS_VLLM_URL", "FIXOPS_OLLAMA_URL", "FIXOPS_LOCAL_LLM_URL",
              "FIXOPS_LLAMACPP_URL", "FIXOPS_LLM_BACKEND"):
        monkeypatch.delenv(k, raising=False)
    import core.brain_pipeline as BP
    called = []

    class FakeBP:
        def run(self, *a, **k):
            called.append(1)

    monkeypatch.setattr(BP, "BrainPipeline", FakeBP)
    r = P.dispatch_pipeline_on_ingest(_F, f"org-d-{time.time()}", "test")
    assert r["dispatched"] is False and r["reason"] == "airgap_no_local_llm"
    time.sleep(0.2)
    assert called == []  # NEVER constructed in enforced air-gap w/o local LLM (no egress)


def test_req_017_airgap_with_local_llm_runs(monkeypatch):
    P = _P()
    monkeypatch.setenv("FIXOPS_PIPELINE_ON_INGEST", "1")
    monkeypatch.setenv("FIXOPS_AIRGAP_MODE", "enforced")
    monkeypatch.setenv("FIXOPS_OLLAMA_URL", "http://localhost:11434")  # local LLM present
    import core.brain_pipeline as BP
    ev = threading.Event()

    class FakeBP:
        def run(self, pi):
            ev.set()

    monkeypatch.setattr(BP, "BrainPipeline", FakeBP)
    r = P.dispatch_pipeline_on_ingest(_F, f"org-e-{time.time()}", "test")
    assert r["dispatched"] is True
    assert ev.wait(5)


def test_req_017_per_org_rate_limit(monkeypatch):
    P = _P()
    monkeypatch.setenv("FIXOPS_PIPELINE_ON_INGEST", "1")
    monkeypatch.setenv("FIXOPS_PIPELINE_RATE_PER_MIN", "2")
    monkeypatch.delenv("FIXOPS_AIRGAP_MODE", raising=False)
    import core.brain_pipeline as BP

    class FakeBP:
        def run(self, pi):
            time.sleep(0.02)

    monkeypatch.setattr(BP, "BrainPipeline", FakeBP)
    org = f"org-rate-{time.time()}"
    reasons = [P.dispatch_pipeline_on_ingest(_F, org, "t")["reason"] for _ in range(5)]
    assert reasons.count("rate_limited") >= 1  # token bucket caps per-org dispatches


def test_pipeline_run_stats_shape():
    P = _P()
    stats = P.pipeline_run_stats()
    assert "by_status" in stats and "enabled" in stats and "max_workers" in stats
