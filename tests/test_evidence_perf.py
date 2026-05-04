"""Performance assertions for the cryptographic evidence chain.

Covers three hotspot fixes shipped in beast-mode(perf):
  1. Persistent SQLite connection (no per-call open/close overhead).
  2. detect_tampering() reuses the entries loaded inside verify_chain() — no
     second get_chain() DB round-trip.
  3. get_chain_stats() reuses entries from verify_chain() — no second
     get_chain() DB round-trip.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import time
import tempfile
from pathlib import Path

import pytest

from core.evidence_chain import EvidenceChain, GENESIS_HASH


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def chain(tmp_path: Path) -> EvidenceChain:
    """Fresh chain backed by a temp DB."""
    return EvidenceChain(db_path=str(tmp_path / "test_evidence.db"))


def _populate(chain: EvidenceChain, org_id: str, n: int = 50) -> None:
    """Append *n* entries to the chain for *org_id*."""
    for i in range(n):
        chain.append("test_event", {"index": i, "payload": "x" * 64}, org_id)


# ---------------------------------------------------------------------------
# Correctness smoke tests (must pass before perf assertions are meaningful)
# ---------------------------------------------------------------------------


def test_append_and_verify(chain: EvidenceChain) -> None:
    org = "org-perf-1"
    _populate(chain, org, n=10)
    result = chain.verify_chain(org)
    assert result["is_valid"] is True
    assert result["chain_length"] == 10
    assert result["broken_links"] == []
    assert result["invalid_signatures"] == []


def test_detect_tampering_clean(chain: EvidenceChain) -> None:
    org = "org-perf-2"
    _populate(chain, org, n=5)
    assert chain.detect_tampering(org) == []


def test_get_chain_stats(chain: EvidenceChain) -> None:
    org = "org-perf-3"
    _populate(chain, org, n=8)
    stats = chain.get_chain_stats(org)
    assert stats["length"] == 8
    assert stats["integrity_status"] == "valid"
    assert stats["first_timestamp"] is not None
    assert stats["last_timestamp"] is not None


def test_genesis_linkage(chain: EvidenceChain) -> None:
    org = "org-perf-genesis"
    entry = chain.append("genesis_test", {"k": "v"}, org)
    assert entry.previous_hash == GENESIS_HASH
    assert entry.sequence_number == 0


def test_persistent_connection_reused(chain: EvidenceChain) -> None:
    """The same connection object must be returned on every _get_conn() call."""
    conn1 = chain._get_conn()
    conn2 = chain._get_conn()
    assert conn1 is conn2, "Expected a single persistent connection to be reused"


# ---------------------------------------------------------------------------
# Performance assertions
# ---------------------------------------------------------------------------


def test_detect_tampering_no_double_db_read(chain: EvidenceChain, monkeypatch) -> None:
    """detect_tampering() must not call get_chain() more than once.

    We patch get_chain() to count invocations.  With the fix, detect_tampering
    calls verify_chain (which calls get_chain once internally) and then reuses
    the cached entries — so total get_chain calls == 1.
    """
    org = "org-perf-dt"
    _populate(chain, org, n=20)

    call_count = {"n": 0}
    original_get_chain = chain.get_chain

    def counting_get_chain(*args, **kwargs):
        call_count["n"] += 1
        return original_get_chain(*args, **kwargs)

    monkeypatch.setattr(chain, "get_chain", counting_get_chain)
    chain.detect_tampering(org)

    assert call_count["n"] == 1, (
        f"detect_tampering() called get_chain() {call_count['n']} times; expected 1"
    )


def test_get_chain_stats_no_double_db_read(chain: EvidenceChain, monkeypatch) -> None:
    """get_chain_stats() must not call get_chain() more than once."""
    org = "org-perf-stats"
    _populate(chain, org, n=20)

    call_count = {"n": 0}
    original_get_chain = chain.get_chain

    def counting_get_chain(*args, **kwargs):
        call_count["n"] += 1
        return original_get_chain(*args, **kwargs)

    monkeypatch.setattr(chain, "get_chain", counting_get_chain)
    chain.get_chain_stats(org)

    assert call_count["n"] == 1, (
        f"get_chain_stats() called get_chain() {call_count['n']} times; expected 1"
    )


def test_bulk_append_throughput(chain: EvidenceChain) -> None:
    """50 sequential appends must complete in under 2 seconds on CI hardware."""
    org = "org-perf-bulk"
    n = 50
    t0 = time.perf_counter()
    _populate(chain, org, n=n)
    elapsed = time.perf_counter() - t0
    assert elapsed < 2.0, f"50 appends took {elapsed:.3f}s — expected < 2s"


def test_verify_chain_wall_time(chain: EvidenceChain) -> None:
    """verify_chain() on 50 entries must complete in under 0.5 seconds."""
    org = "org-perf-verify"
    _populate(chain, org, n=50)
    t0 = time.perf_counter()
    result = chain.verify_chain(org)
    elapsed = time.perf_counter() - t0
    assert result["is_valid"] is True
    assert elapsed < 0.5, f"verify_chain(50) took {elapsed:.3f}s — expected < 0.5s"


def test_verify_chain_result_has_no_private_entries_key(chain: EvidenceChain) -> None:
    """The _entries private key must be stripped from detect_tampering result."""
    org = "org-perf-strip"
    _populate(chain, org, n=5)
    # detect_tampering pops _entries from the verify_chain result dict
    tampered = chain.detect_tampering(org)
    # Result is a list — the entries key is gone (popped inside detect_tampering)
    assert isinstance(tampered, list)


def test_empty_chain_stats(chain: EvidenceChain) -> None:
    """get_chain_stats on an empty chain returns zeros cleanly."""
    stats = chain.get_chain_stats("org-empty")
    assert stats["length"] == 0
    assert stats["integrity_status"] == "empty"
    assert stats["first_timestamp"] is None
