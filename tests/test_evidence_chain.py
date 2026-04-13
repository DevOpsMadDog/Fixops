"""
Tests for the cryptographic evidence chain (suite-core/core/evidence_chain.py)
and its FastAPI router (suite-api/apps/api/evidence_chain_router.py).

Run:
    pytest tests/test_evidence_chain.py -v --timeout=10
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest

# ── path setup ──────────────────────────────────────────────────────────────
_repo = Path(__file__).parent.parent
for _p in [str(_repo / "suite-core"), str(_repo / "suite-api")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from core.evidence_chain import (
    GENESIS_HASH,
    ChainEntry,
    EvidenceChain,
    _hmac_sign,
    _hmac_verify,
    _sha256,
)


# ── fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def chain(tmp_path):
    """Fresh EvidenceChain backed by a temp SQLite database."""
    db = str(tmp_path / "test_evidence.db")
    return EvidenceChain(db_path=db)


@pytest.fixture
def org():
    return "test-org-001"


@pytest.fixture
def org2():
    return "test-org-002"


# ── unit helpers ──────────────────────────────────────────────────────────────


class TestHelpers:
    def test_sha256_produces_64_char_hex(self):
        result = _sha256("hello world")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_sha256_deterministic(self):
        assert _sha256("fixops") == _sha256("fixops")

    def test_sha256_different_inputs(self):
        assert _sha256("a") != _sha256("b")

    def test_hmac_sign_returns_64_char_hex(self):
        sig = _hmac_sign("id-1", 0, "datahash", GENESIS_HASH)
        assert len(sig) == 64

    def test_hmac_sign_deterministic(self):
        s1 = _hmac_sign("id-1", 0, "dh", GENESIS_HASH)
        s2 = _hmac_sign("id-1", 0, "dh", GENESIS_HASH)
        assert s1 == s2

    def test_hmac_verify_valid_entry(self):
        entry_id = "test-id-abc"
        seq = 5
        dh = "aabbcc"
        ph = GENESIS_HASH
        sig = _hmac_sign(entry_id, seq, dh, ph)
        entry = ChainEntry(
            id=entry_id,
            sequence_number=seq,
            event_type="test",
            data_hash=dh,
            previous_hash=ph,
            timestamp=datetime.now(timezone.utc),
            signature=sig,
            org_id="org",
        )
        assert _hmac_verify(entry) is True

    def test_hmac_verify_tampered_entry(self):
        entry_id = "test-id-xyz"
        seq = 3
        dh = "deadbeef"
        ph = GENESIS_HASH
        sig = _hmac_sign(entry_id, seq, dh, ph)
        entry = ChainEntry(
            id=entry_id,
            sequence_number=seq,
            event_type="test",
            data_hash="000000",  # tampered!
            previous_hash=ph,
            timestamp=datetime.now(timezone.utc),
            signature=sig,
            org_id="org",
        )
        assert _hmac_verify(entry) is False

    def test_genesis_hash_is_64_zeros(self):
        assert GENESIS_HASH == "0" * 64


# ── ChainEntry model ──────────────────────────────────────────────────────────


class TestChainEntry:
    def test_default_id_is_uuid(self):
        entry = ChainEntry(
            sequence_number=0,
            event_type="login",
            data_hash="aabb",
            previous_hash=GENESIS_HASH,
            timestamp=datetime.now(timezone.utc),
            signature="sig",
            org_id="org1",
        )
        assert len(entry.id) == 36  # UUID4 format

    def test_fields_accessible(self):
        ts = datetime.now(timezone.utc)
        entry = ChainEntry(
            id="custom-id",
            sequence_number=7,
            event_type="scan_complete",
            data_hash="aabb",
            previous_hash=GENESIS_HASH,
            timestamp=ts,
            signature="mysig",
            org_id="myorg",
        )
        assert entry.sequence_number == 7
        assert entry.event_type == "scan_complete"
        assert entry.org_id == "myorg"


# ── EvidenceChain core operations ─────────────────────────────────────────────


class TestAppend:
    def test_genesis_entry_has_sequence_zero(self, chain, org):
        entry = chain.append("login", {"user": "alice"}, org)
        assert entry.sequence_number == 0

    def test_genesis_previous_hash_is_zeros(self, chain, org):
        entry = chain.append("login", {"user": "alice"}, org)
        assert entry.previous_hash == GENESIS_HASH

    def test_second_entry_has_sequence_one(self, chain, org):
        chain.append("login", {"user": "alice"}, org)
        e2 = chain.append("logout", {"user": "alice"}, org)
        assert e2.sequence_number == 1

    def test_second_entry_previous_hash_not_genesis(self, chain, org):
        chain.append("login", {"user": "alice"}, org)
        e2 = chain.append("logout", {"user": "alice"}, org)
        assert e2.previous_hash != GENESIS_HASH

    def test_data_hash_is_sha256_of_json(self, chain, org):
        data = {"finding": "CVE-2024-1234", "severity": "critical"}
        entry = chain.append("scan_finding", data, org)
        expected = _sha256(json.dumps(data, sort_keys=True, default=str))
        assert entry.data_hash == expected

    def test_entry_has_valid_hmac_signature(self, chain, org):
        entry = chain.append("event", {"k": "v"}, org)
        assert _hmac_verify(entry) is True

    def test_separate_orgs_have_independent_genesis(self, chain, org, org2):
        e1 = chain.append("event", {}, org)
        e2 = chain.append("event", {}, org2)
        # Both start at sequence 0 with genesis previous_hash
        assert e1.sequence_number == 0
        assert e2.sequence_number == 0
        assert e1.previous_hash == GENESIS_HASH
        assert e2.previous_hash == GENESIS_HASH

    def test_org_chains_are_independent(self, chain, org, org2):
        for i in range(3):
            chain.append("event", {"i": i}, org)
        chain.append("event", {}, org2)
        assert chain.get_chain_length(org) == 3
        assert chain.get_chain_length(org2) == 1


class TestGetLatest:
    def test_empty_chain_returns_none(self, chain, org):
        assert chain.get_latest(org) is None

    def test_returns_last_appended(self, chain, org):
        chain.append("a", {}, org)
        chain.append("b", {}, org)
        e3 = chain.append("c", {}, org)
        latest = chain.get_latest(org)
        assert latest is not None
        assert latest.id == e3.id
        assert latest.sequence_number == 2


class TestGetChain:
    def test_empty_chain_returns_empty_list(self, chain, org):
        assert chain.get_chain(org) == []

    def test_returns_all_entries_in_order(self, chain, org):
        for i in range(5):
            chain.append(f"ev-{i}", {"i": i}, org)
        entries = chain.get_chain(org)
        assert len(entries) == 5
        for idx, e in enumerate(entries):
            assert e.sequence_number == idx

    def test_start_parameter(self, chain, org):
        for i in range(5):
            chain.append("ev", {"i": i}, org)
        entries = chain.get_chain(org, start=2)
        assert len(entries) == 3
        assert entries[0].sequence_number == 2

    def test_start_and_end_parameters(self, chain, org):
        for i in range(6):
            chain.append("ev", {"i": i}, org)
        entries = chain.get_chain(org, start=1, end=3)
        assert len(entries) == 3
        assert [e.sequence_number for e in entries] == [1, 2, 3]

    def test_end_beyond_chain_length(self, chain, org):
        for i in range(3):
            chain.append("ev", {}, org)
        entries = chain.get_chain(org, start=0, end=100)
        assert len(entries) == 3


class TestGetChainLength:
    def test_empty_chain_is_zero(self, chain, org):
        assert chain.get_chain_length(org) == 0

    def test_counts_correctly(self, chain, org):
        for i in range(7):
            chain.append("ev", {}, org)
        assert chain.get_chain_length(org) == 7


# ── verify_chain ──────────────────────────────────────────────────────────────


class TestVerifyChain:
    def test_empty_chain_is_valid(self, chain, org):
        result = chain.verify_chain(org)
        assert result["is_valid"] is True
        assert result["chain_length"] == 0
        assert result["broken_links"] == []
        assert result["invalid_signatures"] == []

    def test_intact_chain_is_valid(self, chain, org):
        for i in range(5):
            chain.append("event", {"seq": i}, org)
        result = chain.verify_chain(org)
        assert result["is_valid"] is True
        assert result["broken_links"] == []
        assert result["invalid_signatures"] == []

    def test_result_includes_verified_at(self, chain, org):
        result = chain.verify_chain(org)
        assert "verified_at" in result
        # Should parse as ISO datetime
        datetime.fromisoformat(result["verified_at"].replace("Z", "+00:00"))

    def test_tampered_data_hash_detected(self, chain, org):
        """Directly corrupt a DB row and confirm detect_tampering finds it."""
        chain.append("event", {"k": "original"}, org)
        chain.append("event", {"k": "second"}, org)

        # Corrupt the first entry's data_hash in SQLite
        conn = chain._get_conn()
        try:
            conn.execute(
                "UPDATE chain_entries SET data_hash = 'deadbeef' "
                "WHERE org_id = ? AND sequence_number = 0",
                (org,),
            )
            conn.commit()
        finally:
            conn.close()

        result = chain.verify_chain(org)
        # The second entry's previous_hash now references the corrupted entry,
        # so at minimum the signature on entry 0 is broken (data_hash changed)
        assert result["is_valid"] is False


# ── detect_tampering ──────────────────────────────────────────────────────────


class TestDetectTampering:
    def test_clean_chain_returns_empty_list(self, chain, org):
        for i in range(3):
            chain.append("event", {}, org)
        assert chain.detect_tampering(org) == []

    def test_returns_tampered_entries(self, chain, org):
        chain.append("event", {"k": "v"}, org)
        chain.append("event", {"k": "w"}, org)

        # Corrupt signature of entry 0
        conn = chain._get_conn()
        try:
            conn.execute(
                "UPDATE chain_entries SET signature = 'badsig' "
                "WHERE org_id = ? AND sequence_number = 0",
                (org,),
            )
            conn.commit()
        finally:
            conn.close()

        tampered = chain.detect_tampering(org)
        assert len(tampered) >= 1
        seq_nums = [t["sequence_number"] for t in tampered]
        assert 0 in seq_nums

    def test_tampered_entry_has_reason(self, chain, org):
        chain.append("event", {}, org)

        conn = chain._get_conn()
        try:
            conn.execute(
                "UPDATE chain_entries SET signature = 'badsig' WHERE org_id = ?",
                (org,),
            )
            conn.commit()
        finally:
            conn.close()

        tampered = chain.detect_tampering(org)
        assert len(tampered) == 1
        assert "invalid_hmac" in tampered[0]["reason"]


# ── get_chain_stats ───────────────────────────────────────────────────────────


class TestGetChainStats:
    def test_empty_chain_stats(self, chain, org):
        stats = chain.get_chain_stats(org)
        assert stats["length"] == 0
        assert stats["first_timestamp"] is None
        assert stats["last_timestamp"] is None
        assert stats["integrity_status"] == "empty"

    def test_populated_chain_stats(self, chain, org):
        for i in range(4):
            chain.append("event", {}, org)
        stats = chain.get_chain_stats(org)
        assert stats["length"] == 4
        assert stats["first_timestamp"] is not None
        assert stats["last_timestamp"] is not None
        assert stats["integrity_status"] == "valid"

    def test_tampered_chain_reports_tampered(self, chain, org):
        chain.append("event", {}, org)

        conn = chain._get_conn()
        try:
            conn.execute(
                "UPDATE chain_entries SET signature = 'badsig' WHERE org_id = ?",
                (org,),
            )
            conn.commit()
        finally:
            conn.close()

        stats = chain.get_chain_stats(org)
        assert stats["integrity_status"] == "tampered"


# ── export_chain ──────────────────────────────────────────────────────────────


class TestExportChain:
    def test_empty_export_is_list(self, chain, org):
        result = chain.export_chain(org)
        assert result == []

    def test_export_contains_all_entries(self, chain, org):
        for i in range(3):
            chain.append("ev", {"i": i}, org)
        result = chain.export_chain(org)
        assert len(result) == 3

    def test_export_entry_has_required_fields(self, chain, org):
        chain.append("ev", {"x": 1}, org)
        entry = chain.export_chain(org)[0]
        for field in ["id", "sequence_number", "event_type", "data_hash",
                      "previous_hash", "timestamp", "signature", "org_id"]:
            assert field in entry

    def test_export_is_json_serialisable(self, chain, org):
        for i in range(3):
            chain.append("ev", {"i": i}, org)
        result = chain.export_chain(org)
        # Should not raise
        serialised = json.dumps(result)
        parsed = json.loads(serialised)
        assert len(parsed) == 3


# ── router integration ────────────────────────────────────────────────────────


@pytest.fixture
def client(tmp_path):
    """TestClient for the evidence_chain_router, isolated DB."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # Patch EvidenceChain to use a temp DB
    with patch("apps.api.evidence_chain_router._chain", EvidenceChain(db_path=str(tmp_path / "router.db"))):
        from apps.api.evidence_chain_router import router
        app = FastAPI()
        app.include_router(router)
        yield TestClient(app)


def _headers(org="router-org-001"):
    return {"X-Org-ID": org}


class TestRouterAppend:
    def test_append_returns_201(self, client):
        resp = client.post(
            "/api/v1/evidence-chain/append",
            json={"event_type": "scan_complete", "data": {"target": "app.example.com"}},
            headers=_headers(),
        )
        assert resp.status_code == 201

    def test_append_response_has_chain_fields(self, client):
        resp = client.post(
            "/api/v1/evidence-chain/append",
            json={"event_type": "login", "data": {"user": "alice"}},
            headers=_headers(),
        )
        body = resp.json()
        assert "id" in body
        assert "sequence_number" in body
        assert "data_hash" in body
        assert "previous_hash" in body
        assert "signature" in body

    def test_append_genesis_sequence_is_zero(self, client):
        resp = client.post(
            "/api/v1/evidence-chain/append",
            json={"event_type": "init", "data": {}},
            headers=_headers(),
        )
        assert resp.json()["sequence_number"] == 0

    def test_append_second_entry_sequence_is_one(self, client):
        h = _headers()
        client.post("/api/v1/evidence-chain/append", json={"event_type": "a", "data": {}}, headers=h)
        resp = client.post("/api/v1/evidence-chain/append", json={"event_type": "b", "data": {}}, headers=h)
        assert resp.json()["sequence_number"] == 1


class TestRouterVerify:
    def test_verify_empty_chain_is_valid(self, client):
        resp = client.get("/api/v1/evidence-chain/verify", headers=_headers())
        assert resp.status_code == 200
        body = resp.json()
        assert body["is_valid"] is True
        assert body["chain_length"] == 0

    def test_verify_populated_chain_is_valid(self, client):
        h = _headers()
        for _ in range(3):
            client.post("/api/v1/evidence-chain/append", json={"event_type": "ev", "data": {}}, headers=h)
        resp = client.get("/api/v1/evidence-chain/verify", headers=h)
        body = resp.json()
        assert body["is_valid"] is True
        assert body["chain_length"] == 3


class TestRouterEntries:
    def test_entries_empty_returns_list(self, client):
        resp = client.get("/api/v1/evidence-chain/entries", headers=_headers())
        assert resp.status_code == 200
        assert resp.json() == []

    def test_entries_returns_all(self, client):
        h = _headers()
        for i in range(4):
            client.post("/api/v1/evidence-chain/append", json={"event_type": "ev", "data": {"i": i}}, headers=h)
        resp = client.get("/api/v1/evidence-chain/entries", headers=h)
        assert len(resp.json()) == 4

    def test_entries_start_filter(self, client):
        h = _headers()
        for i in range(5):
            client.post("/api/v1/evidence-chain/append", json={"event_type": "ev", "data": {}}, headers=h)
        resp = client.get("/api/v1/evidence-chain/entries?start=3", headers=h)
        entries = resp.json()
        assert all(e["sequence_number"] >= 3 for e in entries)


class TestRouterLatest:
    def test_latest_on_empty_chain_returns_404(self, client):
        resp = client.get("/api/v1/evidence-chain/latest", headers=_headers())
        assert resp.status_code == 404

    def test_latest_returns_last_entry(self, client):
        h = _headers()
        for i in range(3):
            client.post("/api/v1/evidence-chain/append", json={"event_type": "ev", "data": {"i": i}}, headers=h)
        resp = client.get("/api/v1/evidence-chain/latest", headers=h)
        assert resp.status_code == 200
        assert resp.json()["sequence_number"] == 2


class TestRouterExport:
    def test_export_returns_json_attachment(self, client):
        h = _headers()
        client.post("/api/v1/evidence-chain/append", json={"event_type": "ev", "data": {}}, headers=h)
        resp = client.get("/api/v1/evidence-chain/export", headers=h)
        assert resp.status_code == 200
        assert "attachment" in resp.headers.get("content-disposition", "")
        body = resp.json()
        assert "chain" in body
        assert body["entry_count"] == 1


class TestRouterStats:
    def test_stats_empty_chain(self, client):
        resp = client.get("/api/v1/evidence-chain/stats", headers=_headers())
        assert resp.status_code == 200
        body = resp.json()
        assert body["length"] == 0
        assert body["integrity_status"] == "empty"

    def test_stats_populated_chain(self, client):
        h = _headers()
        for i in range(4):
            client.post("/api/v1/evidence-chain/append", json={"event_type": "ev", "data": {}}, headers=h)
        resp = client.get("/api/v1/evidence-chain/stats", headers=h)
        body = resp.json()
        assert body["length"] == 4
        assert body["integrity_status"] == "valid"
        assert body["first_timestamp"] is not None
        assert body["last_timestamp"] is not None
