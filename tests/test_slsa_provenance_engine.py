"""Tests for SLSAProvenanceEngine — ALDECI GAP-018.

Covers:
- schema idempotency (ensure_schema called multiple times)
- generate_attestation returns in-toto v0.1 Statement + SLSA v0.2 predicate shape
- DSSE envelope structure: payloadType, payload (base64), signatures
- base64 round-trip of payload decodes back to the statement
- SLSA level 1-4 valid; 0 and 5 rejected
- verify_attestation passes on a well-formed attestation
- verify_attestation fails on missing builder_id (via direct DB mutation)
- verify_attestation fails on missing materials (empty list path)
- verify_attestation records a verification row
- verify_attestation on unknown id returns fail verdict
- materials must be a list of dicts
- invocation/metadata must be dicts
- empty required fields raise ValueError
- list_attestations filters by subject_name and builder_id
- list_attestations respects org_id isolation
- get_attestation returns the stored envelope
- stats returns counts by slsa_level (all 4 levels present)
- stats returns verification pass/fail rates correctly
- org_id isolation: org_a data not visible to org_b
- DSSE payloadType is application/vnd.in-toto+json
- subject.digest contains sha256
- ≥30 tests
"""

from __future__ import annotations

import base64
import json
import sqlite3
import sys
import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.slsa_provenance_engine import (
    SLSAProvenanceEngine,
    _IN_TOTO_STATEMENT_TYPE,
    _SLSA_PROVENANCE_V02_TYPE,
    _DSSE_PAYLOAD_TYPE,
    _PLACEHOLDER_SIG,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return SLSAProvenanceEngine(db_path=str(tmp_path / "slsa.db"))


def _attest(
    engine,
    org_id="org1",
    subject_name="registry.example.io/app@sha256:abc",
    subject_sha256="a" * 64,
    builder_id="https://github.com/actions/runner/v2.317.0",
    build_type="https://slsa.dev/container-based-build/v0.1?draft",
    invocation=None,
    materials=None,
    metadata=None,
    slsa_level=3,
):
    invocation = invocation if invocation is not None else {"configSource": {"uri": "git+https://github.com/aldeci/demo@main"}}
    materials = materials if materials is not None else [
        {"uri": "git+https://github.com/aldeci/demo@main", "digest": {"sha1": "deadbeef" * 5}}
    ]
    metadata = metadata if metadata is not None else {"buildStartedOn": "2026-04-22T10:00:00Z", "reproducible": False}
    return engine.generate_attestation(
        org_id=org_id,
        subject_name=subject_name,
        subject_sha256=subject_sha256,
        builder_id=builder_id,
        build_type=build_type,
        invocation=invocation,
        materials=materials,
        metadata=metadata,
        slsa_level=slsa_level,
    )


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_schema_idempotent(engine):
    engine.ensure_schema()
    engine.ensure_schema()  # second call must not error
    # Confirm tables exist
    conn = sqlite3.connect(engine.db_path)
    names = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    conn.close()
    assert "slsa_attestations" in names
    assert "slsa_verifications" in names


def test_schema_columns_present(engine):
    conn = sqlite3.connect(engine.db_path)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(slsa_attestations)").fetchall()}
    conn.close()
    for required in (
        "id", "org_id", "subject_name", "subject_sha256", "builder_id",
        "build_type", "invocation_json", "materials_json", "metadata_json",
        "signature_placeholder", "dsse_envelope_json", "slsa_level", "created_at",
    ):
        assert required in cols, f"missing column: {required}"


# ---------------------------------------------------------------------------
# generate_attestation: shape compliance
# ---------------------------------------------------------------------------


def test_generate_returns_envelope_and_statement(engine):
    att = _attest(engine)
    assert "id" in att
    assert "envelope" in att
    assert "statement" in att
    assert att["slsa_level"] == 3


def test_statement_is_in_toto_v01(engine):
    att = _attest(engine)
    stmt = att["statement"]
    assert stmt["_type"] == _IN_TOTO_STATEMENT_TYPE
    assert stmt["_type"] == "https://in-toto.io/Statement/v0.1"


def test_predicate_type_is_slsa_v02(engine):
    att = _attest(engine)
    assert att["statement"]["predicateType"] == _SLSA_PROVENANCE_V02_TYPE
    assert att["statement"]["predicateType"] == "https://slsa.dev/provenance/v0.2"


def test_subject_digest_contains_sha256(engine):
    att = _attest(engine, subject_sha256="b" * 64)
    subjects = att["statement"]["subject"]
    assert isinstance(subjects, list) and len(subjects) == 1
    assert subjects[0]["digest"]["sha256"] == "b" * 64
    assert subjects[0]["name"] == "registry.example.io/app@sha256:abc"


def test_predicate_has_builder_buildtype_invocation_materials_metadata(engine):
    att = _attest(engine)
    pred = att["statement"]["predicate"]
    assert "builder" in pred and "id" in pred["builder"]
    assert "buildType" in pred
    assert "invocation" in pred and isinstance(pred["invocation"], dict)
    assert "materials" in pred and isinstance(pred["materials"], list)
    assert "metadata" in pred and isinstance(pred["metadata"], dict)


def test_envelope_payload_type_is_in_toto_json(engine):
    att = _attest(engine)
    assert att["envelope"]["payloadType"] == _DSSE_PAYLOAD_TYPE
    assert att["envelope"]["payloadType"] == "application/vnd.in-toto+json"


def test_envelope_signatures_non_empty(engine):
    att = _attest(engine)
    sigs = att["envelope"]["signatures"]
    assert isinstance(sigs, list) and len(sigs) >= 1
    # When real ed25519 signing is active the sig is a base64 string; when the
    # cryptography package is unavailable the engine falls back to _PLACEHOLDER_SIG.
    sig_val = sigs[0]["sig"]
    assert isinstance(sig_val, str) and len(sig_val) > 0


def test_dsse_payload_base64_roundtrips_to_statement(engine):
    att = _attest(engine)
    encoded = att["envelope"]["payload"]
    raw = base64.b64decode(encoded.encode("ascii"))
    decoded = json.loads(raw)
    assert decoded["_type"] == _IN_TOTO_STATEMENT_TYPE
    assert decoded["predicateType"] == _SLSA_PROVENANCE_V02_TYPE
    assert decoded["subject"] == att["statement"]["subject"]


# ---------------------------------------------------------------------------
# SLSA level validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("level", [1, 2, 3, 4])
def test_slsa_level_valid_1_to_4(engine, level):
    att = _attest(engine, slsa_level=level)
    assert att["slsa_level"] == level


@pytest.mark.parametrize("level", [0, 5, -1, 99])
def test_slsa_level_out_of_range_rejected(engine, level):
    with pytest.raises(ValueError):
        _attest(engine, slsa_level=level)


def test_slsa_level_non_int_rejected(engine):
    with pytest.raises(ValueError):
        _attest(engine, slsa_level="three")


# ---------------------------------------------------------------------------
# Required field validation
# ---------------------------------------------------------------------------


def test_missing_org_id_raises(engine):
    with pytest.raises(ValueError):
        engine.generate_attestation(
            org_id="",
            subject_name="x",
            subject_sha256="a" * 64,
            builder_id="b",
            build_type="t",
        )


def test_missing_subject_name_raises(engine):
    with pytest.raises(ValueError):
        engine.generate_attestation(
            org_id="o",
            subject_name="",
            subject_sha256="a" * 64,
            builder_id="b",
            build_type="t",
        )


def test_missing_builder_id_raises(engine):
    with pytest.raises(ValueError):
        engine.generate_attestation(
            org_id="o",
            subject_name="s",
            subject_sha256="a" * 64,
            builder_id="",
            build_type="t",
        )


def test_missing_build_type_raises(engine):
    with pytest.raises(ValueError):
        engine.generate_attestation(
            org_id="o",
            subject_name="s",
            subject_sha256="a" * 64,
            builder_id="b",
            build_type="",
        )


def test_invocation_must_be_dict(engine):
    with pytest.raises(ValueError):
        _attest(engine, invocation=["not a dict"])


def test_metadata_must_be_dict(engine):
    with pytest.raises(ValueError):
        _attest(engine, metadata=["not a dict"])


def test_materials_must_be_list(engine):
    with pytest.raises(ValueError):
        _attest(engine, materials={"not": "a list"})


def test_material_item_must_be_dict(engine):
    with pytest.raises(ValueError):
        _attest(engine, materials=["not a dict"])


# ---------------------------------------------------------------------------
# verify_attestation
# ---------------------------------------------------------------------------


def test_verify_passes_on_well_formed_attestation(engine):
    att = _attest(engine)
    result = engine.verify_attestation(att["id"])
    assert result["verdict"] == "pass", result["verdict_detail"]
    assert result["checks"]["statement_type_ok"] is True
    assert result["checks"]["predicate_type_ok"] is True
    assert result["checks"]["builder_id_present"] is True
    assert result["checks"]["materials_non_empty"] is True
    assert result["checks"]["slsa_level_valid"] is True


def test_verify_fails_on_missing_builder(engine):
    att = _attest(engine)
    # Corrupt the envelope: rewrite payload to remove builder.id
    conn = sqlite3.connect(engine.db_path)
    envelope = json.loads(conn.execute(
        "SELECT dsse_envelope_json FROM slsa_attestations WHERE id=?",
        (att["id"],)
    ).fetchone()[0])
    payload = json.loads(base64.b64decode(envelope["payload"].encode()).decode())
    payload["predicate"]["builder"] = {"id": ""}
    envelope["payload"] = base64.b64encode(
        json.dumps(payload, sort_keys=True).encode()
    ).decode("ascii")
    conn.execute(
        "UPDATE slsa_attestations SET dsse_envelope_json=? WHERE id=?",
        (json.dumps(envelope, sort_keys=True), att["id"]),
    )
    conn.commit()
    conn.close()

    result = engine.verify_attestation(att["id"])
    assert result["verdict"] == "fail"
    assert result["checks"]["builder_id_present"] is False


def test_verify_fails_on_missing_materials(engine):
    att = _attest(engine)
    conn = sqlite3.connect(engine.db_path)
    envelope = json.loads(conn.execute(
        "SELECT dsse_envelope_json FROM slsa_attestations WHERE id=?",
        (att["id"],)
    ).fetchone()[0])
    payload = json.loads(base64.b64decode(envelope["payload"].encode()).decode())
    payload["predicate"]["materials"] = []
    envelope["payload"] = base64.b64encode(
        json.dumps(payload, sort_keys=True).encode()
    ).decode("ascii")
    conn.execute(
        "UPDATE slsa_attestations SET dsse_envelope_json=? WHERE id=?",
        (json.dumps(envelope, sort_keys=True), att["id"]),
    )
    conn.commit()
    conn.close()

    result = engine.verify_attestation(att["id"])
    assert result["verdict"] == "fail"
    assert result["checks"]["materials_non_empty"] is False


def test_verify_on_unknown_id_returns_fail(engine):
    result = engine.verify_attestation("nonexistent-id-abc-123")
    assert result["verdict"] == "fail"
    assert "not found" in result["verdict_detail"].lower()


def test_verify_records_row(engine):
    att = _attest(engine)
    engine.verify_attestation(att["id"])
    conn = sqlite3.connect(engine.db_path)
    cnt = conn.execute(
        "SELECT COUNT(*) FROM slsa_verifications WHERE attestation_id=?",
        (att["id"],),
    ).fetchone()[0]
    conn.close()
    assert cnt == 1


def test_verify_empty_id_raises(engine):
    with pytest.raises(ValueError):
        engine.verify_attestation("")


def test_verify_fails_on_corrupted_payload(engine):
    att = _attest(engine)
    conn = sqlite3.connect(engine.db_path)
    envelope = json.loads(conn.execute(
        "SELECT dsse_envelope_json FROM slsa_attestations WHERE id=?",
        (att["id"],)
    ).fetchone()[0])
    envelope["payload"] = "not!base64!!"
    conn.execute(
        "UPDATE slsa_attestations SET dsse_envelope_json=? WHERE id=?",
        (json.dumps(envelope, sort_keys=True), att["id"]),
    )
    conn.commit()
    conn.close()

    result = engine.verify_attestation(att["id"])
    assert result["verdict"] == "fail"
    assert result["checks"]["payload_parsable"] is False


def test_verify_records_verifier_name(engine):
    att = _attest(engine)
    engine.verify_attestation(att["id"], verifier="kyverno-admission")
    conn = sqlite3.connect(engine.db_path)
    verifier = conn.execute(
        "SELECT verifier FROM slsa_verifications WHERE attestation_id=?",
        (att["id"],),
    ).fetchone()[0]
    conn.close()
    assert verifier == "kyverno-admission"


# ---------------------------------------------------------------------------
# list_attestations / filters
# ---------------------------------------------------------------------------


def test_list_filters_by_subject_name(engine):
    _attest(engine, subject_name="app1", subject_sha256="1" * 64)
    _attest(engine, subject_name="app2", subject_sha256="2" * 64)
    results = engine.list_attestations(org_id="org1", subject_name="app1")
    assert len(results) == 1
    assert results[0]["subject_name"] == "app1"


def test_list_filters_by_builder_id(engine):
    _attest(engine, builder_id="builder-a")
    _attest(engine, builder_id="builder-b")
    results = engine.list_attestations(org_id="org1", builder_id="builder-b")
    assert len(results) == 1
    assert results[0]["builder_id"] == "builder-b"


def test_list_filters_combined(engine):
    _attest(engine, subject_name="app1", builder_id="builder-a")
    _attest(engine, subject_name="app1", builder_id="builder-b")
    _attest(engine, subject_name="app2", builder_id="builder-a")
    results = engine.list_attestations(
        org_id="org1", subject_name="app1", builder_id="builder-a"
    )
    assert len(results) == 1


def test_list_requires_org_id(engine):
    with pytest.raises(ValueError):
        engine.list_attestations(org_id="")


def test_list_empty_returns_empty_list(engine):
    assert engine.list_attestations(org_id="ghost-org") == []


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_list(engine):
    _attest(engine, org_id="org_a")
    _attest(engine, org_id="org_b")
    a = engine.list_attestations(org_id="org_a")
    b = engine.list_attestations(org_id="org_b")
    assert len(a) == 1 and len(b) == 1
    assert a[0]["org_id"] == "org_a"
    assert b[0]["org_id"] == "org_b"


def test_org_isolation_stats(engine):
    _attest(engine, org_id="org_a", slsa_level=3)
    _attest(engine, org_id="org_a", slsa_level=3)
    _attest(engine, org_id="org_b", slsa_level=2)
    a = engine.stats("org_a")
    b = engine.stats("org_b")
    assert a["total_attestations"] == 2
    assert b["total_attestations"] == 1


# ---------------------------------------------------------------------------
# get_attestation
# ---------------------------------------------------------------------------


def test_get_attestation_returns_row(engine):
    att = _attest(engine)
    found = engine.get_attestation(att["id"])
    assert found is not None
    assert found["id"] == att["id"]
    # Deserialised envelope reachable via dsse_envelope key added in _row_to_dict
    assert found["dsse_envelope"]["payloadType"] == _DSSE_PAYLOAD_TYPE


def test_get_attestation_unknown_returns_none(engine):
    assert engine.get_attestation("nonexistent") is None


def test_get_attestation_empty_id_returns_none(engine):
    assert engine.get_attestation("") is None


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------


def test_stats_requires_org_id(engine):
    with pytest.raises(ValueError):
        engine.stats(org_id="")


def test_stats_counts_by_level(engine):
    _attest(engine, subject_sha256="1" * 64, slsa_level=1)
    _attest(engine, subject_sha256="2" * 64, slsa_level=2)
    _attest(engine, subject_sha256="3" * 64, slsa_level=3)
    _attest(engine, subject_sha256="4" * 64, slsa_level=3)
    _attest(engine, subject_sha256="5" * 64, slsa_level=4)
    s = engine.stats("org1")
    assert s["by_slsa_level"][1] == 1
    assert s["by_slsa_level"][2] == 1
    assert s["by_slsa_level"][3] == 2
    assert s["by_slsa_level"][4] == 1
    assert s["total_attestations"] == 5


def test_stats_includes_all_four_levels(engine):
    _attest(engine, slsa_level=3)
    s = engine.stats("org1")
    # Keys for all 4 SLSA levels must be present
    for k in (1, 2, 3, 4):
        assert k in s["by_slsa_level"]


def test_stats_verification_pass_rate(engine):
    a1 = _attest(engine, subject_sha256="1" * 64)
    a2 = _attest(engine, subject_sha256="2" * 64)

    engine.verify_attestation(a1["id"])  # pass
    engine.verify_attestation(a2["id"])  # pass

    s = engine.stats("org1")
    assert s["verifications"]["total"] == 2
    assert s["verifications"]["pass"] == 2
    assert s["verifications"]["fail"] == 0
    assert s["verifications"]["pass_rate"] == 1.0


def test_stats_no_verifications(engine):
    _attest(engine)
    s = engine.stats("org1")
    assert s["verifications"]["total"] == 0
    assert s["verifications"]["pass_rate"] == 0.0


def test_stats_mixed_pass_fail(engine):
    att = _attest(engine, subject_sha256="7" * 64)
    engine.verify_attestation(att["id"])  # pass

    # Corrupt a second attestation to force fail
    att2 = _attest(engine, subject_sha256="8" * 64)
    conn = sqlite3.connect(engine.db_path)
    envelope = json.loads(conn.execute(
        "SELECT dsse_envelope_json FROM slsa_attestations WHERE id=?",
        (att2["id"],)
    ).fetchone()[0])
    payload = json.loads(base64.b64decode(envelope["payload"].encode()).decode())
    payload["predicate"]["materials"] = []
    envelope["payload"] = base64.b64encode(
        json.dumps(payload).encode()
    ).decode("ascii")
    conn.execute(
        "UPDATE slsa_attestations SET dsse_envelope_json=? WHERE id=?",
        (json.dumps(envelope), att2["id"]),
    )
    conn.commit()
    conn.close()
    engine.verify_attestation(att2["id"])  # fail

    s = engine.stats("org1")
    assert s["verifications"]["pass"] == 1
    assert s["verifications"]["fail"] == 1
    assert s["verifications"]["pass_rate"] == 0.5


# ---------------------------------------------------------------------------
# Placeholder signing marker
# ---------------------------------------------------------------------------


def test_signature_placeholder_stored(engine):
    att = _attest(engine)
    conn = sqlite3.connect(engine.db_path)
    stored_sig = conn.execute(
        "SELECT signature_placeholder FROM slsa_attestations WHERE id=?",
        (att["id"],),
    ).fetchone()[0]
    conn.close()
    # Column stores the JSON-serialised signatures list. When real ed25519
    # signing is active this is a JSON array with a real sig; when the
    # cryptography package is absent the fallback stores _PLACEHOLDER_SIG text.
    # Either way the column must be a non-empty string.
    assert isinstance(stored_sig, str) and len(stored_sig) > 0
    # Attempt JSON parse — real signing produces valid JSON array; if it is
    # the legacy plain-text placeholder it may not parse but must equal _PLACEHOLDER_SIG.
    try:
        parsed = json.loads(stored_sig)
        assert isinstance(parsed, list) and len(parsed) >= 1
    except (json.JSONDecodeError, ValueError):
        assert stored_sig == _PLACEHOLDER_SIG


def test_envelope_json_persisted(engine):
    att = _attest(engine)
    conn = sqlite3.connect(engine.db_path)
    env_json = conn.execute(
        "SELECT dsse_envelope_json FROM slsa_attestations WHERE id=?",
        (att["id"],),
    ).fetchone()[0]
    conn.close()
    parsed = json.loads(env_json)
    assert parsed["payloadType"] == _DSSE_PAYLOAD_TYPE
