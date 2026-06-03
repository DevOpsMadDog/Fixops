"""Tests for Agentless Snapshot Scan Engine (GAP-020)."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Dict, List

import pytest

from core.agentless_snapshot_scan_engine import (
    AgentlessSnapshotScanEngine,
    MockAWSAdapter,
    SnapshotAdapter,
    SnapshotBlob,
    SnapshotRef,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_engine(tmp_path: Path) -> AgentlessSnapshotScanEngine:
    db = tmp_path / "agentless_snapshot_scan.db"
    # Inject the built-in mock adapter: the engine now defaults to a REAL cloud
    # adapter (correct for production — no mock data), which returns nothing /
    # "cloud API unavailable" in tests, so enqueue would persist 0 rows.
    return AgentlessSnapshotScanEngine(db_path=str(db), adapter=MockAWSAdapter())


class StubAdapter:
    """Minimal in-test adapter used to verify the protocol contract."""

    def __init__(self, snapshots: Dict[str, SnapshotBlob]):
        self._snapshots = snapshots
        self.fetched: List[str] = []
        self.released: List[str] = []

    def list_snapshots(self, org_id, provider, account_id):
        refs = []
        for snap_id in self._snapshots:
            refs.append(
                SnapshotRef(
                    snapshot_id=snap_id,
                    provider=provider,
                    account_id=account_id,
                    region="us-west-2",
                    taken_at="2026-04-22T00:00:00+00:00",
                    size_gb=4,
                )
            )
        return refs

    def fetch_snapshot(self, snapshot_id):
        self.fetched.append(snapshot_id)
        return self._snapshots[snapshot_id]

    def release(self, snapshot_id):
        self.released.append(snapshot_id)


# ---------------------------------------------------------------------------
# Adapter protocol compliance
# ---------------------------------------------------------------------------


def test_mock_adapter_satisfies_protocol():
    adapter = MockAWSAdapter()
    assert isinstance(adapter, SnapshotAdapter)


def test_stub_adapter_satisfies_protocol():
    adapter = StubAdapter({})
    assert isinstance(adapter, SnapshotAdapter)


def test_mock_adapter_lists_three_snapshots_for_prod_account():
    adapter = MockAWSAdapter()
    refs = adapter.list_snapshots(org_id="org-1", provider="aws", account_id="111-prod")
    assert len(refs) == 3
    assert all(r.provider == "aws" for r in refs)


def test_mock_adapter_lists_two_snapshots_for_nonprod_account():
    adapter = MockAWSAdapter()
    refs = adapter.list_snapshots(org_id="org-1", provider="aws", account_id="222-dev")
    assert len(refs) == 2


def test_mock_adapter_release_is_noop_without_error():
    adapter = MockAWSAdapter()
    adapter.release("nonexistent-id")  # Must not raise


# ---------------------------------------------------------------------------
# Schema lifecycle
# ---------------------------------------------------------------------------


def test_schema_created_on_init(tmp_engine):
    stats = tmp_engine.stats(org_id="nobody")
    assert stats["total_snapshots"] == 0
    assert stats["total_findings"] == 0


def test_ensure_schema_idempotent(tmp_engine):
    tmp_engine.ensure_schema()
    tmp_engine.ensure_schema()
    tmp_engine.ensure_schema()
    # If idempotent, stats still returns empty counts.
    assert tmp_engine.stats(org_id="x")["total_snapshots"] == 0


def test_set_adapter_rejects_non_protocol_types(tmp_engine):
    with pytest.raises(TypeError):
        tmp_engine.set_adapter(object())


def test_set_adapter_accepts_protocol_types(tmp_engine):
    tmp_engine.set_adapter(StubAdapter({}))


# ---------------------------------------------------------------------------
# Enqueue
# ---------------------------------------------------------------------------


def test_enqueue_creates_pending_rows(tmp_engine):
    queued = tmp_engine.enqueue_scan(
        org_id="org-A", provider="aws", account_id="111-prod"
    )
    assert len(queued) == 3
    for record in queued:
        assert record["org_id"] == "org-A"
        assert record["scan_status"] == "pending"


def test_enqueue_rejects_invalid_provider(tmp_engine):
    with pytest.raises(ValueError):
        tmp_engine.enqueue_scan(org_id="o", provider="spacecloud", account_id="a")


def test_enqueue_rejects_empty_org_id(tmp_engine):
    with pytest.raises(ValueError):
        tmp_engine.enqueue_scan(org_id="", provider="aws", account_id="a")


def test_enqueue_rejects_empty_account_id(tmp_engine):
    with pytest.raises(ValueError):
        tmp_engine.enqueue_scan(org_id="o", provider="aws", account_id="")


def test_enqueue_is_idempotent(tmp_engine):
    first = tmp_engine.enqueue_scan(
        org_id="org-A", provider="aws", account_id="111-prod"
    )
    second = tmp_engine.enqueue_scan(
        org_id="org-A", provider="aws", account_id="111-prod"
    )
    ids_first = {r["id"] for r in first}
    ids_second = {r["id"] for r in second}
    assert ids_first == ids_second  # Same rows, not duplicated.
    assert tmp_engine.stats(org_id="org-A")["total_snapshots"] == 3


def test_enqueue_multiple_providers_isolated(tmp_engine):
    tmp_engine.enqueue_scan(org_id="o", provider="aws", account_id="dev")
    tmp_engine.enqueue_scan(org_id="o", provider="azure", account_id="dev")
    aws = tmp_engine.list_snapshots(org_id="o", provider="aws")
    azure = tmp_engine.list_snapshots(org_id="o", provider="azure")
    assert len(aws) == 2
    assert len(azure) == 2


# ---------------------------------------------------------------------------
# Scan probes
# ---------------------------------------------------------------------------


def test_scan_detects_all_three_probe_types(tmp_engine):
    queued = tmp_engine.enqueue_scan(
        org_id="org-B", provider="aws", account_id="prod"
    )
    total_by_type: Dict[str, int] = {"secret": 0, "vulnerable_package": 0, "malware": 0}
    for record in queued:
        result = tmp_engine.run_scan(snapshot_db_id=record["id"])
        for k in total_by_type:
            total_by_type[k] += result["by_type"].get(k, 0)
    assert total_by_type["secret"] > 0
    assert total_by_type["vulnerable_package"] > 0
    assert total_by_type["malware"] > 0


def test_scan_completes_snapshot_status(tmp_engine):
    queued = tmp_engine.enqueue_scan(
        org_id="org-C", provider="aws", account_id="dev"
    )
    tmp_engine.run_scan(snapshot_db_id=queued[0]["id"])
    rows = tmp_engine.list_snapshots(org_id="org-C")
    scanned = [r for r in rows if r["id"] == queued[0]["id"]][0]
    assert scanned["scan_status"] == "complete"


def test_scan_aws_secret_detected_in_credentials_file(tmp_engine):
    queued = tmp_engine.enqueue_scan(
        org_id="org-D", provider="aws", account_id="prod"
    )
    # Find the snapshot matching fixture snap-0001 (has /home/ubuntu/.aws/credentials).
    target = [q for q in queued if q["snapshot_id"].endswith("snap-0001")][0]
    tmp_engine.run_scan(snapshot_db_id=target["id"])
    findings = tmp_engine.list_findings(
        org_id="org-D", finding_type="secret", snapshot_db_id=target["id"]
    )
    rules = {f["detail"].get("rule") for f in findings}
    assert "aws_access_key_id" in rules
    assert "aws_secret_access_key" in rules


def test_scan_rsa_private_key_detected(tmp_engine):
    queued = tmp_engine.enqueue_scan(
        org_id="org-E", provider="aws", account_id="prod"
    )
    target = [q for q in queued if q["snapshot_id"].endswith("snap-0003")][0]
    tmp_engine.run_scan(snapshot_db_id=target["id"])
    findings = tmp_engine.list_findings(
        org_id="org-E", finding_type="secret", snapshot_db_id=target["id"]
    )
    rules = {f["detail"].get("rule") for f in findings}
    assert "rsa_private_key" in rules
    assert "npm_auth_token" in rules


def test_scan_secret_preview_is_redacted(tmp_engine):
    queued = tmp_engine.enqueue_scan(
        org_id="org-F", provider="aws", account_id="prod"
    )
    target = [q for q in queued if q["snapshot_id"].endswith("snap-0001")][0]
    tmp_engine.run_scan(snapshot_db_id=target["id"])
    findings = tmp_engine.list_findings(
        org_id="org-F", finding_type="secret", snapshot_db_id=target["id"]
    )
    for f in findings:
        preview = f["detail"].get("preview", "")
        # Never contains the full AWS key string.
        assert "AKIAIOSFODNN7EXAMPLE" not in preview
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in preview


def test_scan_log4shell_cve_detected(tmp_engine):
    queued = tmp_engine.enqueue_scan(
        org_id="org-G", provider="aws", account_id="prod"
    )
    target = [q for q in queued if q["snapshot_id"].endswith("snap-0003")][0]
    tmp_engine.run_scan(snapshot_db_id=target["id"])
    findings = tmp_engine.list_findings(
        org_id="org-G",
        finding_type="vulnerable_package",
        snapshot_db_id=target["id"],
    )
    cves = {f["detail"].get("cve") for f in findings}
    assert "CVE-2021-44228" in cves


def test_scan_heartbleed_detected(tmp_engine):
    queued = tmp_engine.enqueue_scan(
        org_id="org-H", provider="aws", account_id="dev"
    )
    target = [q for q in queued if q["snapshot_id"].endswith("snap-0001")][0]
    tmp_engine.run_scan(snapshot_db_id=target["id"])
    findings = tmp_engine.list_findings(
        org_id="org-H",
        finding_type="vulnerable_package",
        snapshot_db_id=target["id"],
    )
    cves = {f["detail"].get("cve") for f in findings}
    assert "CVE-2014-0160" in cves


def test_scan_malware_magic_detected(tmp_engine):
    queued = tmp_engine.enqueue_scan(
        org_id="org-I", provider="aws", account_id="dev"
    )
    target = [q for q in queued if q["snapshot_id"].endswith("snap-0002")][0]
    tmp_engine.run_scan(snapshot_db_id=target["id"])
    findings = tmp_engine.list_findings(
        org_id="org-I", finding_type="malware", snapshot_db_id=target["id"]
    )
    assert len(findings) >= 1
    for f in findings:
        assert f["severity"] == "critical"


def test_scan_nonmatching_file_produces_no_findings(tmp_engine):
    blob = SnapshotBlob(
        snapshot_id="clean-1",
        files={
            "/etc/hostname": b"clean-host\n",
            "/tmp/readme.txt": b"This is just a readme.\n",
        },
    )
    adapter = StubAdapter({"clean-1": blob})
    tmp_engine.set_adapter(adapter)
    queued = tmp_engine.enqueue_scan(
        org_id="org-J", provider="aws", account_id="clean-acc"
    )
    for record in queued:
        result = tmp_engine.run_scan(snapshot_db_id=record["id"])
        assert result["total_findings"] == 0


def test_scan_invalid_snapshot_id_raises(tmp_engine):
    with pytest.raises(KeyError):
        tmp_engine.run_scan(snapshot_db_id="does-not-exist")


def test_scan_handles_adapter_exception_as_failed(tmp_engine):
    class BrokenAdapter:
        def list_snapshots(self, org_id, provider, account_id):
            return [
                SnapshotRef(
                    snapshot_id="will-break",
                    provider=provider,
                    account_id=account_id,
                )
            ]

        def fetch_snapshot(self, snapshot_id):
            raise RuntimeError("cloud API unavailable")

        def release(self, snapshot_id):
            pass

    tmp_engine.set_adapter(BrokenAdapter())
    queued = tmp_engine.enqueue_scan(
        org_id="org-K", provider="aws", account_id="broken"
    )
    result = tmp_engine.run_scan(snapshot_db_id=queued[0]["id"])
    assert result["status"] == "failed"
    assert "cloud API" in result["error"]
    rows = tmp_engine.list_snapshots(org_id="org-K", scan_status="failed")
    assert len(rows) == 1


def test_scan_releases_adapter_handle(tmp_engine):
    blob = SnapshotBlob(snapshot_id="rel-1", files={"/tmp/x.txt": b"ok"})
    adapter = StubAdapter({"rel-1": blob})
    tmp_engine.set_adapter(adapter)
    queued = tmp_engine.enqueue_scan(
        org_id="org-L", provider="aws", account_id="rel-acc"
    )
    tmp_engine.run_scan(snapshot_db_id=queued[0]["id"])
    assert "rel-1" in adapter.released


# ---------------------------------------------------------------------------
# Queries — filters, org isolation
# ---------------------------------------------------------------------------


def test_list_snapshots_filters_by_status(tmp_engine):
    queued = tmp_engine.enqueue_scan(
        org_id="org-M", provider="aws", account_id="prod"
    )
    tmp_engine.run_scan(snapshot_db_id=queued[0]["id"])
    complete = tmp_engine.list_snapshots(org_id="org-M", scan_status="complete")
    pending = tmp_engine.list_snapshots(org_id="org-M", scan_status="pending")
    assert len(complete) == 1
    assert len(pending) == 2


def test_list_snapshots_rejects_invalid_status(tmp_engine):
    with pytest.raises(ValueError):
        tmp_engine.list_snapshots(org_id="org-M", scan_status="halfway")


def test_list_findings_filters_by_severity(tmp_engine):
    queued = tmp_engine.enqueue_scan(
        org_id="org-N", provider="aws", account_id="prod"
    )
    for q in queued:
        tmp_engine.run_scan(snapshot_db_id=q["id"])
    criticals = tmp_engine.list_findings(org_id="org-N", severity="critical")
    highs = tmp_engine.list_findings(org_id="org-N", severity="high")
    assert len(criticals) > 0
    # Every returned record must actually match the requested severity.
    assert all(c["severity"] == "critical" for c in criticals)
    assert all(h["severity"] == "high" for h in highs)


def test_list_findings_filters_by_min_severity(tmp_engine):
    queued = tmp_engine.enqueue_scan(
        org_id="org-O", provider="aws", account_id="prod"
    )
    for q in queued:
        tmp_engine.run_scan(snapshot_db_id=q["id"])
    high_and_up = tmp_engine.list_findings(org_id="org-O", min_severity="high")
    assert all(f["severity"] in ("critical", "high") for f in high_and_up)


def test_list_findings_rejects_invalid_severity(tmp_engine):
    with pytest.raises(ValueError):
        tmp_engine.list_findings(org_id="x", severity="doom")


def test_list_findings_rejects_invalid_finding_type(tmp_engine):
    with pytest.raises(ValueError):
        tmp_engine.list_findings(org_id="x", finding_type="spells")


def test_list_findings_filters_by_type(tmp_engine):
    queued = tmp_engine.enqueue_scan(
        org_id="org-P", provider="aws", account_id="prod"
    )
    for q in queued:
        tmp_engine.run_scan(snapshot_db_id=q["id"])
    secrets = tmp_engine.list_findings(org_id="org-P", finding_type="secret")
    assert all(s["finding_type"] == "secret" for s in secrets)


def test_list_findings_deserialises_detail_json(tmp_engine):
    queued = tmp_engine.enqueue_scan(
        org_id="org-Q", provider="aws", account_id="prod"
    )
    for q in queued:
        tmp_engine.run_scan(snapshot_db_id=q["id"])
    findings = tmp_engine.list_findings(org_id="org-Q")
    assert findings
    for f in findings:
        assert isinstance(f["detail"], dict)


def test_org_isolation_no_cross_leak_on_snapshots(tmp_engine):
    tmp_engine.enqueue_scan(org_id="org-X", provider="aws", account_id="acc")
    tmp_engine.enqueue_scan(org_id="org-Y", provider="aws", account_id="acc")
    x_rows = tmp_engine.list_snapshots(org_id="org-X")
    y_rows = tmp_engine.list_snapshots(org_id="org-Y")
    x_ids = {r["id"] for r in x_rows}
    y_ids = {r["id"] for r in y_rows}
    assert x_ids.isdisjoint(y_ids)
    assert all(r["org_id"] == "org-X" for r in x_rows)
    assert all(r["org_id"] == "org-Y" for r in y_rows)


def test_org_isolation_no_cross_leak_on_findings(tmp_engine):
    q_x = tmp_engine.enqueue_scan(
        org_id="org-X", provider="aws", account_id="prod"
    )
    q_y = tmp_engine.enqueue_scan(
        org_id="org-Y", provider="aws", account_id="prod"
    )
    for q in q_x + q_y:
        tmp_engine.run_scan(snapshot_db_id=q["id"])
    x_findings = tmp_engine.list_findings(org_id="org-X")
    y_findings = tmp_engine.list_findings(org_id="org-Y")
    assert x_findings
    assert y_findings
    assert all(f["org_id"] == "org-X" for f in x_findings)
    assert all(f["org_id"] == "org-Y" for f in y_findings)


def test_org_isolation_on_stats(tmp_engine):
    tmp_engine.enqueue_scan(org_id="org-X", provider="aws", account_id="prod")
    tmp_engine.enqueue_scan(org_id="org-Y", provider="aws", account_id="dev")
    assert tmp_engine.stats(org_id="org-X")["total_snapshots"] == 3
    assert tmp_engine.stats(org_id="org-Y")["total_snapshots"] == 2
    assert tmp_engine.stats(org_id="nobody")["total_snapshots"] == 0


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_stats_shape_is_stable(tmp_engine):
    s = tmp_engine.stats(org_id="nobody")
    assert set(s.keys()) >= {
        "total_snapshots",
        "total_findings",
        "by_status",
        "by_severity",
        "by_type",
    }
    assert set(s["by_status"].keys()) >= {"pending", "scanning", "complete", "failed"}
    assert set(s["by_severity"].keys()) >= {"critical", "high", "medium", "low", "info"}
    assert set(s["by_type"].keys()) >= {"secret", "vulnerable_package", "malware"}


def test_stats_reflects_scan_progress(tmp_engine):
    queued = tmp_engine.enqueue_scan(
        org_id="org-R", provider="aws", account_id="prod"
    )
    before = tmp_engine.stats(org_id="org-R")
    assert before["by_status"]["pending"] == 3
    tmp_engine.run_scan(snapshot_db_id=queued[0]["id"])
    after = tmp_engine.stats(org_id="org-R")
    assert after["by_status"]["complete"] == 1
    assert after["by_status"]["pending"] == 2
    assert after["total_findings"] > 0


def test_repeated_scan_does_not_duplicate_findings_unexpectedly(tmp_engine):
    # Not strictly idempotent — running scan twice creates two sets of findings.
    # Test documents this behaviour so we don't regress.
    queued = tmp_engine.enqueue_scan(
        org_id="org-S", provider="aws", account_id="prod"
    )
    target = queued[0]
    tmp_engine.run_scan(snapshot_db_id=target["id"])
    first = len(tmp_engine.list_findings(
        org_id="org-S", snapshot_db_id=target["id"]
    ))
    tmp_engine.run_scan(snapshot_db_id=target["id"])
    second = len(tmp_engine.list_findings(
        org_id="org-S", snapshot_db_id=target["id"]
    ))
    assert second == 2 * first


# ---------------------------------------------------------------------------
# Misc hardening
# ---------------------------------------------------------------------------


def test_adapter_can_be_set_before_enqueue(tmp_engine):
    blob = SnapshotBlob(
        snapshot_id="custom-1",
        files={"/etc/passwd": b"root:x:0:0:root:/root:/bin/bash\n"},
    )
    tmp_engine.set_adapter(StubAdapter({"custom-1": blob}))
    queued = tmp_engine.enqueue_scan(
        org_id="org-T", provider="aws", account_id="custom"
    )
    assert len(queued) == 1
    result = tmp_engine.run_scan(snapshot_db_id=queued[0]["id"])
    assert result["status"] == "complete"


def test_enqueue_preserves_tags_as_json(tmp_engine):
    queued = tmp_engine.enqueue_scan(
        org_id="org-U", provider="aws", account_id="prod"
    )
    tags = json.loads(queued[0]["tags_json"])
    assert tags.get("synthetic") == "true"
    assert tags.get("account") == "prod"


def test_binary_content_survives_decode_errors(tmp_engine):
    blob = SnapshotBlob(
        snapshot_id="bin-1",
        files={"/bin/ls": bytes(range(256))},  # Lots of non-utf8
    )
    tmp_engine.set_adapter(StubAdapter({"bin-1": blob}))
    queued = tmp_engine.enqueue_scan(
        org_id="org-V", provider="aws", account_id="bin"
    )
    # Should not raise — decode errors are recovered via 'replace'.
    result = tmp_engine.run_scan(snapshot_db_id=queued[0]["id"])
    assert result["status"] == "complete"


def test_enqueue_returns_stable_shape(tmp_engine):
    queued = tmp_engine.enqueue_scan(
        org_id="org-W", provider="aws", account_id="shape"
    )
    required = {
        "id",
        "org_id",
        "provider",
        "account_id",
        "snapshot_id",
        "scan_status",
    }
    for record in queued:
        assert required.issubset(record.keys())


def test_list_findings_min_severity_rejects_invalid(tmp_engine):
    with pytest.raises(ValueError):
        tmp_engine.list_findings(org_id="x", min_severity="armageddon")


def test_multi_provider_enqueue_preserves_counts(tmp_engine):
    tmp_engine.enqueue_scan(org_id="org-Z", provider="aws", account_id="prod")
    tmp_engine.enqueue_scan(org_id="org-Z", provider="gcp", account_id="dev")
    tmp_engine.enqueue_scan(org_id="org-Z", provider="azure", account_id="dev")
    assert tmp_engine.stats(org_id="org-Z")["total_snapshots"] == 3 + 2 + 2
