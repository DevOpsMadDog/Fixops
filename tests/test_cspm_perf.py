"""Performance regression tests for CSPM engines.

Validates that the two hotspot fixes in suite-core/core/cspm.py land
within acceptable wall-clock budgets:

  Fix 1 — run_security_checks: batch executemany replaces per-result
           connection open/close (1 conn instead of N×M conns).

  Fix 2 — get_cspm_score: single SQL aggregate replaces 3 full table
           scans (list_resources × 3).
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import json
import os
import sqlite3
import tempfile
import time
import uuid
from datetime import datetime, timezone
from typing import List

import pytest


# ---------------------------------------------------------------------------
# Helper — build a real CSPMEngine against a tmp-file DB
# ---------------------------------------------------------------------------

def _make_engine(tmp_db: str):
    """Return a CSPMEngine that stores data in `tmp_db`."""
    from core.cspm import CSPMEngine
    return CSPMEngine(db_path=tmp_db)


def _resource_row(org_id: str, public: bool = False, encrypted: bool = True):
    """Build a (14-column) tuple for INSERT into cloud_resources."""
    return (
        str(uuid.uuid4()),      # id
        "AWS",                  # provider
        "STORAGE",              # category
        "s3_bucket",            # resource_type
        str(uuid.uuid4()),      # resource_id
        "test-bucket",          # name
        "us-east-1",            # region
        "123456789",            # account_id
        json.dumps({"block_public_access": not public}),  # config
        json.dumps({}),         # tags
        int(public),            # public_exposure
        int(encrypted),         # encryption_enabled
        datetime.now(timezone.utc).isoformat(),  # last_synced
        org_id,                 # org_id
    )


def _seed_resources(engine, n: int, org_id: str):
    conn = engine._get_conn()
    try:
        rows = [_resource_row(org_id, public=(i % 3 == 0), encrypted=(i % 5 != 0))
                for i in range(n)]
        conn.executemany(
            """INSERT OR IGNORE INTO cloud_resources
               (id, provider, category, resource_type, resource_id, name,
                region, account_id, config, tags, public_exposure,
                encryption_enabled, last_synced, org_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Fix 1: batch persist — run_security_checks uses one connection
# ---------------------------------------------------------------------------

class TestRunSecurityChecksBatchPerf:

    def test_batch_persist_completes_within_budget(self, tmp_path):
        """50-resource scan must finish under 3 s."""
        engine = _make_engine(str(tmp_path / "cspm.db"))
        org = "perf-org-1"
        _seed_resources(engine, 50, org)

        t0 = time.perf_counter()
        results = engine.run_security_checks(org_id=org)
        elapsed = time.perf_counter() - t0

        assert elapsed < 3.0, (
            f"run_security_checks(50 resources) took {elapsed:.3f}s — exceeds 3s budget"
        )
        # no crash is the primary invariant
        assert isinstance(results, list)

    def test_persist_results_bulk_single_connection(self, tmp_path):
        """_persist_results_bulk must open exactly 1 connection for any N results."""
        engine = _make_engine(str(tmp_path / "cspm2.db"))

        conn_calls: List[int] = []
        _real_get_conn = engine._get_conn

        def _counting_conn():
            conn_calls.append(1)
            return _real_get_conn()

        engine._get_conn = _counting_conn  # type: ignore[method-assign]

        from core.cspm import CheckResult, ComplianceStatus
        fake_results = [
            CheckResult(
                resource_id=str(uuid.uuid4()),
                check_id=str(uuid.uuid4()),
                status=ComplianceStatus.COMPLIANT,
                details="ok",
                remediation="",
            )
            for _ in range(20)
        ]

        engine._persist_results_bulk(fake_results, "perf-org-2")

        assert len(conn_calls) == 1, (
            f"_persist_results_bulk opened {len(conn_calls)} connections for 20 results "
            f"— expected exactly 1"
        )


# ---------------------------------------------------------------------------
# Fix 2: get_cspm_score — single aggregate query replaces 3 list_resources calls
# ---------------------------------------------------------------------------

class TestGetCspmScoreSingleQuery:

    def test_list_resources_not_called_for_counts(self, tmp_path):
        """get_cspm_score must NOT call list_resources() to obtain resource counts.

        Before the fix it called list_resources 3 times (public, unencrypted,
        total). After the fix a single SQL aggregate handles all three.
        """
        engine = _make_engine(str(tmp_path / "cspm3.db"))
        org = "score-org"
        _seed_resources(engine, 20, org)

        list_resources_calls: List[str] = []
        _real_list = engine.list_resources

        def _spy(*args, **kwargs):
            list_resources_calls.append("called")
            return _real_list(*args, **kwargs)

        engine.list_resources = _spy  # type: ignore[method-assign]

        score = engine.get_cspm_score(org)

        # get_compliance_summary calls list_resources once for check results;
        # the new get_cspm_score itself uses a SQL aggregate — so total ≤ 1.
        assert len(list_resources_calls) <= 1, (
            f"get_cspm_score called list_resources {len(list_resources_calls)} times "
            f"— expected ≤1 (old code called it 3 times)"
        )
        assert 0.0 <= score <= 100.0

    def test_get_cspm_score_completes_quickly(self, tmp_path):
        """get_cspm_score on 200 resources must finish under 1 second."""
        engine = _make_engine(str(tmp_path / "cspm4.db"))
        org = "score-org-2"
        _seed_resources(engine, 200, org)

        t0 = time.perf_counter()
        score = engine.get_cspm_score(org)
        elapsed = time.perf_counter() - t0

        assert elapsed < 1.0, (
            f"get_cspm_score(200 resources) took {elapsed:.3f}s — exceeds 1s budget"
        )
        assert 0.0 <= score <= 100.0


# ---------------------------------------------------------------------------
# Regression: IaC scanner (cspm_engine.py) regex pre-compilation guard
# ---------------------------------------------------------------------------

class TestCspmEngineRegexPrecompiled:

    def test_module_level_regexes_are_compiled(self):
        import re
        import core.cspm_engine as mod

        compiled = [
            name for name, val in vars(mod).items()
            if isinstance(val, type(re.compile(""))) and name.startswith("_TF_")
        ]
        assert len(compiled) >= 8, (
            f"Expected ≥8 pre-compiled _TF_* regexes, found {len(compiled)}: {compiled}"
        )

    def test_scan_terraform_returns_finding(self):
        from core.cspm_engine import get_cspm_engine
        engine = get_cspm_engine()
        hcl = '''
resource "aws_s3_bucket" "bad" {
  acl = "public-read"
  cidr_blocks = ["0.0.0.0/0"]
}
'''
        result = engine.scan_terraform(hcl)
        assert result.total_findings >= 1
        assert 0.0 <= result.compliance_score <= 100.0
        assert result.duration_ms >= 0

    def test_scan_cloudformation_returns_finding(self):
        from core.cspm_engine import get_cspm_engine
        engine = get_cspm_engine()
        template = {
            "Resources": {
                "MyBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"AccessControl": "PublicRead"},
                }
            }
        }
        result = engine.scan_cloudformation(json.dumps(template))
        assert result.total_findings >= 1
        assert result.resources_scanned == 1
