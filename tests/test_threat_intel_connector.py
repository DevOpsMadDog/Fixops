"""Tests for the Threat Intel connector (MISP / CIRCL / PhishTank / OTX).

Tests are *deterministic*: they monkey-patch ``requests.Session.get`` (and
``post``) so we never depend on third-party servers being reachable from CI.
The fusion + correlation engines run for real against a temp SQLite DB.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# Ensure ALDECI root is importable when tests run standalone.
ROOT = Path(__file__).resolve().parents[1]
for p in (
    ROOT,
    ROOT / "suite-core",
    ROOT / "suite-api",
    ROOT / "suite-feeds",
):
    sp = str(p)
    if sp not in sys.path:
        sys.path.insert(0, sp)

from connectors.threat_intel_connector import (  # noqa: E402
    PHISHTANK_URL,
    SyncResult,
    ThreatIntelConnector,
)


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_data(monkeypatch):
    """Redirect engine SQLite paths into a tmp dir."""
    tmp = Path(tempfile.mkdtemp(prefix="ti_conn_"))
    # Per-org SQLite stores: fusion + correlation use _DEFAULT_DB_DIR.
    import core.threat_intel_fusion_engine as tif
    import core.security_event_correlation_engine as sec_corr
    # Single-file SQLite store: SecurityFindingsEngine uses _DEFAULT_DB.
    import core.security_findings_engine as sfe_mod

    monkeypatch.setattr(tif, "_DEFAULT_DB_DIR", tmp)
    monkeypatch.setattr(sec_corr, "_DEFAULT_DB_DIR", tmp)
    monkeypatch.setattr(sfe_mod, "_DEFAULT_DB", str(tmp / "security_findings.db"))
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def connector(tmp_data):
    return ThreatIntelConnector(request_timeout=2, max_indicators_per_source=200)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_response(payload: Any, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = payload
    resp.raise_for_status = lambda: None if 200 <= status < 300 else (_ for _ in ()).throw(
        Exception(f"HTTP {status}")
    )
    return resp


# ---------------------------------------------------------------------------
# Classification + helpers
# ---------------------------------------------------------------------------


class TestClassification:
    def test_ip_classified(self):
        assert ThreatIntelConnector._classify_value("8.8.8.8") == "ip"

    def test_domain_classified(self):
        assert ThreatIntelConnector._classify_value("evil.example.com") == "domain"

    def test_url_classified(self):
        assert ThreatIntelConnector._classify_value("https://bad.example/x") == "url"

    def test_hash_classified(self):
        assert ThreatIntelConnector._classify_value("a" * 64) == "hash"

    def test_garbage_returns_none(self):
        assert ThreatIntelConnector._classify_value("???") is None

    def test_empty_returns_none(self):
        assert ThreatIntelConnector._classify_value("   ") is None

    def test_misp_type_mapping(self):
        m = ThreatIntelConnector._misp_type_to_internal
        assert m("ip-src", "1.2.3.4") == "ip"
        assert m("domain", "x.example") == "domain"
        assert m("url", "http://x") == "url"
        assert m("sha256", "a" * 64) == "hash"
        assert m("email-src", "x@y.z") == "email"

    def test_otx_type_mapping(self):
        m = ThreatIntelConnector._otx_type_to_internal
        assert m("IPv4", "1.2.3.4") == "ip"
        assert m("hostname", "evil.example") == "domain"
        assert m("FileHash-SHA256", "a" * 64) == "hash"
        assert m("Url", "https://x") == "url"


class TestSafeUrl:
    def test_https_ok(self):
        assert ThreatIntelConnector._safe_url("https://example.com/x")

    def test_localhost_blocked(self):
        assert not ThreatIntelConnector._safe_url("http://localhost/x")

    def test_metadata_ip_blocked(self):
        assert not ThreatIntelConnector._safe_url("http://169.254.169.254/")

    def test_non_http_blocked(self):
        assert not ThreatIntelConnector._safe_url("file:///etc/passwd")

    def test_empty_blocked(self):
        assert not ThreatIntelConnector._safe_url("")


# ---------------------------------------------------------------------------
# MISP adapter
# ---------------------------------------------------------------------------


class TestMispAdapter:
    def test_misp_ingests_attributes(self, connector):
        manifest = {
            "uuid-event-1": {"timestamp": 100, "info": "Malware run"},
        }
        event_doc = {
            "Event": {
                "uuid": "uuid-event-1",
                "info": "Malware run",
                "Tag": [{"name": "tlp:white"}, {"name": "malware"}],
                "Attribute": [
                    {"type": "ip-dst", "value": "1.2.3.4", "to_ids": True},
                    {"type": "domain", "value": "evil.example.com", "to_ids": True},
                    {"type": "url", "value": "http://evil.example.com/x", "to_ids": True},
                    {"type": "sha256", "value": "a" * 64, "to_ids": True},
                ],
            }
        }

        def fake_get(url, **kwargs):
            if url.endswith("manifest.json"):
                return _mock_response(manifest)
            if url.endswith("uuid-event-1.json"):
                return _mock_response(event_doc)
            return _mock_response({}, status=404)

        with patch.object(connector._session, "get", side_effect=fake_get):
            n = connector.sync_misp("acme")
        # 4 attributes per manifest, 2 manifests in defaults = up to 8 (deduped).
        assert n >= 4

    def test_misp_handles_unsafe_url(self, connector):
        bad = ThreatIntelConnector(misp_feed_urls=["http://localhost/manifest.json"])
        # Should bail out without exception.
        assert bad.sync_misp("acme") == 0

    def test_misp_handles_network_error(self, connector):
        def boom(url, **kwargs):
            raise __import__("requests").RequestException("network down")

        with patch.object(connector._session, "get", side_effect=boom):
            assert connector.sync_misp("acme") == 0

    def test_misp_handles_malformed_manifest(self, connector):
        def fake_get(url, **kwargs):
            return _mock_response("not-a-dict")

        with patch.object(connector._session, "get", side_effect=fake_get):
            assert connector.sync_misp("acme") == 0


# ---------------------------------------------------------------------------
# CIRCL CVE adapter
# ---------------------------------------------------------------------------


class TestCirclAdapter:
    def test_circl_legacy_list_payload(self, connector):
        payload = [
            {
                "id": "CVE-2099-0001",
                "Published": "2099-01-01T00:00:00",
                "cvss": 9.8,
            },
            {
                "id": "CVE-2099-0002",
                "Published": "2099-01-01T00:00:00",
                "cvss": 5.0,
            },
        ]

        def fake_get(url, **kwargs):
            return _mock_response(payload)

        with patch.object(connector._session, "get", side_effect=fake_get):
            n = connector.sync_circl("acme", hours_back=24 * 365 * 100)
        assert n == 2

    def test_circl_modern_data_payload(self, connector):
        payload = {
            "data": [
                {"cveMetadata": {"cveId": "CVE-2099-1234", "datePublished": "2099-01-01T00:00:00"}, "cvssV3": 7.5}
            ]
        }

        def fake_get(url, **kwargs):
            return _mock_response(payload)

        with patch.object(connector._session, "get", side_effect=fake_get):
            n = connector.sync_circl("acme", hours_back=24 * 365 * 100)
        assert n == 1

    def test_circl_skips_old_cves(self, connector):
        payload = [{"id": "CVE-1999-0001", "Published": "1999-01-01T00:00:00", "cvss": 5.0}]

        def fake_get(url, **kwargs):
            return _mock_response(payload)

        with patch.object(connector._session, "get", side_effect=fake_get):
            assert connector.sync_circl("acme", hours_back=24) == 0

    def test_circl_handles_network_error(self, connector):
        def boom(url, **kwargs):
            raise __import__("requests").RequestException("circl down")

        with patch.object(connector._session, "get", side_effect=boom):
            assert connector.sync_circl("acme") == 0


# ---------------------------------------------------------------------------
# PhishTank adapter
# ---------------------------------------------------------------------------


class TestPhishtankAdapter:
    def test_phishtank_ingests_verified_online(self, connector):
        payload = [
            {
                "url": "https://phish.example.com/login",
                "verified": "yes",
                "online": "yes",
                "target": "PayPal",
            },
            # Filtered out — not verified.
            {
                "url": "https://maybe.example.com",
                "verified": "no",
                "online": "yes",
                "target": "Other",
            },
            # Filtered out — offline.
            {
                "url": "https://offline.example.com",
                "verified": "yes",
                "online": "no",
                "target": "Other",
            },
        ]

        with patch.object(
            connector._session, "get", return_value=_mock_response(payload)
        ):
            n = connector.sync_phishtank("acme")
        # 1 url + derived domain
        assert n >= 1

    def test_phishtank_handles_non_list(self, connector):
        with patch.object(
            connector._session, "get", return_value=_mock_response({"unexpected": True})
        ):
            assert connector.sync_phishtank("acme") == 0

    def test_phishtank_handles_network_error(self, connector):
        def boom(url, **kwargs):
            raise __import__("requests").RequestException("phishtank down")

        with patch.object(connector._session, "get", side_effect=boom):
            assert connector.sync_phishtank("acme") == 0


# ---------------------------------------------------------------------------
# OTX adapter (real API path + fallback)
# ---------------------------------------------------------------------------


class TestOtxAdapter:
    def test_otx_real_api_when_key_set(self, tmp_data, monkeypatch):
        c = ThreatIntelConnector(otx_api_key="test-key", request_timeout=2)
        payload = {
            "results": [
                {
                    "tags": ["malware", "apt"],
                    "indicators": [
                        {"type": "IPv4", "indicator": "10.0.0.1"},
                        {"type": "domain", "indicator": "evil.otx.example"},
                        {"type": "FileHash-SHA256", "indicator": "b" * 64},
                    ],
                }
            ]
        }
        with patch.object(c._session, "get", return_value=_mock_response(payload)) as mocked_get:
            n = c.sync_otx("acme")
        assert n == 3
        # Verify real API was called (not the file fallback).
        called_url = mocked_get.call_args.args[0]
        assert "otx.alienvault.com" in called_url

    def test_otx_falls_back_when_no_key(self, tmp_data, monkeypatch):
        # Force the env var off and create a sample file.
        monkeypatch.delenv("OTX_API_KEY", raising=False)
        from connectors import threat_intel_connector as mod

        sample = tmp_data / "otx_sample.json"
        sample.write_text(
            json.dumps(
                {
                    "results": [
                        {
                            "tags": ["fallback"],
                            "indicators": [
                                {"type": "IPv4", "indicator": "172.20.0.1"}
                            ],
                        }
                    ]
                }
            )
        )
        monkeypatch.setattr(mod, "OTX_SAMPLE_FILE", sample)

        c = ThreatIntelConnector(request_timeout=2)
        n = c.sync_otx("acme")
        assert n == 1

    def test_otx_returns_zero_when_no_key_and_no_cache(self, tmp_data, monkeypatch):
        monkeypatch.delenv("OTX_API_KEY", raising=False)
        from connectors import threat_intel_connector as mod

        monkeypatch.setattr(mod, "OTX_SAMPLE_FILE", tmp_data / "does-not-exist.json")
        c = ThreatIntelConnector(request_timeout=2)
        assert c.sync_otx("acme") == 0


# ---------------------------------------------------------------------------
# Cross-correlation
# ---------------------------------------------------------------------------


class TestCrossCorrelation:
    def test_correlates_ioc_against_finding(self, connector):
        # Seed an IoC.
        fusion = connector._get_fusion()
        src = fusion.add_intel_source("acme", {"name": "test", "source_type": "osint"})
        fusion.ingest_indicator(
            "acme",
            {
                "source_id": src["id"],
                "indicator_type": "domain",
                "value": "evil.example.com",
                "confidence": 95,
                "tags": ["test"],
            },
        )

        # Seed a tenant finding mentioning the IoC.
        from core.security_findings_engine import SecurityFindingsEngine

        sfe = SecurityFindingsEngine()
        sfe.record_finding(
            org_id="acme",
            title="Suspicious outbound connection to evil.example.com",
            finding_type="anomaly",
            source_tool="EDR",
            severity="high",
            cvss_score=7.5,
            asset_id="host-1",
            asset_type="endpoint",
            description="Endpoint connected to evil.example.com",
            remediation="Block the destination domain",
        )

        events = connector.cross_correlate("acme")
        assert len(events) >= 1
        ev = events[0]
        assert ev["event_type"] == "ioc_match"
        assert ev["severity"] in ("high", "critical")
        assert ev["entity_type"] == "finding"

    def test_correlate_no_iocs_returns_empty(self, connector):
        assert connector.cross_correlate("empty-org") == []

    def test_correlate_no_findings_returns_empty(self, connector):
        fusion = connector._get_fusion()
        src = fusion.add_intel_source("nofind", {"name": "test"})
        fusion.ingest_indicator(
            "nofind",
            {
                "source_id": src["id"],
                "indicator_type": "ip",
                "value": "1.2.3.4",
                "confidence": 90,
            },
        )
        assert connector.cross_correlate("nofind") == []


# ---------------------------------------------------------------------------
# sync_all + result dataclass
# ---------------------------------------------------------------------------


class TestSyncAll:
    def test_sync_all_runs_each_adapter(self, connector):
        with patch.object(connector, "sync_misp", return_value=3) as m1, patch.object(
            connector, "sync_circl", return_value=4
        ) as m2, patch.object(
            connector, "sync_phishtank", return_value=5
        ) as m3, patch.object(
            connector, "sync_otx", return_value=6
        ) as m4, patch.object(
            connector, "cross_correlate", return_value=[{"id": "ev1"}]
        ) as m5:
            r = connector.sync_all("acme")
        assert r.misp == 3 and r.circl == 4 and r.phishtank == 5 and r.otx == 6
        assert r.correlations == 1
        assert r.total() == 18
        for m in (m1, m2, m3, m4, m5):
            m.assert_called_once()

    def test_sync_all_isolates_adapter_errors(self, connector):
        with patch.object(connector, "sync_misp", side_effect=RuntimeError("nope")), patch.object(
            connector, "sync_circl", return_value=2
        ), patch.object(
            connector, "sync_phishtank", return_value=0
        ), patch.object(
            connector, "sync_otx", return_value=0
        ), patch.object(
            connector, "cross_correlate", return_value=[]
        ):
            r = connector.sync_all("acme")
        assert r.misp == 0 and r.circl == 2
        assert any("misp:" in e for e in r.errors)

    def test_sync_all_validates_org_id(self, connector):
        with pytest.raises(ValueError):
            connector.sync_all("")
        with pytest.raises(ValueError):
            connector.sync_all("x" * 200)

    def test_sync_all_respects_toggles(self, connector):
        with patch.object(connector, "sync_misp", return_value=1) as m1, patch.object(
            connector, "sync_circl", return_value=1
        ) as m2, patch.object(
            connector, "sync_phishtank", return_value=1
        ) as m3, patch.object(
            connector, "sync_otx", return_value=1
        ) as m4, patch.object(
            connector, "cross_correlate", return_value=[]
        ) as m5:
            connector.sync_all(
                "acme",
                run_misp=True,
                run_circl=False,
                run_phishtank=False,
                run_otx=False,
                run_correlation=False,
            )
        m1.assert_called_once()
        m2.assert_not_called()
        m3.assert_not_called()
        m4.assert_not_called()
        m5.assert_not_called()


class TestSyncResult:
    def test_result_total_and_serialization(self):
        r = SyncResult(misp=1, circl=2, phishtank=3, otx=4, correlations=5)
        assert r.total() == 10
        d = r.to_dict()
        assert d["total_ingested"] == 10
        assert d["correlations_created"] == 5


class TestHealth:
    def test_health_reports_all_adapters(self, connector):
        h = connector.health()
        assert set(h.keys()) == {"misp", "circl", "phishtank", "otx"}
        assert isinstance(h["circl"]["endpoints"], list)
        assert "api_key_configured" in h["otx"]
