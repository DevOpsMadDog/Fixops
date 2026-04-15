"""Tests for EmailSecurityEngine — DMARC/SPF/DKIM analysis backend.

25+ tests covering: init, add/list domains, compliance scoring, analyze_domain,
update_domain_policy, create/list/update threats, DMARC reports, stats,
and org isolation.
"""
from __future__ import annotations

import os
import sys
import tempfile
import pytest

# Ensure suite-core is on the path
_SUITE_CORE = os.path.join(os.path.dirname(__file__), "..", "suite-core")
if _SUITE_CORE not in sys.path:
    sys.path.insert(0, _SUITE_CORE)

from core.email_security_engine import EmailSecurityEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "test_email_security.db")
    return EmailSecurityEngine(db_path=db)


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = str(tmp_path / "init_test.db")
    eng = EmailSecurityEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "idempotent.db")
    EmailSecurityEngine(db_path=db)
    EmailSecurityEngine(db_path=db)  # second init must not raise
    assert os.path.exists(db)


# ---------------------------------------------------------------------------
# add_domain / list_domains
# ---------------------------------------------------------------------------


def test_add_domain_minimal(engine):
    result = engine.add_domain("org1", "example.com")
    assert result["domain"] == "example.com"
    assert result["org_id"] == "org1"
    assert "domain_id" in result
    assert result["spf_status"] == "missing"
    assert result["dkim_status"] == "missing"
    assert result["dmarc_policy"] == "missing"
    assert result["compliance_score"] == 0


def test_add_domain_with_spf(engine):
    result = engine.add_domain("org1", "spf.com", spf_record="v=spf1 include:_spf.example.com ~all")
    assert result["spf_status"] == "pass"
    assert result["dkim_status"] == "missing"
    assert result["compliance_score"] > 0


def test_add_domain_with_dkim(engine):
    result = engine.add_domain("org1", "dkim.com", dkim_selector="default")
    assert result["dkim_status"] == "pass"
    assert result["compliance_score"] > 0


def test_add_domain_with_dmarc_reject(engine):
    result = engine.add_domain(
        "org1", "full.com",
        spf_record="v=spf1 -all",
        dkim_selector="mail",
        dmarc_policy="reject",
    )
    assert result["spf_status"] == "pass"
    assert result["dkim_status"] == "pass"
    assert result["dmarc_policy"] == "reject"
    assert result["compliance_score"] == 100  # 30+30+40=100


def test_add_domain_with_dmarc_quarantine(engine):
    result = engine.add_domain(
        "org1", "quarantine.com",
        spf_record="v=spf1 -all",
        dkim_selector="mail",
        dmarc_policy="quarantine",
    )
    assert result["compliance_score"] == 85  # 30+30+25=85


def test_add_domain_with_dmarc_none(engine):
    result = engine.add_domain(
        "org1", "none-policy.com",
        spf_record="v=spf1 -all",
        dkim_selector="mail",
        dmarc_policy="none",
    )
    assert result["compliance_score"] == 70  # 30+30+10=70


def test_add_domain_invalid_dmarc_policy_normalised(engine):
    result = engine.add_domain("org1", "bad.com", dmarc_policy="unknown_policy")
    assert result["dmarc_policy"] == "missing"


def test_list_domains_empty(engine):
    assert engine.list_domains("org_empty") == []


def test_list_domains_returns_all(engine):
    engine.add_domain("org2", "a.com")
    engine.add_domain("org2", "b.com")
    domains = engine.list_domains("org2")
    assert len(domains) == 2
    names = {d["domain"] for d in domains}
    assert names == {"a.com", "b.com"}


def test_list_domains_ordered_by_score_asc(engine):
    engine.add_domain("org3", "low.com")  # score=0
    engine.add_domain("org3", "high.com", spf_record="v=spf1 -all", dkim_selector="s", dmarc_policy="reject")
    domains = engine.list_domains("org3")
    assert domains[0]["domain"] == "low.com"
    assert domains[1]["domain"] == "high.com"


# ---------------------------------------------------------------------------
# analyze_domain
# ---------------------------------------------------------------------------


def test_analyze_domain_returns_updated_score(engine):
    d = engine.add_domain("org1", "analyze.com", spf_record="v=spf1 -all", dmarc_policy="reject")
    result = engine.analyze_domain("org1", d["domain_id"])
    assert result["compliance_score"] == d["compliance_score"]
    assert "issues" in result


def test_analyze_domain_not_found_raises(engine):
    with pytest.raises(ValueError):
        engine.analyze_domain("org1", "nonexistent-uuid")


def test_analyze_domain_detects_issues(engine):
    d = engine.add_domain("org1", "issues.com")  # all missing
    result = engine.analyze_domain("org1", d["domain_id"])
    assert len(result["issues"]) > 0
    issue_text = " ".join(result["issues"])
    assert "SPF" in issue_text or "DKIM" in issue_text or "DMARC" in issue_text


# ---------------------------------------------------------------------------
# update_domain_policy
# ---------------------------------------------------------------------------


def test_update_domain_policy_dmarc(engine):
    d = engine.add_domain("org1", "update.com")
    assert d["compliance_score"] == 0
    ok = engine.update_domain_policy("org1", d["domain_id"], {"dmarc_policy": "quarantine"})
    assert ok is True
    updated = engine.get_domain("org1", d["domain_id"])
    assert updated["dmarc_policy"] == "quarantine"
    assert updated["compliance_score"] > 0


def test_update_domain_policy_spf_record(engine):
    d = engine.add_domain("org1", "spfupdate.com")
    ok = engine.update_domain_policy("org1", d["domain_id"], {"spf_record": "v=spf1 -all"})
    assert ok is True
    updated = engine.get_domain("org1", d["domain_id"])
    assert updated["spf_status"] == "pass"


def test_update_domain_policy_no_valid_fields(engine):
    d = engine.add_domain("org1", "noop.com")
    ok = engine.update_domain_policy("org1", d["domain_id"], {"nonexistent": "value"})
    assert ok is False


def test_update_domain_policy_not_found(engine):
    ok = engine.update_domain_policy("org1", "bad-uuid", {"dmarc_policy": "reject"})
    assert ok is False


# ---------------------------------------------------------------------------
# create_threat / list_threats / update_threat_status
# ---------------------------------------------------------------------------


def test_create_threat_minimal(engine):
    t = engine.create_threat("org1", {"threat_type": "phishing", "sender": "evil@bad.com"})
    assert "threat_id" in t
    assert t["threat_type"] == "phishing"
    assert t["status"] == "detected"
    assert t["org_id"] == "org1"


def test_create_threat_all_fields(engine):
    t = engine.create_threat("org1", {
        "threat_type": "spoofing",
        "source_ip": "1.2.3.4",
        "sender": "spoof@evil.com",
        "subject_preview": "Urgent action needed",
        "similarity_score": 0.95,
        "status": "blocked",
    })
    assert t["threat_type"] == "spoofing"
    assert t["source_ip"] == "1.2.3.4"
    assert t["similarity_score"] == 0.95
    assert t["status"] == "blocked"


def test_create_threat_invalid_type_defaults(engine):
    t = engine.create_threat("org1", {"threat_type": "unknown"})
    assert t["threat_type"] == "phishing"


def test_list_threats_empty(engine):
    assert engine.list_threats("org_none") == []


def test_list_threats_all(engine):
    engine.create_threat("org4", {"threat_type": "phishing"})
    engine.create_threat("org4", {"threat_type": "spam"})
    threats = engine.list_threats("org4")
    assert len(threats) == 2


def test_list_threats_filter_by_type(engine):
    engine.create_threat("org5", {"threat_type": "phishing"})
    engine.create_threat("org5", {"threat_type": "spam"})
    phishing = engine.list_threats("org5", threat_type="phishing")
    assert len(phishing) == 1
    assert phishing[0]["threat_type"] == "phishing"


def test_list_threats_filter_by_status(engine):
    engine.create_threat("org6", {"threat_type": "bec", "status": "blocked"})
    engine.create_threat("org6", {"threat_type": "spam", "status": "detected"})
    blocked = engine.list_threats("org6", status="blocked")
    assert len(blocked) == 1
    assert blocked[0]["status"] == "blocked"


def test_update_threat_status_valid(engine):
    t = engine.create_threat("org1", {"threat_type": "malware"})
    ok = engine.update_threat_status("org1", t["threat_id"], "quarantined")
    assert ok is True
    threats = engine.list_threats("org1", status="quarantined")
    assert any(x["threat_id"] == t["threat_id"] for x in threats)


def test_update_threat_status_invalid(engine):
    t = engine.create_threat("org1", {"threat_type": "phishing"})
    ok = engine.update_threat_status("org1", t["threat_id"], "invalid_status")
    assert ok is False


def test_update_threat_status_not_found(engine):
    ok = engine.update_threat_status("org1", "nonexistent-uuid", "blocked")
    assert ok is False


# ---------------------------------------------------------------------------
# DMARC reports
# ---------------------------------------------------------------------------


def test_add_dmarc_report(engine):
    d = engine.add_domain("org1", "dmarc-report.com")
    r = engine.add_dmarc_report("org1", d["domain_id"], {
        "date": "2026-04-16",
        "pass_count": 100,
        "fail_count": 5,
        "quarantine_count": 2,
        "reject_count": 1,
        "source_ips": ["1.2.3.4", "5.6.7.8"],
    })
    assert "report_id" in r
    assert r["pass_count"] == 100
    assert r["fail_count"] == 5
    assert r["source_ips"] == ["1.2.3.4", "5.6.7.8"]


def test_list_dmarc_reports_all(engine):
    d = engine.add_domain("org1", "reports.com")
    engine.add_dmarc_report("org1", d["domain_id"], {"pass_count": 10})
    engine.add_dmarc_report("org1", d["domain_id"], {"pass_count": 20})
    reports = engine.list_dmarc_reports("org1")
    assert len(reports) == 2


def test_list_dmarc_reports_filter_by_domain(engine):
    d1 = engine.add_domain("org1", "d1.com")
    d2 = engine.add_domain("org1", "d2.com")
    engine.add_dmarc_report("org1", d1["domain_id"], {"pass_count": 10})
    engine.add_dmarc_report("org1", d2["domain_id"], {"pass_count": 20})
    reports = engine.list_dmarc_reports("org1", domain_id=d1["domain_id"])
    assert len(reports) == 1
    assert reports[0]["domain_id"] == d1["domain_id"]


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_get_email_stats_empty(engine):
    stats = engine.get_email_stats("org_empty_stats")
    assert stats["total_domains"] == 0
    assert stats["compliant_domains"] == 0
    assert stats["threats_detected"] == 0
    assert stats["threats_blocked"] == 0
    assert stats["phishing_count"] == 0
    assert stats["avg_compliance_score"] == 0.0


def test_get_email_stats_with_data(engine):
    # Add a fully compliant domain
    engine.add_domain("org7", "full.com", spf_record="v=spf1 -all", dkim_selector="s", dmarc_policy="reject")
    # Add a non-compliant domain
    engine.add_domain("org7", "bare.com")
    # Add threats
    engine.create_threat("org7", {"threat_type": "phishing", "status": "detected"})
    engine.create_threat("org7", {"threat_type": "spam", "status": "blocked"})
    engine.create_threat("org7", {"threat_type": "phishing", "status": "quarantined"})

    stats = engine.get_email_stats("org7")
    assert stats["total_domains"] == 2
    assert stats["compliant_domains"] == 1  # only full.com score=100
    assert stats["threats_detected"] == 3
    assert stats["threats_blocked"] == 2  # blocked + quarantined
    assert stats["phishing_count"] == 2
    assert stats["avg_compliance_score"] == 50.0  # (100+0)/2


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_domains(engine):
    engine.add_domain("orgA", "a.com")
    engine.add_domain("orgB", "b.com")
    assert len(engine.list_domains("orgA")) == 1
    assert len(engine.list_domains("orgB")) == 1
    assert engine.list_domains("orgA")[0]["domain"] == "a.com"
    assert engine.list_domains("orgB")[0]["domain"] == "b.com"


def test_org_isolation_threats(engine):
    engine.create_threat("orgA", {"threat_type": "phishing"})
    engine.create_threat("orgB", {"threat_type": "spam"})
    assert len(engine.list_threats("orgA")) == 1
    assert len(engine.list_threats("orgB")) == 1


def test_org_isolation_stats(engine):
    engine.add_domain("orgX", "x.com", spf_record="v=spf1 -all", dkim_selector="s", dmarc_policy="reject")
    engine.add_domain("orgY", "y.com")
    x_stats = engine.get_email_stats("orgX")
    y_stats = engine.get_email_stats("orgY")
    assert x_stats["total_domains"] == 1
    assert x_stats["compliant_domains"] == 1
    assert y_stats["total_domains"] == 1
    assert y_stats["compliant_domains"] == 0


def test_update_domain_cross_org_denied(engine):
    d = engine.add_domain("orgA", "secret.com")
    ok = engine.update_domain_policy("orgB", d["domain_id"], {"dmarc_policy": "reject"})
    assert ok is False
    # orgA domain must be unchanged
    unchanged = engine.get_domain("orgA", d["domain_id"])
    assert unchanged["dmarc_policy"] == "missing"
