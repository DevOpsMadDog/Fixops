"""
Tests for the PhishingSimulator engine and phishing_router.

Coverage:
- PhishingTemplate and PhishingCampaign Pydantic models
- All 10 built-in templates present across 5 categories
- create_campaign (happy path, missing template, empty targets, single target)
- record_open / record_click / record_report
- get_campaign_results (counts, rates, per_user, metadata)
- get_user_susceptibility (risk scoring, all risk levels, boundary values)
- get_org_phishing_risk (org-wide aggregation, all risk levels, isolation)
- get_campaign_history (ordering, filtering by org, field completeness)
- add_custom_template + list_templates (CRUD, dedup, replace)
- Singleton get_instance() lifecycle
- Thread-safety smoke test
- Edge cases (invalid inputs, special chars, unknown event types)
- Executive reporting (click/report rates, risk metrics)
- Router endpoints (status codes, response shape, all error paths)

Run with: python -m pytest tests/test_phishing_simulator.py -v --timeout=15
"""

from __future__ import annotations

import sys
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------

from core.phishing_simulator import (
    BUILTIN_TEMPLATES,
    PhishingCampaign,
    PhishingCategory,
    PhishingDifficulty,
    PhishingSimulator,
    PhishingTemplate,
    _TEMPLATE_INDEX,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture()
def sim(tmp_path):
    """Fresh PhishingSimulator backed by a temp database."""
    return PhishingSimulator(db_path=str(tmp_path / "phish_test.db"))


@pytest.fixture()
def org_id():
    return "org_" + uuid.uuid4().hex[:8]


@pytest.fixture()
def template_id():
    """First built-in template ID."""
    return BUILTIN_TEMPLATES[0].id


@pytest.fixture()
def campaign(sim, org_id, template_id):
    """A launched campaign with 3 targets."""
    targets = ["alice@corp.com", "bob@corp.com", "carol@corp.com"]
    return sim.create_campaign("Test Campaign", template_id, targets, org_id)


# ============================================================================
# PYDANTIC MODEL TESTS
# ============================================================================


class TestPhishingTemplate:
    def test_template_defaults(self):
        t = PhishingTemplate(
            name="Test",
            subject="Subj",
            body_html="<p>body</p>",
            category=PhishingCategory.URGENCY,
            difficulty=PhishingDifficulty.EASY,
        )
        assert t.id  # auto-generated
        assert t.indicators == []

    def test_template_category_enum(self):
        assert PhishingCategory.CREDENTIAL_HARVEST == "credential_harvest"
        assert PhishingCategory.MALWARE_LINK == "malware_link"
        assert PhishingCategory.DATA_REQUEST == "data_request"
        assert PhishingCategory.URGENCY == "urgency"
        assert PhishingCategory.AUTHORITY == "authority"

    def test_template_difficulty_enum(self):
        assert PhishingDifficulty.EASY == "easy"
        assert PhishingDifficulty.MEDIUM == "medium"
        assert PhishingDifficulty.HARD == "hard"

    def test_template_with_indicators(self):
        t = PhishingTemplate(
            name="X",
            subject="S",
            body_html="<p/>",
            category=PhishingCategory.AUTHORITY,
            difficulty=PhishingDifficulty.HARD,
            indicators=["clue1", "clue2"],
        )
        assert len(t.indicators) == 2

    def test_template_with_explicit_id(self):
        """Template accepts an explicit ID rather than auto-generating one."""
        custom_id = "explicit_" + uuid.uuid4().hex
        t = PhishingTemplate(
            id=custom_id,
            name="Explicit ID Template",
            subject="Sub",
            body_html="<p>body</p>",
            category=PhishingCategory.MALWARE_LINK,
            difficulty=PhishingDifficulty.MEDIUM,
        )
        assert t.id == custom_id

    def test_template_all_five_categories_instantiate(self):
        """Each PhishingCategory value can construct a valid template."""
        for category in PhishingCategory:
            t = PhishingTemplate(
                name=f"Template {category.value}",
                subject="Sub",
                body_html="<p>body</p>",
                category=category,
                difficulty=PhishingDifficulty.EASY,
            )
            assert t.category == category

    def test_template_all_three_difficulties_instantiate(self):
        """Each PhishingDifficulty value can construct a valid template."""
        for difficulty in PhishingDifficulty:
            t = PhishingTemplate(
                name=f"Template {difficulty.value}",
                subject="Sub",
                body_html="<p>body</p>",
                category=PhishingCategory.URGENCY,
                difficulty=difficulty,
            )
            assert t.difficulty == difficulty

    def test_template_ids_are_unique_across_new_instances(self):
        """Auto-generated template IDs do not collide."""
        ids = {
            PhishingTemplate(
                name="T",
                subject="S",
                body_html="<p/>",
                category=PhishingCategory.URGENCY,
                difficulty=PhishingDifficulty.EASY,
            ).id
            for _ in range(20)
        }
        assert len(ids) == 20


class TestPhishingCampaign:
    def test_campaign_defaults(self):
        c = PhishingCampaign(
            name="Camp",
            template_id="tpl_001",
            org_id="org_001",
        )
        assert c.id
        assert c.sent_count == 0
        assert c.opened_count == 0
        assert c.clicked_count == 0
        assert c.reported_count == 0
        assert c.ended_at is None
        assert c.target_emails == []

    def test_campaign_started_at_is_set(self):
        c = PhishingCampaign(name="C", template_id="t", org_id="o")
        assert c.started_at  # auto-set

    def test_campaign_started_at_is_iso8601(self):
        """started_at timestamp is a valid ISO 8601 string."""
        from datetime import datetime
        c = PhishingCampaign(name="C", template_id="t", org_id="o")
        # Should not raise
        dt = datetime.fromisoformat(c.started_at.replace("Z", "+00:00"))
        assert dt is not None

    def test_campaign_ids_are_unique(self):
        """Auto-generated campaign IDs do not collide."""
        ids = {
            PhishingCampaign(name="C", template_id="t", org_id="o").id
            for _ in range(20)
        }
        assert len(ids) == 20

    def test_campaign_ended_at_can_be_set(self):
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()
        c = PhishingCampaign(name="C", template_id="t", org_id="o", ended_at=ts)
        assert c.ended_at == ts


# ============================================================================
# BUILT-IN TEMPLATES
# ============================================================================


class TestBuiltinTemplates:
    def test_ten_templates_exist(self):
        assert len(BUILTIN_TEMPLATES) == 10

    def test_all_five_categories_covered(self):
        categories = {t.category for t in BUILTIN_TEMPLATES}
        assert PhishingCategory.CREDENTIAL_HARVEST in categories
        assert PhishingCategory.MALWARE_LINK in categories
        assert PhishingCategory.DATA_REQUEST in categories
        assert PhishingCategory.URGENCY in categories
        assert PhishingCategory.AUTHORITY in categories

    def test_all_difficulties_covered(self):
        difficulties = {t.difficulty for t in BUILTIN_TEMPLATES}
        assert difficulties == {
            PhishingDifficulty.EASY,
            PhishingDifficulty.MEDIUM,
            PhishingDifficulty.HARD,
        }

    def test_each_template_has_indicators(self):
        for t in BUILTIN_TEMPLATES:
            assert len(t.indicators) >= 2, f"Template {t.id} needs at least 2 indicators"

    def test_each_template_has_html_body(self):
        for t in BUILTIN_TEMPLATES:
            assert "<" in t.body_html, f"Template {t.id} missing HTML body"

    def test_unique_template_ids(self):
        ids = [t.id for t in BUILTIN_TEMPLATES]
        assert len(ids) == len(set(ids))

    def test_get_template_returns_builtin(self, sim):
        t = sim.get_template(BUILTIN_TEMPLATES[0].id)
        assert t is not None
        assert t.id == BUILTIN_TEMPLATES[0].id

    def test_get_template_unknown_returns_none(self, sim):
        assert sim.get_template("no_such_template") is None

    def test_template_index_matches_builtin_list(self):
        """_TEMPLATE_INDEX contains an entry for every built-in template."""
        for t in BUILTIN_TEMPLATES:
            assert t.id in _TEMPLATE_INDEX

    def test_each_builtin_has_nonempty_subject(self):
        for t in BUILTIN_TEMPLATES:
            assert len(t.subject.strip()) > 0, f"Template {t.id} has empty subject"

    def test_each_builtin_has_nonempty_name(self):
        for t in BUILTIN_TEMPLATES:
            assert len(t.name.strip()) > 0, f"Template {t.id} has empty name"

    def test_two_templates_per_category(self):
        """Each category should have exactly 2 built-in templates."""
        from collections import Counter
        counts = Counter(t.category for t in BUILTIN_TEMPLATES)
        for category in PhishingCategory:
            assert counts[category] == 2, (
                f"Category {category} has {counts[category]} templates, expected 2"
            )

    def test_builtin_credential_harvest_templates_have_expected_ids(self):
        ids = {t.id for t in BUILTIN_TEMPLATES if t.category == PhishingCategory.CREDENTIAL_HARVEST}
        assert "tpl_cred_001" in ids
        assert "tpl_cred_002" in ids

    def test_builtin_hard_templates_have_hard_difficulty(self):
        hard_templates = [t for t in BUILTIN_TEMPLATES if t.difficulty == PhishingDifficulty.HARD]
        assert len(hard_templates) >= 1
        for t in hard_templates:
            assert t.difficulty == PhishingDifficulty.HARD


# ============================================================================
# CREATE CAMPAIGN
# ============================================================================


class TestCreateCampaign:
    def test_create_campaign_returns_campaign(self, sim, org_id, template_id):
        c = sim.create_campaign("Camp A", template_id, ["a@x.com", "b@x.com"], org_id)
        assert isinstance(c, PhishingCampaign)
        assert c.name == "Camp A"
        assert c.org_id == org_id
        assert c.sent_count == 2
        assert c.template_id == template_id

    def test_create_campaign_sets_target_emails(self, sim, org_id, template_id):
        targets = ["x@y.com", "z@y.com", "w@y.com"]
        c = sim.create_campaign("C", template_id, targets, org_id)
        assert c.target_emails == targets

    def test_create_campaign_sent_count_equals_targets(self, sim, org_id, template_id):
        targets = ["a@b.com"] * 5
        c = sim.create_campaign("C", template_id, targets, org_id)
        assert c.sent_count == 5

    def test_create_campaign_invalid_template(self, sim, org_id):
        with pytest.raises(ValueError, match="Template not found"):
            sim.create_campaign("C", "bad_tpl_id", ["a@b.com"], org_id)

    def test_create_campaign_zero_targets(self, sim, org_id, template_id):
        c = sim.create_campaign("Empty", template_id, [], org_id)
        assert c.sent_count == 0

    def test_create_campaign_single_target(self, sim, org_id, template_id):
        c = sim.create_campaign("Solo", template_id, ["solo@x.com"], org_id)
        assert c.sent_count == 1
        assert c.target_emails == ["solo@x.com"]

    def test_create_campaign_persists_to_db(self, sim, org_id, template_id):
        """Campaign created via create_campaign is visible in history immediately."""
        c = sim.create_campaign("Persistent", template_id, ["a@b.com"], org_id)
        history = sim.get_campaign_history(org_id)
        assert any(h["id"] == c.id for h in history)

    def test_create_campaign_name_with_special_characters(self, sim, org_id, template_id):
        """Campaign names with special characters round-trip correctly."""
        name = "Q4 Phishing 'Test' & Review — 2025"
        c = sim.create_campaign(name, template_id, ["a@b.com"], org_id)
        results = sim.get_campaign_results(c.id)
        assert results["name"] == name

    def test_create_campaign_initial_counts_all_zero(self, sim, org_id, template_id):
        """Newly created campaign has zero opened, clicked, reported counts."""
        c = sim.create_campaign("C", template_id, ["a@b.com"], org_id)
        assert c.opened_count == 0
        assert c.clicked_count == 0
        assert c.reported_count == 0

    def test_create_campaign_all_builtin_templates_usable(self, sim, org_id):
        """Every built-in template can be used to create a campaign."""
        for template in BUILTIN_TEMPLATES:
            c = sim.create_campaign(
                f"Camp-{template.id}", template.id, ["a@b.com"], org_id
            )
            assert c.template_id == template.id

    def test_multiple_campaigns_same_org_are_independent(self, sim, org_id, template_id):
        """Two campaigns in the same org do not share state."""
        c1 = sim.create_campaign("C1", template_id, ["a@x.com"], org_id)
        c2 = sim.create_campaign("C2", template_id, ["b@x.com"], org_id)
        sim.record_click(c1.id, "a@x.com")
        r1 = sim.get_campaign_results(c1.id)
        r2 = sim.get_campaign_results(c2.id)
        assert r1["clicked_count"] == 1
        assert r2["clicked_count"] == 0


# ============================================================================
# RECORD INTERACTIONS
# ============================================================================


class TestRecordInteractions:
    def test_record_open_increments_opened_count(self, sim, campaign):
        sim.record_open(campaign.id, "alice@corp.com")
        results = sim.get_campaign_results(campaign.id)
        assert results["opened_count"] == 1

    def test_record_click_increments_clicked_count(self, sim, campaign):
        sim.record_click(campaign.id, "bob@corp.com")
        results = sim.get_campaign_results(campaign.id)
        assert results["clicked_count"] == 1

    def test_record_report_increments_reported_count(self, sim, campaign):
        sim.record_report(campaign.id, "carol@corp.com")
        results = sim.get_campaign_results(campaign.id)
        assert results["reported_count"] == 1

    def test_multiple_interactions_same_user(self, sim, campaign):
        sim.record_open(campaign.id, "alice@corp.com")
        sim.record_click(campaign.id, "alice@corp.com")
        results = sim.get_campaign_results(campaign.id)
        assert results["opened_count"] == 1
        assert results["clicked_count"] == 1

    def test_record_invalid_campaign_raises(self, sim):
        with pytest.raises(ValueError, match="Campaign not found"):
            sim.record_click("no_such_campaign", "x@y.com")

    def test_record_open_invalid_campaign_raises(self, sim):
        with pytest.raises(ValueError, match="Campaign not found"):
            sim.record_open("no_such_campaign", "x@y.com")

    def test_record_report_invalid_campaign_raises(self, sim):
        with pytest.raises(ValueError, match="Campaign not found"):
            sim.record_report("no_such_campaign", "x@y.com")

    def test_multiple_users_each_interact_independently(self, sim, campaign):
        """Each user's events are tracked independently."""
        sim.record_click(campaign.id, "alice@corp.com")
        sim.record_report(campaign.id, "bob@corp.com")
        sim.record_open(campaign.id, "carol@corp.com")
        results = sim.get_campaign_results(campaign.id)
        assert results["clicked_count"] == 1
        assert results["reported_count"] == 1
        assert results["opened_count"] == 1

    def test_record_open_for_non_target_email_still_recorded(self, sim, campaign):
        """Interaction events are accepted even if the email was not in target_emails."""
        sim.record_open(campaign.id, "outsider@corp.com")
        results = sim.get_campaign_results(campaign.id)
        assert results["opened_count"] == 1

    def test_all_three_interaction_types_per_user(self, sim, campaign):
        """A single user can have open, click, and report events."""
        sim.record_open(campaign.id, "alice@corp.com")
        sim.record_click(campaign.id, "alice@corp.com")
        sim.record_report(campaign.id, "alice@corp.com")
        results = sim.get_campaign_results(campaign.id)
        per_user = results["per_user"]["alice@corp.com"]
        assert "open" in per_user
        assert "click" in per_user
        assert "report" in per_user

    def test_click_for_every_target_reaches_100_pct(self, sim, org_id, template_id):
        """When all targets click, click_rate_pct is 100.0."""
        targets = [f"u{i}@corp.com" for i in range(5)]
        c = sim.create_campaign("Full Click", template_id, targets, org_id)
        for email in targets:
            sim.record_click(c.id, email)
        results = sim.get_campaign_results(c.id)
        assert results["click_rate_pct"] == 100.0

    def test_report_for_every_target_reaches_100_pct(self, sim, org_id, template_id):
        """When all targets report, report_rate_pct is 100.0."""
        targets = [f"u{i}@corp.com" for i in range(4)]
        c = sim.create_campaign("Full Report", template_id, targets, org_id)
        for email in targets:
            sim.record_report(c.id, email)
        results = sim.get_campaign_results(c.id)
        assert results["report_rate_pct"] == 100.0


# ============================================================================
# GET CAMPAIGN RESULTS
# ============================================================================


class TestGetCampaignResults:
    def test_results_include_per_user(self, sim, campaign):
        sim.record_click(campaign.id, "alice@corp.com")
        sim.record_report(campaign.id, "bob@corp.com")
        results = sim.get_campaign_results(campaign.id)
        assert "alice@corp.com" in results["per_user"]
        assert "click" in results["per_user"]["alice@corp.com"]
        assert "bob@corp.com" in results["per_user"]
        assert "report" in results["per_user"]["bob@corp.com"]

    def test_click_rate_pct(self, sim, campaign):
        # 3 targets, 1 click → 33.3%
        sim.record_click(campaign.id, "alice@corp.com")
        results = sim.get_campaign_results(campaign.id)
        assert results["click_rate_pct"] == pytest.approx(33.3, rel=0.01)

    def test_report_rate_pct(self, sim, campaign):
        sim.record_report(campaign.id, "carol@corp.com")
        results = sim.get_campaign_results(campaign.id)
        assert results["report_rate_pct"] == pytest.approx(33.3, rel=0.01)

    def test_zero_click_rate_when_no_clicks(self, sim, campaign):
        results = sim.get_campaign_results(campaign.id)
        assert results["click_rate_pct"] == 0.0

    def test_get_results_invalid_campaign_raises(self, sim):
        with pytest.raises(ValueError, match="Campaign not found"):
            sim.get_campaign_results("no_such_campaign")

    def test_results_include_campaign_metadata(self, sim, campaign):
        results = sim.get_campaign_results(campaign.id)
        assert results["name"] == campaign.name
        assert results["org_id"] == campaign.org_id
        assert results["sent_count"] == 3

    def test_results_per_user_empty_when_no_interactions(self, sim, campaign):
        """per_user dict is empty when no interaction events have been recorded."""
        results = sim.get_campaign_results(campaign.id)
        assert results["per_user"] == {}

    def test_results_contain_all_expected_keys(self, sim, campaign):
        """Campaign results dict contains every documented key."""
        results = sim.get_campaign_results(campaign.id)
        expected_keys = {
            "id", "name", "template_id", "target_emails", "sent_count",
            "opened_count", "clicked_count", "reported_count",
            "started_at", "ended_at", "org_id",
            "per_user", "click_rate_pct", "report_rate_pct",
        }
        assert expected_keys.issubset(results.keys())

    def test_results_target_emails_round_trips(self, sim, org_id, template_id):
        """target_emails stored as JSON and restored to a list correctly."""
        targets = ["a@x.com", "b@x.com"]
        c = sim.create_campaign("C", template_id, targets, org_id)
        results = sim.get_campaign_results(c.id)
        assert results["target_emails"] == targets

    def test_zero_sent_produces_zero_rates(self, sim, org_id, template_id):
        """A campaign with no targets has 0.0 for both rates (no division by zero)."""
        c = sim.create_campaign("Empty", template_id, [], org_id)
        results = sim.get_campaign_results(c.id)
        assert results["click_rate_pct"] == 0.0
        assert results["report_rate_pct"] == 0.0

    def test_results_click_rate_two_decimal_precision(self, sim, org_id, template_id):
        """Click rate is rounded to one decimal place."""
        targets = [f"u{i}@corp.com" for i in range(3)]
        c = sim.create_campaign("C", template_id, targets, org_id)
        sim.record_click(c.id, targets[0])
        results = sim.get_campaign_results(c.id)
        # 1/3 = 33.333... → rounded to 33.3
        assert results["click_rate_pct"] == 33.3


# ============================================================================
# USER SUSCEPTIBILITY
# ============================================================================


class TestUserSusceptibility:
    def test_user_with_no_campaigns_returns_unknown(self, sim, org_id):
        result = sim.get_user_susceptibility("ghost@corp.com", org_id)
        assert result["campaigns_targeted"] == 0
        assert result["susceptibility_score"] == 0.0
        assert result["risk_level"] == "unknown"

    def test_user_clicked_is_high_risk(self, sim, org_id, template_id):
        c = sim.create_campaign("C", template_id, ["risky@corp.com"], org_id)
        sim.record_click(c.id, "risky@corp.com")
        result = sim.get_user_susceptibility("risky@corp.com", org_id)
        assert result["susceptibility_score"] == 1.0
        assert result["risk_level"] == "critical"

    def test_user_never_clicked_is_low_risk(self, sim, org_id, template_id):
        c = sim.create_campaign("C", template_id, ["safe@corp.com"], org_id)
        sim.record_report(c.id, "safe@corp.com")
        result = sim.get_user_susceptibility("safe@corp.com", org_id)
        assert result["susceptibility_score"] == 0.0
        assert result["risk_level"] == "low"

    def test_user_susceptibility_across_multiple_campaigns(self, sim, org_id, template_id):
        c1 = sim.create_campaign("C1", template_id, ["user@corp.com"], org_id)
        c2 = sim.create_campaign("C2", template_id, ["user@corp.com"], org_id)
        c3 = sim.create_campaign("C3", template_id, ["user@corp.com"], org_id)
        c4 = sim.create_campaign("C4", template_id, ["user@corp.com"], org_id)
        sim.record_click(c1.id, "user@corp.com")
        sim.record_click(c2.id, "user@corp.com")
        # 2 clicks out of 4 campaigns → 0.5
        result = sim.get_user_susceptibility("user@corp.com", org_id)
        assert result["susceptibility_score"] == 0.5
        assert result["risk_level"] == "high"

    def test_user_report_count_tracked(self, sim, org_id, template_id):
        c = sim.create_campaign("C", template_id, ["user@corp.com"], org_id)
        sim.record_report(c.id, "user@corp.com")
        result = sim.get_user_susceptibility("user@corp.com", org_id)
        assert result["report_count"] == 1

    def test_user_not_in_other_org_campaigns(self, sim, template_id):
        org_a = "org_aaa"
        org_b = "org_bbb"
        c = sim.create_campaign("C", template_id, ["user@corp.com"], org_a)
        sim.record_click(c.id, "user@corp.com")
        # Querying for org_b should return 0
        result = sim.get_user_susceptibility("user@corp.com", org_b)
        assert result["campaigns_targeted"] == 0

    def test_user_susceptibility_low_risk_threshold(self, sim, org_id, template_id):
        """Score < 0.25 → risk_level 'low'."""
        campaigns = [
            sim.create_campaign(f"C{i}", template_id, ["u@corp.com"], org_id)
            for i in range(4)
        ]
        # 0 clicks → score 0.0 → low
        result = sim.get_user_susceptibility("u@corp.com", org_id)
        assert result["risk_level"] == "low"
        assert result["susceptibility_score"] < 0.25

    def test_user_susceptibility_medium_risk_threshold(self, sim, org_id, template_id):
        """Score 0.25 → risk_level 'medium'."""
        campaigns = [
            sim.create_campaign(f"C{i}", template_id, ["u@corp.com"], org_id)
            for i in range(4)
        ]
        # 1 click out of 4 = 0.25 → medium
        sim.record_click(campaigns[0].id, "u@corp.com")
        result = sim.get_user_susceptibility("u@corp.com", org_id)
        assert result["susceptibility_score"] == 0.25
        assert result["risk_level"] == "medium"

    def test_user_susceptibility_high_risk_threshold(self, sim, org_id, template_id):
        """Score 0.5 → risk_level 'high' (not critical)."""
        campaigns = [
            sim.create_campaign(f"C{i}", template_id, ["u@corp.com"], org_id)
            for i in range(4)
        ]
        # 2 clicks out of 4 = 0.5 → high
        sim.record_click(campaigns[0].id, "u@corp.com")
        sim.record_click(campaigns[1].id, "u@corp.com")
        result = sim.get_user_susceptibility("u@corp.com", org_id)
        assert result["susceptibility_score"] == 0.5
        assert result["risk_level"] == "high"

    def test_user_susceptibility_critical_risk_threshold(self, sim, org_id, template_id):
        """Score 0.75 → risk_level 'critical'."""
        campaigns = [
            sim.create_campaign(f"C{i}", template_id, ["u@corp.com"], org_id)
            for i in range(4)
        ]
        # 3 clicks out of 4 = 0.75 → critical
        for camp in campaigns[:3]:
            sim.record_click(camp.id, "u@corp.com")
        result = sim.get_user_susceptibility("u@corp.com", org_id)
        assert result["susceptibility_score"] == 0.75
        assert result["risk_level"] == "critical"

    def test_user_susceptibility_returns_campaigns_targeted_count(self, sim, org_id, template_id):
        """campaigns_targeted reflects actual number of campaigns targeting the user."""
        for i in range(3):
            sim.create_campaign(f"C{i}", template_id, ["u@corp.com"], org_id)
        result = sim.get_user_susceptibility("u@corp.com", org_id)
        assert result["campaigns_targeted"] == 3

    def test_user_susceptibility_click_count_tracked(self, sim, org_id, template_id):
        c = sim.create_campaign("C", template_id, ["u@corp.com"], org_id)
        sim.record_click(c.id, "u@corp.com")
        result = sim.get_user_susceptibility("u@corp.com", org_id)
        assert result["click_count"] == 1

    def test_user_not_targeted_in_campaign_not_counted(self, sim, org_id, template_id):
        """User in org but not in any campaign's target_emails is not counted."""
        sim.create_campaign("C", template_id, ["other@corp.com"], org_id)
        result = sim.get_user_susceptibility("notme@corp.com", org_id)
        assert result["campaigns_targeted"] == 0
        assert result["risk_level"] == "unknown"

    def test_user_susceptibility_result_has_all_keys(self, sim, org_id, template_id):
        sim.create_campaign("C", template_id, ["u@corp.com"], org_id)
        result = sim.get_user_susceptibility("u@corp.com", org_id)
        expected_keys = {
            "email", "org_id", "campaigns_targeted",
            "click_count", "report_count",
            "susceptibility_score", "risk_level",
        }
        assert expected_keys.issubset(result.keys())


# ============================================================================
# ORG PHISHING RISK
# ============================================================================


class TestOrgPhishingRisk:
    def test_empty_org_returns_zeros(self, sim, org_id):
        result = sim.get_org_phishing_risk(org_id)
        assert result["total_campaigns"] == 0
        assert result["susceptibility_rate_pct"] == 0.0
        assert result["risk_level"] == "low"

    def test_org_risk_aggregates_campaigns(self, sim, org_id, template_id):
        c1 = sim.create_campaign("C1", template_id, ["a@x.com", "b@x.com"], org_id)
        c2 = sim.create_campaign("C2", template_id, ["c@x.com", "d@x.com"], org_id)
        sim.record_click(c1.id, "a@x.com")
        sim.record_click(c2.id, "c@x.com")
        result = sim.get_org_phishing_risk(org_id)
        assert result["total_campaigns"] == 2
        assert result["total_sent"] == 4
        assert result["total_clicked"] == 2
        assert result["susceptibility_rate_pct"] == 50.0
        assert result["risk_level"] == "critical"

    def test_org_risk_includes_report_rate(self, sim, org_id, template_id):
        c = sim.create_campaign("C", template_id, ["a@x.com", "b@x.com"], org_id)
        sim.record_report(c.id, "b@x.com")
        result = sim.get_org_phishing_risk(org_id)
        assert result["report_rate_pct"] == 50.0

    def test_org_risk_low_level(self, sim, org_id, template_id):
        # 1 click out of 20 = 5% → low
        c = sim.create_campaign("C", template_id, ["a@x.com"] * 20, org_id)
        sim.record_click(c.id, "a@x.com")
        result = sim.get_org_phishing_risk(org_id)
        assert result["risk_level"] == "low"

    def test_org_risk_medium_level(self, sim, org_id, template_id):
        # 2 clicks out of 10 = 20% → medium (≥10%, <25%)
        targets = [f"u{i}@x.com" for i in range(10)]
        c = sim.create_campaign("C", template_id, targets, org_id)
        for u in targets[:2]:
            sim.record_click(c.id, u)
        result = sim.get_org_phishing_risk(org_id)
        assert result["risk_level"] == "medium"

    def test_org_risk_high_level(self, sim, org_id, template_id):
        """25% ≤ susceptibility_rate < 40% → risk_level 'high'."""
        targets = [f"u{i}@x.com" for i in range(4)]
        c = sim.create_campaign("C", template_id, targets, org_id)
        # 1 out of 4 = 25% → high
        sim.record_click(c.id, targets[0])
        result = sim.get_org_phishing_risk(org_id)
        assert result["risk_level"] == "high"
        assert result["susceptibility_rate_pct"] == 25.0

    def test_org_risk_critical_level_at_40_pct(self, sim, org_id, template_id):
        """susceptibility_rate ≥ 40% → risk_level 'critical'."""
        targets = [f"u{i}@x.com" for i in range(5)]
        c = sim.create_campaign("C", template_id, targets, org_id)
        # 2 out of 5 = 40% → critical
        sim.record_click(c.id, targets[0])
        sim.record_click(c.id, targets[1])
        result = sim.get_org_phishing_risk(org_id)
        assert result["susceptibility_rate_pct"] == 40.0
        assert result["risk_level"] == "critical"

    def test_different_orgs_isolated(self, sim, template_id):
        org_a = "org_a_" + uuid.uuid4().hex[:6]
        org_b = "org_b_" + uuid.uuid4().hex[:6]
        c = sim.create_campaign("C", template_id, ["x@x.com"], org_a)
        sim.record_click(c.id, "x@x.com")
        result_b = sim.get_org_phishing_risk(org_b)
        assert result_b["total_campaigns"] == 0

    def test_org_risk_zero_sent_no_division_error(self, sim, org_id, template_id):
        """Empty campaign (0 targets) does not cause division by zero."""
        sim.create_campaign("Empty", template_id, [], org_id)
        result = sim.get_org_phishing_risk(org_id)
        assert result["susceptibility_rate_pct"] == 0.0
        assert result["report_rate_pct"] == 0.0

    def test_org_risk_result_contains_all_keys(self, sim, org_id):
        result = sim.get_org_phishing_risk(org_id)
        expected_keys = {
            "org_id", "total_campaigns", "total_sent",
            "total_clicked", "total_reported",
            "susceptibility_rate_pct", "report_rate_pct", "risk_level",
        }
        assert expected_keys.issubset(result.keys())

    def test_org_risk_total_reported_tracked(self, sim, org_id, template_id):
        c = sim.create_campaign("C", template_id, ["a@x.com", "b@x.com"], org_id)
        sim.record_report(c.id, "a@x.com")
        sim.record_report(c.id, "b@x.com")
        result = sim.get_org_phishing_risk(org_id)
        assert result["total_reported"] == 2


# ============================================================================
# CAMPAIGN HISTORY
# ============================================================================


class TestCampaignHistory:
    def test_history_empty_for_new_org(self, sim, org_id):
        assert sim.get_campaign_history(org_id) == []

    def test_history_returns_campaigns_for_org(self, sim, org_id, template_id):
        sim.create_campaign("A", template_id, ["a@x.com"], org_id)
        sim.create_campaign("B", template_id, ["b@x.com"], org_id)
        history = sim.get_campaign_history(org_id)
        assert len(history) == 2

    def test_history_does_not_include_other_org(self, sim, template_id):
        org_a = "org_a"
        org_b = "org_b"
        sim.create_campaign("A", template_id, ["a@x.com"], org_a)
        history = sim.get_campaign_history(org_b)
        assert len(history) == 0

    def test_history_contains_expected_fields(self, sim, org_id, template_id):
        sim.create_campaign("Hist", template_id, ["a@x.com"], org_id)
        row = sim.get_campaign_history(org_id)[0]
        required = {"id", "name", "template_id", "sent_count", "org_id", "started_at"}
        assert required.issubset(row.keys())

    def test_history_ordered_newest_first(self, sim, org_id, template_id):
        """get_campaign_history returns campaigns ordered by started_at descending."""
        c1 = sim.create_campaign("First", template_id, ["a@x.com"], org_id)
        c2 = sim.create_campaign("Second", template_id, ["b@x.com"], org_id)
        history = sim.get_campaign_history(org_id)
        names = [h["name"] for h in history]
        # Newest (Second) should appear before First
        assert names.index("Second") < names.index("First")

    def test_history_row_target_emails_is_list(self, sim, org_id, template_id):
        """History rows deserialise target_emails to a Python list."""
        targets = ["a@x.com", "b@x.com"]
        sim.create_campaign("C", template_id, targets, org_id)
        row = sim.get_campaign_history(org_id)[0]
        assert isinstance(row["target_emails"], list)
        assert row["target_emails"] == targets

    def test_history_row_counts_reflect_interactions(self, sim, org_id, template_id):
        """Counts in history rows are updated after recording interactions."""
        c = sim.create_campaign("C", template_id, ["a@x.com"], org_id)
        sim.record_click(c.id, "a@x.com")
        row = sim.get_campaign_history(org_id)[0]
        assert row["clicked_count"] == 1

    def test_history_returns_all_campaigns_for_large_org(self, sim, org_id, template_id):
        """All campaigns created for an org appear in history."""
        n = 10
        for i in range(n):
            sim.create_campaign(f"C{i}", template_id, ["a@x.com"], org_id)
        history = sim.get_campaign_history(org_id)
        assert len(history) == n


# ============================================================================
# TEMPLATE MANAGEMENT
# ============================================================================


class TestTemplateManagement:
    def test_list_templates_returns_10_builtins(self, sim):
        templates = sim.list_templates()
        assert len(templates) >= 10

    def test_add_custom_template(self, sim):
        custom = PhishingTemplate(
            name="Custom Phish",
            subject="Custom Subject",
            body_html="<p>Custom body</p>",
            category=PhishingCategory.URGENCY,
            difficulty=PhishingDifficulty.HARD,
            indicators=["custom clue"],
        )
        result = sim.add_custom_template(custom)
        assert result.id == custom.id

    def test_custom_template_retrievable(self, sim):
        custom = PhishingTemplate(
            name="Retrievable",
            subject="Sub",
            body_html="<p/>",
            category=PhishingCategory.AUTHORITY,
            difficulty=PhishingDifficulty.MEDIUM,
            indicators=["clue"],
        )
        sim.add_custom_template(custom)
        retrieved = sim.get_template(custom.id)
        assert retrieved is not None
        assert retrieved.name == "Retrievable"

    def test_custom_template_in_list(self, sim):
        custom = PhishingTemplate(
            name="Listed",
            subject="Sub",
            body_html="<p/>",
            category=PhishingCategory.DATA_REQUEST,
            difficulty=PhishingDifficulty.EASY,
            indicators=["x"],
        )
        sim.add_custom_template(custom)
        ids = [t.id for t in sim.list_templates()]
        assert custom.id in ids

    def test_can_use_custom_template_in_campaign(self, sim, org_id):
        custom = PhishingTemplate(
            name="Campaign Custom",
            subject="S",
            body_html="<p/>",
            category=PhishingCategory.MALWARE_LINK,
            difficulty=PhishingDifficulty.MEDIUM,
            indicators=["x"],
        )
        sim.add_custom_template(custom)
        c = sim.create_campaign("C", custom.id, ["a@x.com"], org_id)
        assert c.template_id == custom.id

    def test_add_duplicate_custom_template_replaces(self, sim):
        """Adding a custom template with the same ID updates it (INSERT OR REPLACE)."""
        custom_id = "dup_test_" + uuid.uuid4().hex[:6]
        t1 = PhishingTemplate(
            id=custom_id,
            name="Original",
            subject="Sub",
            body_html="<p>v1</p>",
            category=PhishingCategory.URGENCY,
            difficulty=PhishingDifficulty.EASY,
        )
        t2 = PhishingTemplate(
            id=custom_id,
            name="Updated",
            subject="Sub",
            body_html="<p>v2</p>",
            category=PhishingCategory.URGENCY,
            difficulty=PhishingDifficulty.HARD,
        )
        sim.add_custom_template(t1)
        sim.add_custom_template(t2)
        retrieved = sim.get_template(custom_id)
        assert retrieved.name == "Updated"

    def test_multiple_custom_templates_all_appear_in_list(self, sim):
        added_ids = set()
        for i in range(3):
            t = PhishingTemplate(
                name=f"Custom {i}",
                subject="Sub",
                body_html="<p/>",
                category=PhishingCategory.DATA_REQUEST,
                difficulty=PhishingDifficulty.MEDIUM,
            )
            sim.add_custom_template(t)
            added_ids.add(t.id)
        all_ids = {t.id for t in sim.list_templates()}
        assert added_ids.issubset(all_ids)

    def test_list_templates_count_grows_with_custom_additions(self, sim):
        base_count = len(sim.list_templates())
        for i in range(3):
            t = PhishingTemplate(
                name=f"Custom {i}",
                subject="Sub",
                body_html="<p/>",
                category=PhishingCategory.AUTHORITY,
                difficulty=PhishingDifficulty.EASY,
            )
            sim.add_custom_template(t)
        assert len(sim.list_templates()) == base_count + 3

    def test_custom_template_fields_round_trip(self, sim):
        """All fields survive serialisation to DB and back."""
        t = PhishingTemplate(
            name="Round Trip",
            subject="Subj RT",
            body_html="<p>HTML content</p>",
            category=PhishingCategory.MALWARE_LINK,
            difficulty=PhishingDifficulty.HARD,
            indicators=["ind1", "ind2", "ind3"],
        )
        sim.add_custom_template(t)
        r = sim.get_template(t.id)
        assert r.name == t.name
        assert r.subject == t.subject
        assert r.body_html == t.body_html
        assert r.category == t.category
        assert r.difficulty == t.difficulty
        assert r.indicators == t.indicators


# ============================================================================
# SINGLETON LIFECYCLE
# ============================================================================


class TestSingletonLifecycle:
    def test_get_instance_returns_instance(self, tmp_path, monkeypatch):
        """get_instance() returns a PhishingSimulator."""
        import core.phishing_simulator as ps_mod
        original = ps_mod.PhishingSimulator._instance
        try:
            ps_mod.PhishingSimulator._instance = None
            instance = ps_mod.PhishingSimulator.get_instance()
            assert isinstance(instance, ps_mod.PhishingSimulator)
        finally:
            ps_mod.PhishingSimulator._instance = original

    def test_get_instance_returns_same_object_on_repeated_calls(self):
        """Repeated calls to get_instance() return the same object."""
        import core.phishing_simulator as ps_mod
        i1 = ps_mod.PhishingSimulator.get_instance()
        i2 = ps_mod.PhishingSimulator.get_instance()
        assert i1 is i2

    def test_fresh_simulator_per_tmp_path(self, tmp_path):
        """Two simulators backed by different DB paths are independent."""
        db1 = str(tmp_path / "db1.db")
        db2 = str(tmp_path / "db2.db")
        s1 = PhishingSimulator(db_path=db1)
        s2 = PhishingSimulator(db_path=db2)
        org = "org_iso"
        s1.create_campaign("C", BUILTIN_TEMPLATES[0].id, ["a@x.com"], org)
        assert s2.get_campaign_history(org) == []


# ============================================================================
# THREAD SAFETY
# ============================================================================


class TestThreadSafety:
    def test_concurrent_record_click_no_race(self, sim, org_id, template_id):
        """Concurrent record_click calls from multiple threads do not corrupt state."""
        targets = [f"u{i}@corp.com" for i in range(10)]
        c = sim.create_campaign("Concurrent", template_id, targets, org_id)

        errors: List[Exception] = []

        def click(email: str) -> None:
            try:
                sim.record_click(c.id, email)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=click, args=(t,)) for t in targets]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert errors == [], f"Thread errors: {errors}"
        results = sim.get_campaign_results(c.id)
        assert results["clicked_count"] == 10

    def test_concurrent_create_campaigns_no_conflict(self, sim, org_id, template_id):
        """Simultaneous campaign creation from multiple threads all succeed."""
        errors: List[Exception] = []
        campaigns: List = []
        lock = threading.Lock()

        def create(i: int) -> None:
            try:
                camp = sim.create_campaign(
                    f"Thread-{i}", template_id, [f"u{i}@x.com"], org_id
                )
                with lock:
                    campaigns.append(camp)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=create, args=(i,)) for i in range(8)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert errors == [], f"Thread errors: {errors}"
        assert len(campaigns) == 8
        history = sim.get_campaign_history(org_id)
        assert len(history) == 8


# ============================================================================
# EXECUTIVE REPORTING — RISK METRICS
# ============================================================================


class TestExecutiveReporting:
    def test_overall_click_rate_tracks_across_campaigns(self, sim, org_id, template_id):
        """Org-level susceptibility rate aggregates all campaign clicks correctly."""
        c1 = sim.create_campaign("Q1", template_id, ["a@x.com", "b@x.com", "c@x.com", "d@x.com"], org_id)
        c2 = sim.create_campaign("Q2", template_id, ["e@x.com", "f@x.com", "g@x.com", "h@x.com"], org_id)
        # 2 clicks out of 8 total = 25% → high
        sim.record_click(c1.id, "a@x.com")
        sim.record_click(c2.id, "e@x.com")
        result = sim.get_org_phishing_risk(org_id)
        assert result["total_sent"] == 8
        assert result["total_clicked"] == 2
        assert result["susceptibility_rate_pct"] == 25.0
        assert result["risk_level"] == "high"

    def test_report_rate_vs_click_rate_are_independent(self, sim, org_id, template_id):
        """report_rate_pct and susceptibility_rate_pct can differ independently."""
        targets = [f"u{i}@x.com" for i in range(4)]
        c = sim.create_campaign("C", template_id, targets, org_id)
        sim.record_click(c.id, targets[0])   # 1 click
        sim.record_report(c.id, targets[1])  # 1 report
        sim.record_report(c.id, targets[2])  # 2 reports
        result = sim.get_org_phishing_risk(org_id)
        assert result["susceptibility_rate_pct"] == 25.0
        assert result["report_rate_pct"] == 50.0

    def test_zero_click_low_report_rate_is_low_risk(self, sim, org_id, template_id):
        """No clicks at all → risk_level 'low' regardless of report rate."""
        targets = [f"u{i}@x.com" for i in range(5)]
        c = sim.create_campaign("C", template_id, targets, org_id)
        for email in targets:
            sim.record_report(c.id, email)
        result = sim.get_org_phishing_risk(org_id)
        assert result["risk_level"] == "low"
        assert result["report_rate_pct"] == 100.0

    def test_campaign_summary_click_rate_rounded(self, sim, org_id, template_id):
        """click_rate_pct in campaign results is rounded to one decimal."""
        targets = [f"u{i}@x.com" for i in range(3)]
        c = sim.create_campaign("C", template_id, targets, org_id)
        sim.record_click(c.id, targets[0])
        results = sim.get_campaign_results(c.id)
        # 1/3 ≈ 33.3
        assert results["click_rate_pct"] == 33.3

    def test_high_click_rate_triggers_critical_org_risk(self, sim, org_id, template_id):
        """org risk is 'critical' when susceptibility_rate ≥ 40%."""
        targets = [f"u{i}@x.com" for i in range(10)]
        c = sim.create_campaign("C", template_id, targets, org_id)
        for email in targets[:5]:  # 50% click rate
            sim.record_click(c.id, email)
        result = sim.get_org_phishing_risk(org_id)
        assert result["risk_level"] == "critical"

    def test_per_user_report_in_campaign_results(self, sim, campaign):
        """per_user dict shows correct event types per user."""
        sim.record_report(campaign.id, "alice@corp.com")
        results = sim.get_campaign_results(campaign.id)
        assert "report" in results["per_user"]["alice@corp.com"]
        assert "click" not in results["per_user"]["alice@corp.com"]

    def test_campaign_results_counts_match_per_user_events(self, sim, campaign):
        """Top-level counts are consistent with per_user event breakdown."""
        sim.record_click(campaign.id, "alice@corp.com")
        sim.record_report(campaign.id, "bob@corp.com")
        results = sim.get_campaign_results(campaign.id)
        all_clicks = sum(1 for events in results["per_user"].values() if "click" in events)
        all_reports = sum(1 for events in results["per_user"].values() if "report" in events)
        assert results["clicked_count"] == all_clicks
        assert results["reported_count"] == all_reports


# ============================================================================
# ROUTER TESTS
# ============================================================================


@pytest.fixture()
def client(tmp_path):
    """TestClient with phishing_router mounted, using temp DB."""
    from fastapi import FastAPI
    from apps.api.phishing_router import router

    app = FastAPI()
    app.include_router(router)

    # Patch the singleton to use a temp path
    import core.phishing_simulator as ps_mod
    ps_mod.PhishingSimulator._instance = ps_mod.PhishingSimulator(
        db_path=str(tmp_path / "router_test.db")
    )

    yield TestClient(app)

    # Reset singleton after test
    ps_mod.PhishingSimulator._instance = None


@pytest.fixture()
def router_org():
    return "router_org_" + uuid.uuid4().hex[:6]


@pytest.fixture()
def router_campaign_id(client, router_org):
    """Create a campaign via the API and return its ID."""
    resp = client.post(
        "/api/v1/phishing/campaigns",
        json={
            "name": "Router Campaign",
            "template_id": BUILTIN_TEMPLATES[0].id,
            "target_emails": ["a@corp.com", "b@corp.com"],
            "org_id": router_org,
        },
    )
    assert resp.status_code == 201
    return resp.json()["id"]


class TestPhishingRouter:
    def test_create_campaign_201(self, client, router_org):
        resp = client.post(
            "/api/v1/phishing/campaigns",
            json={
                "name": "My Campaign",
                "template_id": BUILTIN_TEMPLATES[0].id,
                "target_emails": ["x@x.com"],
                "org_id": router_org,
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "My Campaign"
        assert data["sent_count"] == 1

    def test_create_campaign_bad_template_404(self, client, router_org):
        resp = client.post(
            "/api/v1/phishing/campaigns",
            json={
                "name": "Bad",
                "template_id": "nonexistent",
                "target_emails": ["x@x.com"],
                "org_id": router_org,
            },
        )
        assert resp.status_code == 404

    def test_get_campaign_results_200(self, client, router_campaign_id):
        resp = client.get(f"/api/v1/phishing/campaigns/{router_campaign_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert "click_rate_pct" in data
        assert "report_rate_pct" in data

    def test_get_campaign_results_404(self, client):
        resp = client.get("/api/v1/phishing/campaigns/no_such_id")
        assert resp.status_code == 404

    def test_record_open_204(self, client, router_campaign_id):
        resp = client.post(
            f"/api/v1/phishing/campaigns/{router_campaign_id}/open",
            json={"email": "a@corp.com"},
        )
        assert resp.status_code == 204

    def test_record_click_204(self, client, router_campaign_id):
        resp = client.post(
            f"/api/v1/phishing/campaigns/{router_campaign_id}/click",
            json={"email": "a@corp.com"},
        )
        assert resp.status_code == 204

    def test_record_report_204(self, client, router_campaign_id):
        resp = client.post(
            f"/api/v1/phishing/campaigns/{router_campaign_id}/report",
            json={"email": "b@corp.com"},
        )
        assert resp.status_code == 204

    def test_record_click_invalid_campaign_404(self, client):
        resp = client.post(
            "/api/v1/phishing/campaigns/bad_id/click",
            json={"email": "x@x.com"},
        )
        assert resp.status_code == 404

    def test_record_open_invalid_campaign_404(self, client):
        resp = client.post(
            "/api/v1/phishing/campaigns/bad_id/open",
            json={"email": "x@x.com"},
        )
        assert resp.status_code == 404

    def test_record_report_invalid_campaign_404(self, client):
        resp = client.post(
            "/api/v1/phishing/campaigns/bad_id/report",
            json={"email": "x@x.com"},
        )
        assert resp.status_code == 404

    def test_get_org_history_200(self, client, router_campaign_id, router_org):
        resp = client.get(f"/api/v1/phishing/orgs/{router_org}/history")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)
        assert len(resp.json()) >= 1

    def test_get_org_history_empty_org_returns_empty_list(self, client):
        resp = client.get("/api/v1/phishing/orgs/org_nonexistent_xyz/history")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_get_org_risk_200(self, client, router_org):
        resp = client.get(f"/api/v1/phishing/orgs/{router_org}/risk")
        assert resp.status_code == 200
        data = resp.json()
        assert "susceptibility_rate_pct" in data
        assert "risk_level" in data

    def test_get_org_risk_unknown_org_returns_zeros(self, client):
        resp = client.get("/api/v1/phishing/orgs/org_totally_new/risk")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_campaigns"] == 0
        assert data["susceptibility_rate_pct"] == 0.0

    def test_user_susceptibility_200(self, client, router_campaign_id, router_org):
        # Record a click first
        client.post(
            f"/api/v1/phishing/campaigns/{router_campaign_id}/click",
            json={"email": "a@corp.com"},
        )
        resp = client.get(
            "/api/v1/phishing/users/susceptibility",
            params={"email": "a@corp.com", "org_id": router_org},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["susceptibility_score"] == 1.0
        assert data["risk_level"] == "critical"

    def test_user_susceptibility_unknown_user_returns_unknown_risk(self, client, router_org):
        """User with no campaign activity returns risk_level 'unknown'."""
        resp = client.get(
            "/api/v1/phishing/users/susceptibility",
            params={"email": "nobody@corp.com", "org_id": router_org},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] == "unknown"
        assert data["susceptibility_score"] == 0.0

    def test_list_templates_200(self, client):
        resp = client.get("/api/v1/phishing/templates")
        assert resp.status_code == 200
        templates = resp.json()
        assert len(templates) >= 10
        assert "id" in templates[0]
        assert "category" in templates[0]
        assert "indicators" in templates[0]

    def test_list_templates_includes_all_required_fields(self, client):
        """Each template in the list response has id, name, subject, body_html, category, difficulty, indicators."""
        resp = client.get("/api/v1/phishing/templates")
        assert resp.status_code == 200
        for tpl in resp.json():
            assert "id" in tpl
            assert "name" in tpl
            assert "subject" in tpl
            assert "body_html" in tpl
            assert "category" in tpl
            assert "difficulty" in tpl
            assert "indicators" in tpl

    def test_add_template_201(self, client):
        resp = client.post(
            "/api/v1/phishing/templates",
            json={
                "name": "My Custom Template",
                "subject": "Click here!",
                "body_html": "<p>Phish</p>",
                "category": "urgency",
                "difficulty": "hard",
                "indicators": ["fake urgency", "bad domain"],
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "My Custom Template"
        assert data["category"] == "urgency"

    def test_add_template_invalid_category_422(self, client):
        resp = client.post(
            "/api/v1/phishing/templates",
            json={
                "name": "Bad",
                "subject": "S",
                "body_html": "<p/>",
                "category": "not_a_category",
                "difficulty": "easy",
            },
        )
        assert resp.status_code == 422

    def test_add_template_invalid_difficulty_422(self, client):
        resp = client.post(
            "/api/v1/phishing/templates",
            json={
                "name": "Bad Difficulty",
                "subject": "S",
                "body_html": "<p/>",
                "category": "urgency",
                "difficulty": "extreme",
            },
        )
        assert resp.status_code == 422

    def test_click_count_reflected_in_results(self, client, router_campaign_id):
        client.post(
            f"/api/v1/phishing/campaigns/{router_campaign_id}/click",
            json={"email": "a@corp.com"},
        )
        resp = client.get(f"/api/v1/phishing/campaigns/{router_campaign_id}")
        assert resp.json()["clicked_count"] == 1

    def test_report_count_reflected_in_results(self, client, router_campaign_id):
        client.post(
            f"/api/v1/phishing/campaigns/{router_campaign_id}/report",
            json={"email": "b@corp.com"},
        )
        resp = client.get(f"/api/v1/phishing/campaigns/{router_campaign_id}")
        assert resp.json()["reported_count"] == 1

    def test_open_count_reflected_in_results(self, client, router_campaign_id):
        client.post(
            f"/api/v1/phishing/campaigns/{router_campaign_id}/open",
            json={"email": "a@corp.com"},
        )
        resp = client.get(f"/api/v1/phishing/campaigns/{router_campaign_id}")
        assert resp.json()["opened_count"] == 1

    def test_create_campaign_response_has_all_fields(self, client, router_org):
        resp = client.post(
            "/api/v1/phishing/campaigns",
            json={
                "name": "Full Fields Test",
                "template_id": BUILTIN_TEMPLATES[0].id,
                "target_emails": ["x@x.com", "y@x.com"],
                "org_id": router_org,
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        expected_fields = {
            "id", "name", "template_id", "target_emails",
            "sent_count", "opened_count", "clicked_count", "reported_count",
            "started_at", "ended_at", "org_id",
        }
        assert expected_fields.issubset(data.keys())

    def test_add_custom_template_then_list_includes_it(self, client):
        """Custom template added via POST /templates appears in GET /templates."""
        add_resp = client.post(
            "/api/v1/phishing/templates",
            json={
                "name": "Listed Custom",
                "subject": "Sub",
                "body_html": "<p>body</p>",
                "category": "authority",
                "difficulty": "medium",
                "indicators": [],
            },
        )
        assert add_resp.status_code == 201
        added_id = add_resp.json()["id"]

        list_resp = client.get("/api/v1/phishing/templates")
        listed_ids = [t["id"] for t in list_resp.json()]
        assert added_id in listed_ids

    def test_create_campaign_with_zero_targets_returns_zero_sent(self, client, router_org):
        resp = client.post(
            "/api/v1/phishing/campaigns",
            json={
                "name": "Empty Campaign",
                "template_id": BUILTIN_TEMPLATES[0].id,
                "target_emails": [],
                "org_id": router_org,
            },
        )
        assert resp.status_code == 201
        assert resp.json()["sent_count"] == 0

    def test_org_risk_after_multiple_campaigns(self, client, router_org):
        """Org risk endpoint aggregates across all campaigns for that org."""
        for i in range(3):
            r = client.post(
                "/api/v1/phishing/campaigns",
                json={
                    "name": f"Camp {i}",
                    "template_id": BUILTIN_TEMPLATES[0].id,
                    "target_emails": ["u@x.com"],
                    "org_id": router_org,
                },
            )
            cid = r.json()["id"]
            client.post(
                f"/api/v1/phishing/campaigns/{cid}/click",
                json={"email": "u@x.com"},
            )
        resp = client.get(f"/api/v1/phishing/orgs/{router_org}/risk")
        data = resp.json()
        assert data["total_campaigns"] == 3
        assert data["total_clicked"] == 3
