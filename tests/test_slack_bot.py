"""Tests for Slack Security Bot.

Covers:
- All slash commands produce valid BlockKit responses
- Status command includes posture score
- Findings command includes severity filtering
- SLA command shows breached items
- Triage command shows action buttons
- Interaction handler processes ack/escalate/dismiss/comment
- Help command lists all commands
- Severity emoji mapping
- Router endpoint smoke tests
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.slack_bot import InteractionAction, SlashCommand, SlackBot


# ============================================================================
# Fixtures
# ============================================================================


def _make_posture(score: float = 78.5, grade: str = "C") -> MagicMock:
    comp = MagicMock()
    comp.name = "vulnerability_density"
    comp.score = score
    comp.weight = 0.25

    posture = MagicMock()
    posture.overall_score = score
    posture.grade = grade
    posture.components = [comp]
    return posture


def _make_sla_record(finding_id: str, severity: str = "critical") -> MagicMock:
    record = MagicMock()
    record.finding_id = finding_id
    record.severity = severity
    return record


@pytest.fixture
def mock_posture_scorer():
    scorer = MagicMock()
    scorer.calculate_score.return_value = _make_posture(78.5, "C")
    return scorer


@pytest.fixture
def mock_sla_manager():
    manager = MagicMock()
    manager.get_breached.return_value = [
        _make_sla_record("FIND-001", "critical"),
        _make_sla_record("FIND-002", "high"),
    ]
    manager.get_at_risk.return_value = [
        _make_sla_record("FIND-003", "high"),
    ]
    return manager


@pytest.fixture
def bot(mock_posture_scorer, mock_sla_manager):
    return SlackBot(
        posture_scorer=mock_posture_scorer,
        sla_manager=mock_sla_manager,
        signing_secret=None,
        org_id="test-org",
    )


# ============================================================================
# Enums
# ============================================================================


def test_slash_command_enum_values():
    assert SlashCommand.STATUS == "/status"
    assert SlashCommand.FINDINGS == "/findings"
    assert SlashCommand.SLA == "/sla"
    assert SlashCommand.HELP == "/help"
    assert SlashCommand.TRIAGE == "/triage"
    assert SlashCommand.SCORE == "/score"


def test_interaction_action_enum_values():
    assert InteractionAction.ACKNOWLEDGE == "acknowledge"
    assert InteractionAction.ESCALATE == "escalate"
    assert InteractionAction.DISMISS == "dismiss"
    assert InteractionAction.COMMENT == "comment"


# ============================================================================
# SlackBot instantiation
# ============================================================================


def test_bot_instantiates():
    b = SlackBot()
    assert b is not None
    assert b._signing_secret is None
    assert b._org_id == "default"


def test_bot_instantiates_with_secret():
    b = SlackBot(signing_secret="secret123")
    assert b._signing_secret == "secret123"


# ============================================================================
# Severity emoji
# ============================================================================


def test_format_severity_emoji_critical(bot):
    assert bot.format_severity_emoji("critical") == ":red_circle:"


def test_format_severity_emoji_high(bot):
    assert bot.format_severity_emoji("high") == ":large_orange_circle:"


def test_format_severity_emoji_medium(bot):
    assert bot.format_severity_emoji("medium") == ":large_yellow_circle:"


def test_format_severity_emoji_low(bot):
    assert bot.format_severity_emoji("low") == ":large_blue_circle:"


def test_format_severity_emoji_info(bot):
    assert bot.format_severity_emoji("info") == ":white_circle:"


def test_format_severity_emoji_unknown(bot):
    assert bot.format_severity_emoji("unknown_sev") == ":white_circle:"


def test_format_severity_emoji_case_insensitive(bot):
    assert bot.format_severity_emoji("CRITICAL") == ":red_circle:"
    assert bot.format_severity_emoji("HIGH") == ":large_orange_circle:"


# ============================================================================
# handle_status
# ============================================================================


def test_handle_status_returns_dict(bot):
    result = bot.handle_status()
    assert isinstance(result, dict)


def test_handle_status_response_type(bot):
    result = bot.handle_status()
    assert result["response_type"] == "in_channel"


def test_handle_status_has_blocks(bot):
    result = bot.handle_status()
    assert "blocks" in result
    assert len(result["blocks"]) > 0


def test_handle_status_contains_score(bot, mock_posture_scorer):
    mock_posture_scorer.calculate_score.return_value = _make_posture(78.5, "C")
    result = bot.handle_status()
    # Flatten all text in blocks
    all_text = json.dumps(result["blocks"])
    assert "78.5" in all_text


def test_handle_status_contains_grade(bot, mock_posture_scorer):
    mock_posture_scorer.calculate_score.return_value = _make_posture(92.0, "A")
    result = bot.handle_status()
    all_text = json.dumps(result["blocks"])
    assert "A" in all_text


def test_handle_status_has_header_block(bot):
    result = bot.handle_status()
    header_blocks = [b for b in result["blocks"] if b.get("type") == "header"]
    assert len(header_blocks) >= 1


def test_handle_status_fallback_on_scorer_error():
    bad_scorer = MagicMock()
    bad_scorer.calculate_score.side_effect = RuntimeError("DB unavailable")
    b = SlackBot(posture_scorer=bad_scorer, org_id="test")
    result = b.handle_status()
    assert "blocks" in result
    assert len(result["blocks"]) > 0


# ============================================================================
# handle_findings
# ============================================================================


def test_handle_findings_returns_dict(bot):
    result = bot.handle_findings()
    assert isinstance(result, dict)


def test_handle_findings_has_blocks(bot):
    result = bot.handle_findings()
    assert "blocks" in result
    assert len(result["blocks"]) > 0


def test_handle_findings_severity_filter_critical(bot):
    result = bot.handle_findings(filters={"severity": "critical"})
    all_text = json.dumps(result["blocks"])
    assert "critical" in all_text.lower()


def test_handle_findings_severity_filter_no_results(bot):
    result = bot.handle_findings(filters={"severity": "nonexistent_severity"})
    all_text = json.dumps(result["blocks"])
    # Should return empty-state message
    assert "No findings" in all_text or result["response_type"] == "ephemeral"


def test_handle_findings_limit(bot):
    result = bot.handle_findings(filters={"limit": "2"})
    # Count finding blocks (sections that are not header/divider)
    sections = [b for b in result["blocks"] if b.get("type") == "section"]
    assert len(sections) <= 2


def test_handle_findings_includes_severity_emoji(bot):
    result = bot.handle_findings(filters={"severity": "critical"})
    all_text = json.dumps(result["blocks"])
    assert ":red_circle:" in all_text


# ============================================================================
# handle_sla
# ============================================================================


def test_handle_sla_returns_dict(bot):
    result = bot.handle_sla()
    assert isinstance(result, dict)


def test_handle_sla_has_blocks(bot):
    result = bot.handle_sla()
    assert "blocks" in result
    assert len(result["blocks"]) > 0


def test_handle_sla_shows_breached_count(bot):
    result = bot.handle_sla()
    all_text = json.dumps(result["blocks"])
    assert "2" in all_text  # 2 breached records


def test_handle_sla_shows_breached_finding_ids(bot):
    result = bot.handle_sla()
    all_text = json.dumps(result["blocks"])
    assert "FIND-001" in all_text


def test_handle_sla_shows_at_risk(bot):
    result = bot.handle_sla()
    all_text = json.dumps(result["blocks"])
    assert "FIND-003" in all_text


def test_handle_sla_fallback_on_manager_error():
    bad_manager = MagicMock()
    bad_manager.get_breached.side_effect = RuntimeError("DB error")
    bad_manager.get_at_risk.side_effect = RuntimeError("DB error")
    b = SlackBot(sla_manager=bad_manager, org_id="test")
    result = b.handle_sla()
    assert "blocks" in result


# ============================================================================
# handle_triage
# ============================================================================


def test_handle_triage_returns_dict(bot):
    result = bot.handle_triage("FIND-001")
    assert isinstance(result, dict)


def test_handle_triage_has_action_buttons(bot):
    result = bot.handle_triage("FIND-001")
    action_blocks = [b for b in result["blocks"] if b.get("type") == "actions"]
    assert len(action_blocks) == 1


def test_handle_triage_action_buttons_have_correct_actions(bot):
    result = bot.handle_triage("FIND-001")
    action_blocks = [b for b in result["blocks"] if b.get("type") == "actions"]
    elements = action_blocks[0]["elements"]
    action_ids = {e["action_id"] for e in elements}
    assert InteractionAction.ACKNOWLEDGE in action_ids
    assert InteractionAction.ESCALATE in action_ids
    assert InteractionAction.DISMISS in action_ids


def test_handle_triage_buttons_carry_finding_id(bot):
    result = bot.handle_triage("FIND-XYZ")
    action_blocks = [b for b in result["blocks"] if b.get("type") == "actions"]
    values = [e["value"] for e in action_blocks[0]["elements"]]
    assert all(v == "FIND-XYZ" for v in values)


def test_handle_triage_no_id_returns_error(bot):
    result = bot.handle_triage("")
    assert result["response_type"] == "ephemeral"
    all_text = json.dumps(result["blocks"])
    assert "finding ID" in all_text or "finding_id" in all_text.lower()


# ============================================================================
# handle_score
# ============================================================================


def test_handle_score_returns_dict(bot):
    result = bot.handle_score("my-repo")
    assert isinstance(result, dict)


def test_handle_score_has_blocks(bot):
    result = bot.handle_score("my-repo")
    assert "blocks" in result
    assert len(result["blocks"]) > 0


def test_handle_score_contains_repo_name(bot):
    result = bot.handle_score("cool-repo")
    all_text = json.dumps(result["blocks"])
    assert "cool-repo" in all_text


def test_handle_score_no_repo_returns_error(bot):
    result = bot.handle_score("")
    assert result["response_type"] == "ephemeral"


def test_handle_score_contains_grade(bot):
    result = bot.handle_score("my-repo")
    all_text = json.dumps(result["blocks"])
    # Should contain a letter grade
    assert any(g in all_text for g in ["A", "B", "C", "D", "F"])


# ============================================================================
# handle_help
# ============================================================================


def test_handle_help_returns_dict(bot):
    result = bot.handle_help()
    assert isinstance(result, dict)


def test_handle_help_lists_all_commands(bot):
    result = bot.handle_help()
    all_text = json.dumps(result["blocks"])
    for cmd in SlashCommand:
        assert cmd.value in all_text


def test_handle_help_response_type_ephemeral(bot):
    result = bot.handle_help()
    assert result["response_type"] == "ephemeral"


def test_handle_help_has_blocks(bot):
    result = bot.handle_help()
    assert "blocks" in result
    assert len(result["blocks"]) > 0


# ============================================================================
# handle_slash_command router
# ============================================================================


def test_slash_command_routes_status(bot):
    result = bot.handle_slash_command("/status", "", "U123", "C456")
    assert "blocks" in result


def test_slash_command_routes_findings(bot):
    result = bot.handle_slash_command("/findings", "", "U123", "C456")
    assert "blocks" in result


def test_slash_command_routes_sla(bot):
    result = bot.handle_slash_command("/sla", "", "U123", "C456")
    assert "blocks" in result


def test_slash_command_routes_help(bot):
    result = bot.handle_slash_command("/help", "", "U123", "C456")
    assert "blocks" in result


def test_slash_command_routes_triage(bot):
    result = bot.handle_slash_command("/triage", "FIND-001", "U123", "C456")
    assert "blocks" in result


def test_slash_command_routes_score(bot):
    result = bot.handle_slash_command("/score", "my-repo", "U123", "C456")
    assert "blocks" in result


def test_slash_command_unknown_returns_error(bot):
    result = bot.handle_slash_command("/unknown", "", "U123", "C456")
    assert result["response_type"] == "ephemeral"
    all_text = json.dumps(result["blocks"])
    assert "Unknown command" in all_text or "help" in all_text.lower()


# ============================================================================
# handle_interaction
# ============================================================================


def test_handle_interaction_acknowledge(bot):
    payload = {
        "actions": [{"action_id": "acknowledge", "value": "FIND-001"}],
        "user": {"id": "U123"},
    }
    result = bot.handle_interaction(payload)
    assert result["ok"] is True
    assert result["action"] == InteractionAction.ACKNOWLEDGE
    assert result["finding_id"] == "FIND-001"


def test_handle_interaction_escalate(bot):
    payload = {
        "actions": [{"action_id": "escalate", "value": "FIND-002"}],
        "user": {"id": "U456"},
    }
    result = bot.handle_interaction(payload)
    assert result["ok"] is True
    assert result["action"] == InteractionAction.ESCALATE
    assert result["finding_id"] == "FIND-002"


def test_handle_interaction_dismiss(bot):
    payload = {
        "actions": [{"action_id": "dismiss", "value": "FIND-003"}],
        "user": {"id": "U789"},
    }
    result = bot.handle_interaction(payload)
    assert result["ok"] is True
    assert result["action"] == InteractionAction.DISMISS


def test_handle_interaction_comment(bot):
    payload = {
        "actions": [{"action_id": "comment", "value": "FIND-004"}],
        "user": {"id": "U999"},
    }
    result = bot.handle_interaction(payload)
    assert result["ok"] is True
    assert result["action"] == InteractionAction.COMMENT


def test_handle_interaction_no_actions(bot):
    payload = {"actions": [], "user": {"id": "U123"}}
    result = bot.handle_interaction(payload)
    assert result["ok"] is True


def test_handle_interaction_unknown_action(bot):
    payload = {
        "actions": [{"action_id": "unknown_action", "value": "FIND-001"}],
        "user": {"id": "U123"},
    }
    result = bot.handle_interaction(payload)
    assert result["ok"] is True


def test_handle_interaction_carries_user_id(bot):
    payload = {
        "actions": [{"action_id": "acknowledge", "value": "FIND-001"}],
        "user": {"id": "USPECIFIC"},
    }
    result = bot.handle_interaction(payload)
    assert result["user_id"] == "USPECIFIC"


# ============================================================================
# Build helpers
# ============================================================================


def test_build_finding_block_structure(bot):
    finding = {
        "id": "TEST-001",
        "title": "Test Finding",
        "severity": "critical",
        "source": "SAST",
        "description": "Test description.",
    }
    block = bot._build_finding_block(finding)
    assert block["type"] == "section"
    assert "TEST-001" in block["text"]["text"]
    assert ":red_circle:" in block["text"]["text"]


def test_build_action_buttons_structure(bot):
    block = bot._build_action_buttons("FIND-XYZ")
    assert block["type"] == "actions"
    assert len(block["elements"]) >= 3
    action_ids = {e["action_id"] for e in block["elements"]}
    assert "acknowledge" in action_ids
    assert "escalate" in action_ids
    assert "dismiss" in action_ids


def test_build_status_blocks_structure(bot):
    posture = _make_posture(85.0, "B")
    blocks = bot._build_status_blocks(posture)
    assert isinstance(blocks, list)
    assert len(blocks) > 0
    all_text = json.dumps(blocks)
    assert "85.0" in all_text


def test_verify_signature_no_secret(bot):
    assert bot.verify_signature("12345", "body", "v0=abc") is True


def test_verify_signature_with_secret():
    import hashlib
    import hmac as hmac_mod

    secret = "test_signing_secret"
    timestamp = "1234567890"
    body = "command=%2Fstatus&text=&user_id=U123"
    base = f"v0:{timestamp}:{body}"
    mac = hmac_mod.new(secret.encode(), base.encode(), hashlib.sha256).hexdigest()
    sig = f"v0={mac}"

    b = SlackBot(signing_secret=secret)
    assert b.verify_signature(timestamp, body, sig) is True


def test_verify_signature_bad_secret():
    b = SlackBot(signing_secret="correct_secret")
    assert b.verify_signature("ts", "body", "v0=badsig") is False
