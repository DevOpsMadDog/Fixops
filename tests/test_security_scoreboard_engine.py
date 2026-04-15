"""Tests for SecurityScoreboardEngine — 30+ tests covering all methods."""

from __future__ import annotations

import pytest

from core.security_scoreboard_engine import SecurityScoreboardEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_security_scoreboard.db")


@pytest.fixture
def engine(db_path):
    return SecurityScoreboardEngine(db_path=db_path)


ORG = "org-sb-test"
ORG2 = "org-sb-other"


# ---------------------------------------------------------------------------
# create_team
# ---------------------------------------------------------------------------

def test_create_team_minimal(engine):
    t = engine.create_team(ORG, {"name": "Blue Team Alpha"})
    assert t["name"] == "Blue Team Alpha"
    assert t["team_type"] == "blue"
    assert t["score"] == 0
    assert t["wins"] == 0
    assert t["losses"] == 0
    assert t["status"] == "active"
    assert "id" in t
    assert "created_at" in t


def test_create_team_all_fields(engine):
    t = engine.create_team(ORG, {
        "name": "Red Team Omega",
        "team_type": "red",
        "department": "Security Operations",
    })
    assert t["team_type"] == "red"
    assert t["department"] == "Security Operations"


def test_create_team_missing_name(engine):
    with pytest.raises(ValueError, match="name is required"):
        engine.create_team(ORG, {"team_type": "blue"})


def test_create_team_invalid_type(engine):
    with pytest.raises(ValueError, match="Invalid team_type"):
        engine.create_team(ORG, {"name": "X", "team_type": "yellow"})


def test_create_team_all_valid_types(engine):
    valid_types = ["blue", "red", "purple", "devsecops", "compliance"]
    for t in valid_types:
        team = engine.create_team(ORG, {"name": f"Team {t}", "team_type": t})
        assert team["team_type"] == t


def test_create_team_unique_ids(engine):
    t1 = engine.create_team(ORG, {"name": "T1"})
    t2 = engine.create_team(ORG, {"name": "T2"})
    assert t1["id"] != t2["id"]


# ---------------------------------------------------------------------------
# list_teams / get_team
# ---------------------------------------------------------------------------

def test_list_teams_empty(engine):
    assert engine.list_teams(ORG) == []


def test_list_teams_returns_all(engine):
    engine.create_team(ORG, {"name": "A"})
    engine.create_team(ORG, {"name": "B"})
    assert len(engine.list_teams(ORG)) == 2


def test_list_teams_filter_type(engine):
    engine.create_team(ORG, {"name": "Blue1", "team_type": "blue"})
    engine.create_team(ORG, {"name": "Red1", "team_type": "red"})
    blues = engine.list_teams(ORG, team_type="blue")
    assert len(blues) == 1
    assert blues[0]["team_type"] == "blue"


def test_list_teams_org_isolation(engine):
    engine.create_team(ORG, {"name": "Org1 Team"})
    engine.create_team(ORG2, {"name": "Org2 Team"})
    assert len(engine.list_teams(ORG)) == 1
    assert len(engine.list_teams(ORG2)) == 1


def test_get_team_found(engine):
    t = engine.create_team(ORG, {"name": "Findable"})
    fetched = engine.get_team(ORG, t["id"])
    assert fetched is not None
    assert fetched["name"] == "Findable"


def test_get_team_not_found(engine):
    assert engine.get_team(ORG, "ghost-id") is None


def test_get_team_wrong_org(engine):
    t = engine.create_team(ORG, {"name": "Private"})
    assert engine.get_team(ORG2, t["id"]) is None


# ---------------------------------------------------------------------------
# record_challenge
# ---------------------------------------------------------------------------

def test_record_challenge_basic(engine):
    c = engine.record_challenge(ORG, {
        "name": "CTF Qualifier",
        "challenge_type": "ctf",
        "max_points": 200,
        "participants": ["team-1", "team-2"],
    })
    assert c["name"] == "CTF Qualifier"
    assert c["challenge_type"] == "ctf"
    assert c["max_points"] == 200
    assert c["participants"] == ["team-1", "team-2"]
    assert c["status"] == "active"
    assert "id" in c
    assert "started_at" in c


def test_record_challenge_missing_name(engine):
    with pytest.raises(ValueError, match="name is required"):
        engine.record_challenge(ORG, {"challenge_type": "ctf"})


def test_record_challenge_invalid_type(engine):
    with pytest.raises(ValueError, match="Invalid challenge_type"):
        engine.record_challenge(ORG, {"name": "X", "challenge_type": "hackathon"})


def test_record_challenge_all_valid_types(engine):
    valid_types = ["ctf", "tabletop", "red_vs_blue", "compliance_audit", "incident_drill"]
    for ct in valid_types:
        c = engine.record_challenge(ORG, {"name": f"Challenge {ct}", "challenge_type": ct})
        assert c["challenge_type"] == ct


# ---------------------------------------------------------------------------
# submit_score
# ---------------------------------------------------------------------------

def test_submit_score_win(engine):
    """Points >= max_points/2 → win."""
    team = engine.create_team(ORG, {"name": "Winners"})
    challenge = engine.record_challenge(ORG, {"name": "CTF", "challenge_type": "ctf", "max_points": 100})
    updated = engine.submit_score(ORG, challenge["id"], team["id"], points_earned=60)
    assert updated["score"] == 60
    assert updated["wins"] == 1
    assert updated["losses"] == 0


def test_submit_score_loss(engine):
    """Points < max_points/2 → loss."""
    team = engine.create_team(ORG, {"name": "Learners"})
    challenge = engine.record_challenge(ORG, {"name": "CTF", "challenge_type": "ctf", "max_points": 100})
    updated = engine.submit_score(ORG, challenge["id"], team["id"], points_earned=40)
    assert updated["score"] == 40
    assert updated["wins"] == 0
    assert updated["losses"] == 1


def test_submit_score_exactly_half_is_win(engine):
    """Points == max_points/2 → win (>=)."""
    team = engine.create_team(ORG, {"name": "Borderline"})
    challenge = engine.record_challenge(ORG, {"name": "CTF", "challenge_type": "ctf", "max_points": 100})
    updated = engine.submit_score(ORG, challenge["id"], team["id"], points_earned=50)
    assert updated["wins"] == 1
    assert updated["losses"] == 0


def test_submit_score_accumulates(engine):
    """Multiple submissions accumulate score."""
    team = engine.create_team(ORG, {"name": "Grinders"})
    c1 = engine.record_challenge(ORG, {"name": "C1", "challenge_type": "ctf", "max_points": 100})
    c2 = engine.record_challenge(ORG, {"name": "C2", "challenge_type": "tabletop", "max_points": 50})
    engine.submit_score(ORG, c1["id"], team["id"], points_earned=80)
    updated = engine.submit_score(ORG, c2["id"], team["id"], points_earned=30)
    assert updated["score"] == 110
    assert updated["wins"] == 2


def test_submit_score_with_notes(engine):
    team = engine.create_team(ORG, {"name": "Noted"})
    challenge = engine.record_challenge(ORG, {"name": "CTF", "challenge_type": "ctf", "max_points": 100})
    updated = engine.submit_score(ORG, challenge["id"], team["id"], points_earned=75, notes="Solved all flags")
    assert updated is not None  # notes stored in score_entries, not team row


def test_submit_score_challenge_not_found(engine):
    team = engine.create_team(ORG, {"name": "Ghost Challenge"})
    result = engine.submit_score(ORG, "ghost-challenge-id", team["id"], points_earned=50)
    assert result is None


def test_submit_score_team_not_found(engine):
    challenge = engine.record_challenge(ORG, {"name": "CTF", "challenge_type": "ctf", "max_points": 100})
    result = engine.submit_score(ORG, challenge["id"], "ghost-team-id", points_earned=50)
    assert result is None


def test_submit_score_org_isolation(engine):
    """Team from ORG2 cannot be scored in ORG challenge."""
    team2 = engine.create_team(ORG2, {"name": "Foreign Team"})
    challenge = engine.record_challenge(ORG, {"name": "CTF", "challenge_type": "ctf", "max_points": 100})
    result = engine.submit_score(ORG, challenge["id"], team2["id"], points_earned=80)
    assert result is None


# ---------------------------------------------------------------------------
# list_challenges
# ---------------------------------------------------------------------------

def test_list_challenges_empty(engine):
    assert engine.list_challenges(ORG) == []


def test_list_challenges_returns_all(engine):
    engine.record_challenge(ORG, {"name": "C1", "challenge_type": "ctf"})
    engine.record_challenge(ORG, {"name": "C2", "challenge_type": "tabletop"})
    assert len(engine.list_challenges(ORG)) == 2


def test_list_challenges_filter_status(engine):
    engine.record_challenge(ORG, {"name": "Active", "challenge_type": "ctf"})
    results = engine.list_challenges(ORG, status="active")
    assert len(results) == 1
    assert results[0]["status"] == "active"


def test_list_challenges_org_isolation(engine):
    engine.record_challenge(ORG, {"name": "Org1 Challenge", "challenge_type": "ctf"})
    engine.record_challenge(ORG2, {"name": "Org2 Challenge", "challenge_type": "tabletop"})
    assert len(engine.list_challenges(ORG)) == 1
    assert len(engine.list_challenges(ORG2)) == 1


# ---------------------------------------------------------------------------
# get_leaderboard
# ---------------------------------------------------------------------------

def test_get_leaderboard_empty(engine):
    assert engine.get_leaderboard(ORG) == []


def test_get_leaderboard_ordered_by_score(engine):
    t1 = engine.create_team(ORG, {"name": "Low Score"})
    t2 = engine.create_team(ORG, {"name": "High Score"})
    t3 = engine.create_team(ORG, {"name": "Mid Score"})
    c = engine.record_challenge(ORG, {"name": "CTF", "challenge_type": "ctf", "max_points": 100})
    engine.submit_score(ORG, c["id"], t1["id"], points_earned=20)
    engine.submit_score(ORG, c["id"], t2["id"], points_earned=90)
    engine.submit_score(ORG, c["id"], t3["id"], points_earned=50)
    lb = engine.get_leaderboard(ORG)
    assert lb[0]["name"] == "High Score"
    assert lb[1]["name"] == "Mid Score"
    assert lb[2]["name"] == "Low Score"


def test_get_leaderboard_has_rank_field(engine):
    engine.create_team(ORG, {"name": "T1"})
    engine.create_team(ORG, {"name": "T2"})
    lb = engine.get_leaderboard(ORG)
    assert lb[0]["rank"] == 1
    assert lb[1]["rank"] == 2


def test_get_leaderboard_org_isolation(engine):
    engine.create_team(ORG, {"name": "Org1 Team"})
    engine.create_team(ORG2, {"name": "Org2 Team"})
    lb1 = engine.get_leaderboard(ORG)
    lb2 = engine.get_leaderboard(ORG2)
    assert len(lb1) == 1
    assert len(lb2) == 1


# ---------------------------------------------------------------------------
# get_scoreboard_stats
# ---------------------------------------------------------------------------

def test_stats_empty_org(engine):
    stats = engine.get_scoreboard_stats(ORG)
    assert stats["total_teams"] == 0
    assert stats["by_type"] == {}
    assert stats["total_challenges"] == 0
    assert stats["active_challenges"] == 0
    assert stats["top_team"] is None
    assert stats["avg_team_score"] == 0.0


def test_stats_team_counts(engine):
    engine.create_team(ORG, {"name": "Blue1", "team_type": "blue"})
    engine.create_team(ORG, {"name": "Blue2", "team_type": "blue"})
    engine.create_team(ORG, {"name": "Red1", "team_type": "red"})
    stats = engine.get_scoreboard_stats(ORG)
    assert stats["total_teams"] == 3
    assert stats["by_type"]["blue"] == 2
    assert stats["by_type"]["red"] == 1


def test_stats_top_team(engine):
    t1 = engine.create_team(ORG, {"name": "Winner"})
    t2 = engine.create_team(ORG, {"name": "Loser"})
    c = engine.record_challenge(ORG, {"name": "CTF", "challenge_type": "ctf", "max_points": 100})
    engine.submit_score(ORG, c["id"], t1["id"], points_earned=90)
    engine.submit_score(ORG, c["id"], t2["id"], points_earned=30)
    stats = engine.get_scoreboard_stats(ORG)
    assert stats["top_team"]["name"] == "Winner"
    assert stats["top_team"]["score"] == 90


def test_stats_avg_team_score(engine):
    t1 = engine.create_team(ORG, {"name": "T1"})
    t2 = engine.create_team(ORG, {"name": "T2"})
    c = engine.record_challenge(ORG, {"name": "CTF", "challenge_type": "ctf", "max_points": 100})
    engine.submit_score(ORG, c["id"], t1["id"], points_earned=60)
    engine.submit_score(ORG, c["id"], t2["id"], points_earned=40)
    stats = engine.get_scoreboard_stats(ORG)
    assert stats["avg_team_score"] == 50.0


def test_stats_challenge_counts(engine):
    engine.record_challenge(ORG, {"name": "C1", "challenge_type": "ctf"})
    engine.record_challenge(ORG, {"name": "C2", "challenge_type": "tabletop"})
    stats = engine.get_scoreboard_stats(ORG)
    assert stats["total_challenges"] == 2
    assert stats["active_challenges"] == 2
