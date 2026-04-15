"""Tests for SecurityAwarenessGamificationEngine — 30+ tests covering
challenges, completions, leaderboard, badges, user profiles, stats,
and org isolation.
"""
from __future__ import annotations

import pytest
from core.security_awareness_gamification_engine import SecurityAwarenessGamificationEngine


@pytest.fixture
def engine(tmp_path):
    return SecurityAwarenessGamificationEngine(db_dir=str(tmp_path))


@pytest.fixture
def org():
    return "org-alpha"


@pytest.fixture
def org2():
    return "org-beta"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _challenge(**kwargs):
    defaults = {
        "title": "Security Quiz",
        "challenge_type": "quiz",
        "difficulty": "medium",
        "points": 20,
        "department": "engineering",
    }
    defaults.update(kwargs)
    return defaults


def _completion(**kwargs):
    defaults = {
        "score": 85.0,
        "time_spent_seconds": 120,
        "passed": True,
    }
    defaults.update(kwargs)
    return defaults


# ---------------------------------------------------------------------------
# create_challenge
# ---------------------------------------------------------------------------

class TestCreateChallenge:
    def test_create_returns_record(self, engine, org):
        ch = engine.create_challenge(org, _challenge())
        assert ch["id"]
        assert ch["org_id"] == org
        assert ch["title"] == "Security Quiz"
        assert ch["challenge_type"] == "quiz"
        assert ch["difficulty"] == "medium"
        assert ch["points"] == 20
        assert ch["active"] == 1

    def test_create_all_valid_types(self, engine, org):
        for ct in ["quiz", "phishing_sim", "ctf", "training", "policy_review"]:
            ch = engine.create_challenge(org, _challenge(title=f"Test {ct}", challenge_type=ct))
            assert ch["challenge_type"] == ct

    def test_create_all_valid_difficulties(self, engine, org):
        for diff in ["easy", "medium", "hard", "expert"]:
            ch = engine.create_challenge(org, _challenge(title=f"Test {diff}", difficulty=diff))
            assert ch["difficulty"] == diff

    def test_create_invalid_type_raises(self, engine, org):
        with pytest.raises(ValueError, match="challenge_type"):
            engine.create_challenge(org, _challenge(challenge_type="hackathon"))

    def test_create_invalid_difficulty_raises(self, engine, org):
        with pytest.raises(ValueError, match="difficulty"):
            engine.create_challenge(org, _challenge(difficulty="legendary"))

    def test_create_missing_title_raises(self, engine, org):
        with pytest.raises(ValueError, match="title"):
            engine.create_challenge(org, {"challenge_type": "quiz", "difficulty": "easy"})

    def test_create_empty_title_raises(self, engine, org):
        with pytest.raises(ValueError, match="title"):
            engine.create_challenge(org, _challenge(title="  "))

    def test_create_default_points(self, engine, org):
        ch = engine.create_challenge(org, {"title": "T", "challenge_type": "quiz", "difficulty": "easy"})
        assert ch["points"] == 10


# ---------------------------------------------------------------------------
# list_challenges
# ---------------------------------------------------------------------------

class TestListChallenges:
    def test_list_empty(self, engine, org):
        assert engine.list_challenges(org) == []

    def test_list_returns_all(self, engine, org):
        engine.create_challenge(org, _challenge(title="A"))
        engine.create_challenge(org, _challenge(title="B"))
        assert len(engine.list_challenges(org)) == 2

    def test_list_filter_type(self, engine, org):
        engine.create_challenge(org, _challenge(title="Quiz1", challenge_type="quiz"))
        engine.create_challenge(org, _challenge(title="CTF1", challenge_type="ctf"))
        result = engine.list_challenges(org, challenge_type="quiz")
        assert all(c["challenge_type"] == "quiz" for c in result)
        assert len(result) == 1

    def test_list_filter_difficulty(self, engine, org):
        engine.create_challenge(org, _challenge(title="Easy1", difficulty="easy"))
        engine.create_challenge(org, _challenge(title="Hard1", difficulty="hard"))
        result = engine.list_challenges(org, difficulty="hard")
        assert all(c["difficulty"] == "hard" for c in result)
        assert len(result) == 1

    def test_list_org_isolation(self, engine, org, org2):
        engine.create_challenge(org, _challenge(title="OrgA"))
        engine.create_challenge(org2, _challenge(title="OrgB"))
        assert len(engine.list_challenges(org)) == 1
        assert len(engine.list_challenges(org2)) == 1


# ---------------------------------------------------------------------------
# record_completion
# ---------------------------------------------------------------------------

class TestRecordCompletion:
    def test_completion_returns_record(self, engine, org):
        ch = engine.create_challenge(org, _challenge())
        comp = engine.record_completion(org, "user-1", ch["id"], _completion())
        assert comp["id"]
        assert comp["user_id"] == "user-1"
        assert comp["challenge_id"] == ch["id"]
        assert comp["passed"] == 1

    def test_passed_true_adds_points(self, engine, org):
        ch = engine.create_challenge(org, _challenge(points=50))
        engine.record_completion(org, "user-1", ch["id"], _completion(passed=True))
        profile = engine.get_user_profile(org, "user-1")
        assert profile["total_points"] == 50

    def test_passed_false_no_points(self, engine, org):
        ch = engine.create_challenge(org, _challenge(points=50))
        engine.record_completion(org, "user-1", ch["id"], _completion(passed=False))
        profile = engine.get_user_profile(org, "user-1")
        assert profile["total_points"] == 0

    def test_multiple_completions_accumulate_points(self, engine, org):
        ch = engine.create_challenge(org, _challenge(points=10))
        engine.record_completion(org, "user-1", ch["id"], _completion(passed=True))
        engine.record_completion(org, "user-1", ch["id"], _completion(passed=True))
        profile = engine.get_user_profile(org, "user-1")
        assert profile["total_points"] == 20

    def test_completion_unknown_challenge_defaults_10_points(self, engine, org):
        engine.record_completion(org, "user-x", "nonexistent-ch", _completion(passed=True))
        profile = engine.get_user_profile(org, "user-x")
        assert profile["total_points"] == 10


# ---------------------------------------------------------------------------
# get_leaderboard
# ---------------------------------------------------------------------------

class TestGetLeaderboard:
    def test_leaderboard_empty(self, engine, org):
        assert engine.get_leaderboard(org) == []

    def test_leaderboard_ordering(self, engine, org):
        ch = engine.create_challenge(org, _challenge(points=30))
        engine.record_completion(org, "user-a", ch["id"], _completion(passed=True))
        ch2 = engine.create_challenge(org, _challenge(title="Q2", points=10))
        engine.record_completion(org, "user-b", ch2["id"], _completion(passed=True))
        lb = engine.get_leaderboard(org)
        assert lb[0]["user_id"] == "user-a"
        assert lb[0]["total_points"] == 30
        assert lb[0]["rank"] == 1
        assert lb[1]["rank"] == 2

    def test_leaderboard_limit(self, engine, org):
        ch = engine.create_challenge(org, _challenge(points=5))
        for i in range(10):
            engine.record_completion(org, f"user-{i}", ch["id"], _completion(passed=True))
        lb = engine.get_leaderboard(org, limit=3)
        assert len(lb) <= 3

    def test_leaderboard_org_isolation(self, engine, org, org2):
        ch = engine.create_challenge(org, _challenge(points=100))
        engine.record_completion(org, "user-1", ch["id"], _completion(passed=True))
        lb2 = engine.get_leaderboard(org2)
        assert lb2 == []


# ---------------------------------------------------------------------------
# get_user_profile
# ---------------------------------------------------------------------------

class TestGetUserProfile:
    def test_profile_new_user(self, engine, org):
        profile = engine.get_user_profile(org, "new-user")
        assert profile["user_id"] == "new-user"
        assert profile["total_points"] == 0
        assert profile["completions_count"] == 0
        assert profile["challenges_passed"] == 0
        assert profile["badges"] == []

    def test_profile_shows_badges(self, engine, org):
        engine.award_badge(org, "user-1", {"badge_name": "Champion", "badge_type": "achievement"})
        profile = engine.get_user_profile(org, "user-1")
        assert len(profile["badges"]) == 1
        assert profile["badges"][0]["badge_name"] == "Champion"

    def test_profile_shows_completions(self, engine, org):
        ch = engine.create_challenge(org, _challenge(points=10))
        engine.record_completion(org, "user-1", ch["id"], _completion(passed=True))
        engine.record_completion(org, "user-1", ch["id"], _completion(passed=False))
        profile = engine.get_user_profile(org, "user-1")
        assert profile["completions_count"] == 2
        assert profile["challenges_passed"] == 1


# ---------------------------------------------------------------------------
# award_badge
# ---------------------------------------------------------------------------

class TestAwardBadge:
    def test_award_valid_badge(self, engine, org):
        badge = engine.award_badge(org, "user-1", {
            "badge_name": "Phishing Pro",
            "badge_type": "milestone",
            "description": "Passed 10 phishing sims",
        })
        assert badge["id"]
        assert badge["badge_type"] == "milestone"
        assert badge["user_id"] == "user-1"

    def test_award_all_badge_types(self, engine, org):
        for bt in ["achievement", "milestone", "streak", "special"]:
            b = engine.award_badge(org, "user-1", {"badge_name": bt, "badge_type": bt})
            assert b["badge_type"] == bt

    def test_award_invalid_badge_type_raises(self, engine, org):
        with pytest.raises(ValueError, match="badge_type"):
            engine.award_badge(org, "user-1", {"badge_name": "X", "badge_type": "legendary"})

    def test_award_multiple_badges(self, engine, org):
        engine.award_badge(org, "user-1", {"badge_name": "A", "badge_type": "achievement"})
        engine.award_badge(org, "user-1", {"badge_name": "B", "badge_type": "streak"})
        profile = engine.get_user_profile(org, "user-1")
        assert len(profile["badges"]) == 2


# ---------------------------------------------------------------------------
# get_gamification_stats
# ---------------------------------------------------------------------------

class TestGetGamificationStats:
    def test_stats_empty(self, engine, org):
        stats = engine.get_gamification_stats(org)
        assert stats["total_challenges"] == 0
        assert stats["total_completions"] == 0
        assert stats["active_users"] == 0
        assert stats["avg_score"] == 0.0
        assert stats["top_department"] is None

    def test_stats_total_challenges(self, engine, org):
        engine.create_challenge(org, _challenge(title="A"))
        engine.create_challenge(org, _challenge(title="B"))
        stats = engine.get_gamification_stats(org)
        assert stats["total_challenges"] == 2

    def test_stats_total_completions(self, engine, org):
        ch = engine.create_challenge(org, _challenge())
        engine.record_completion(org, "u1", ch["id"], _completion())
        engine.record_completion(org, "u2", ch["id"], _completion())
        stats = engine.get_gamification_stats(org)
        assert stats["total_completions"] == 2

    def test_stats_active_users(self, engine, org):
        ch = engine.create_challenge(org, _challenge())
        engine.record_completion(org, "u1", ch["id"], _completion())
        engine.record_completion(org, "u1", ch["id"], _completion())
        engine.record_completion(org, "u2", ch["id"], _completion())
        stats = engine.get_gamification_stats(org)
        assert stats["active_users"] == 2

    def test_stats_avg_score(self, engine, org):
        ch = engine.create_challenge(org, _challenge())
        engine.record_completion(org, "u1", ch["id"], _completion(score=80.0))
        engine.record_completion(org, "u2", ch["id"], _completion(score=60.0))
        stats = engine.get_gamification_stats(org)
        assert abs(stats["avg_score"] - 70.0) < 0.01

    def test_stats_top_department(self, engine, org):
        ch_eng = engine.create_challenge(org, _challenge(title="Eng", department="engineering"))
        ch_hr = engine.create_challenge(org, _challenge(title="HR", challenge_type="training", department="hr"))
        engine.record_completion(org, "u1", ch_eng["id"], _completion())
        engine.record_completion(org, "u2", ch_eng["id"], _completion())
        engine.record_completion(org, "u3", ch_hr["id"], _completion())
        stats = engine.get_gamification_stats(org)
        assert stats["top_department"] == "engineering"

    def test_stats_org_isolation(self, engine, org, org2):
        ch = engine.create_challenge(org, _challenge())
        engine.record_completion(org, "u1", ch["id"], _completion())
        stats2 = engine.get_gamification_stats(org2)
        assert stats2["total_challenges"] == 0
        assert stats2["total_completions"] == 0
