"""Tests for UserDB — user and team database manager."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest
from core.user_models import Team, TeamMember, User, UserRole, UserStatus


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------
class TestUserModels:
    def test_user_role_enum(self):
        assert UserRole.ADMIN == "admin"
        assert UserRole.SECURITY_ANALYST == "security_analyst"
        assert UserRole.DEVELOPER == "developer"
        assert UserRole.VIEWER == "viewer"

    def test_user_status_enum(self):
        assert UserStatus.ACTIVE == "active"
        assert UserStatus.INACTIVE == "inactive"
        assert UserStatus.SUSPENDED == "suspended"

    def test_user_to_dict(self):
        user = User(
            id="u1",
            email="test@example.com",
            password_hash="$2b$hash",
            first_name="John",
            last_name="Doe",
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE,
            department="Security",
        )
        d = user.to_dict()
        assert d["id"] == "u1"
        assert d["email"] == "test@example.com"
        assert "password_hash" not in d
        assert d["role"] == "admin"
        assert d["status"] == "active"
        assert d["department"] == "Security"

    def test_user_to_dict_with_password(self):
        user = User(
            id="u2",
            email="a@b.com",
            password_hash="hash123",
            first_name="A",
            last_name="B",
            role=UserRole.VIEWER,
        )
        d = user.to_dict(include_password=True)
        assert "password_hash" in d

    def test_team_to_dict(self):
        team = Team(id="t1", name="Team Alpha", description="Test team")
        d = team.to_dict()
        assert d["id"] == "t1"
        assert d["name"] == "Team Alpha"

    def test_team_member_to_dict(self):
        tm = TeamMember(team_id="t1", user_id="u1", role="lead")
        d = tm.to_dict()
        assert d["team_id"] == "t1"
        assert d["user_id"] == "u1"
        assert d["role"] == "lead"


# ---------------------------------------------------------------------------
# UserDB tests
# ---------------------------------------------------------------------------
class TestUserDB:
    @pytest.fixture
    def db(self, tmp_path):
        from core.user_db import UserDB
        db_path = str(tmp_path / "test_users.db")
        return UserDB(db_path=db_path)

    @pytest.fixture
    def sample_user(self, db):
        user = User(
            id="",
            email="john@example.com",
            password_hash=db.hash_password("securepass123"),
            first_name="John",
            last_name="Doe",
            role=UserRole.SECURITY_ANALYST,
            status=UserStatus.ACTIVE,
            department="Security",
        )
        return db.create_user(user)

    def test_create_user(self, db):
        user = User(
            id="",
            email="new@example.com",
            password_hash=db.hash_password("pass"),
            first_name="New",
            last_name="User",
            role=UserRole.DEVELOPER,
        )
        created = db.create_user(user)
        assert created.id != ""
        assert created.email == "new@example.com"

    def test_get_user(self, db, sample_user):
        user = db.get_user(sample_user.id)
        assert user is not None
        assert user.email == "john@example.com"
        assert user.first_name == "John"

    def test_get_user_not_found(self, db):
        assert db.get_user("nonexistent") is None

    def test_get_user_by_email(self, db, sample_user):
        user = db.get_user_by_email("john@example.com")
        assert user is not None
        assert user.id == sample_user.id

    def test_get_user_by_email_not_found(self, db):
        assert db.get_user_by_email("nobody@nowhere.com") is None

    def test_list_users(self, db, sample_user):
        users = db.list_users()
        assert len(users) >= 1

    def test_list_users_pagination(self, db):
        for i in range(5):
            db.create_user(User(
                id="",
                email=f"user{i}@test.com",
                password_hash=db.hash_password("p"),
                first_name=f"User{i}",
                last_name="Test",
                role=UserRole.VIEWER,
            ))
        page1 = db.list_users(limit=3, offset=0)
        page2 = db.list_users(limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 2

    def test_update_user(self, db, sample_user):
        sample_user.first_name = "Jane"
        sample_user.department = "Engineering"
        updated = db.update_user(sample_user)
        assert updated.first_name == "Jane"
        assert updated.department == "Engineering"
        # Verify from DB
        from_db = db.get_user(sample_user.id)
        assert from_db.first_name == "Jane"

    def test_delete_user(self, db, sample_user):
        result = db.delete_user(sample_user.id)
        assert result is True
        assert db.get_user(sample_user.id) is None

    def test_hash_password(self, db):
        hashed = db.hash_password("mypassword")
        assert hashed != "mypassword"
        assert hashed.startswith("$2b$")

    def test_verify_password(self, db):
        hashed = db.hash_password("correcthorse")
        assert db.verify_password("correcthorse", hashed) is True
        assert db.verify_password("wrongpassword", hashed) is False


# ---------------------------------------------------------------------------
# Team DB tests
# ---------------------------------------------------------------------------
class TestTeamDB:
    @pytest.fixture
    def db(self, tmp_path):
        from core.user_db import UserDB
        return UserDB(db_path=str(tmp_path / "test_teams.db"))

    @pytest.fixture
    def sample_team(self, db):
        team = Team(id="", name="Security Team", description="AppSec team")
        return db.create_team(team)

    def test_create_team(self, db):
        team = Team(id="", name="New Team", description="A new team")
        created = db.create_team(team)
        assert created.id != ""
        assert created.name == "New Team"

    def test_get_team(self, db, sample_team):
        team = db.get_team(sample_team.id)
        assert team is not None
        assert team.name == "Security Team"

    def test_get_team_not_found(self, db):
        assert db.get_team("nonexistent") is None

    def test_list_teams(self, db, sample_team):
        teams = db.list_teams()
        assert len(teams) >= 1

    def test_update_team(self, db, sample_team):
        sample_team.name = "Updated Team"
        updated = db.update_team(sample_team)
        assert updated.name == "Updated Team"

    def test_delete_team(self, db, sample_team):
        result = db.delete_team(sample_team.id)
        assert result is True
        assert db.get_team(sample_team.id) is None


# ---------------------------------------------------------------------------
# Team membership tests
# ---------------------------------------------------------------------------
class TestTeamMembership:
    @pytest.fixture
    def db(self, tmp_path):
        from core.user_db import UserDB
        return UserDB(db_path=str(tmp_path / "test_membership.db"))

    @pytest.fixture
    def user_and_team(self, db):
        user = db.create_user(User(
            id="",
            email="member@test.com",
            password_hash=db.hash_password("p"),
            first_name="Member",
            last_name="Test",
            role=UserRole.DEVELOPER,
        ))
        team = db.create_team(Team(id="", name="DevTeam", description="Dev team"))
        return user, team

    def test_add_team_member(self, db, user_and_team):
        user, team = user_and_team
        member = db.add_team_member(team.id, user.id, "member")
        assert member.team_id == team.id
        assert member.user_id == user.id
        assert member.role == "member"

    def test_list_team_members(self, db, user_and_team):
        user, team = user_and_team
        db.add_team_member(team.id, user.id, "lead")
        members = db.list_team_members(team.id)
        assert len(members) == 1
        assert members[0]["email"] == "member@test.com"
        assert members[0]["team_role"] == "lead"

    def test_remove_team_member(self, db, user_and_team):
        user, team = user_and_team
        db.add_team_member(team.id, user.id)
        result = db.remove_team_member(team.id, user.id)
        assert result is True
        members = db.list_team_members(team.id)
        assert len(members) == 0

    def test_delete_user_cascades_membership(self, db, user_and_team):
        user, team = user_and_team
        db.add_team_member(team.id, user.id)
        db.delete_user(user.id)
        members = db.list_team_members(team.id)
        assert len(members) == 0

    def test_delete_team_cascades_membership(self, db, user_and_team):
        user, team = user_and_team
        db.add_team_member(team.id, user.id)
        db.delete_team(team.id)
        # team is gone
        assert db.get_team(team.id) is None
