"""
User and team database manager using SQLite.
"""
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import bcrypt

from core.user_models import Team, TeamMember, User, UserRole, UserStatus


class UserDB:
    """Database manager for users and teams."""

    def __init__(self, db_path: str = "data/users.db"):
        """Initialize database connection."""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self):
        """Initialize database tables."""
        conn = self._get_connection()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    first_name TEXT NOT NULL,
                    last_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    status TEXT NOT NULL,
                    department TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login_at TEXT
                );

                CREATE TABLE IF NOT EXISTS teams (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS team_members (
                    team_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    added_at TEXT NOT NULL,
                    PRIMARY KEY (team_id, user_id),
                    FOREIGN KEY (team_id) REFERENCES teams(id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );

                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
                CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
                CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members(user_id);
                CREATE INDEX IF NOT EXISTS idx_team_members_team ON team_members(team_id);
            """
            )
            conn.commit()
        finally:
            conn.close()

    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt."""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash."""
        return bcrypt.checkpw(password.encode(), password_hash.encode())

    def create_user(self, user: User) -> User:
        """Create new user."""
        if not user.id:
            user.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    user.id,
                    user.email,
                    user.password_hash,
                    user.first_name,
                    user.last_name,
                    user.role.value,
                    user.status.value,
                    user.department,
                    user.created_at.isoformat(),
                    user.updated_at.isoformat(),
                    user.last_login_at.isoformat() if user.last_login_at else None,
                ),
            )
            conn.commit()
            return user
        finally:
            conn.close()

    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if row:
                return self._row_to_user(row)
            return None
        finally:
            conn.close()

    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()
            if row:
                return self._row_to_user(row)
            return None
        finally:
            conn.close()

    def list_users(self, limit: int = 100, offset: int = 0) -> List[User]:
        """List users with pagination."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return [self._row_to_user(row) for row in rows]
        finally:
            conn.close()

    def update_user(self, user: User) -> User:
        """Update user."""
        user.updated_at = datetime.utcnow()
        conn = self._get_connection()
        try:
            conn.execute(
                """UPDATE users SET email=?, first_name=?, last_name=?, role=?,
                   status=?, department=?, updated_at=?, last_login_at=? WHERE id=?""",
                (
                    user.email,
                    user.first_name,
                    user.last_name,
                    user.role.value,
                    user.status.value,
                    user.department,
                    user.updated_at.isoformat(),
                    user.last_login_at.isoformat() if user.last_login_at else None,
                    user.id,
                ),
            )
            conn.commit()
            return user
        finally:
            conn.close()

    def delete_user(self, user_id: str) -> bool:
        """Delete user."""
        conn = self._get_connection()
        try:
            conn.execute("DELETE FROM team_members WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            return True
        finally:
            conn.close()

    def create_team(self, team: Team) -> Team:
        """Create new team."""
        if not team.id:
            team.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO teams VALUES (?, ?, ?, ?, ?)""",
                (
                    team.id,
                    team.name,
                    team.description,
                    team.created_at.isoformat(),
                    team.updated_at.isoformat(),
                ),
            )
            conn.commit()
            return team
        finally:
            conn.close()

    def get_team(self, team_id: str) -> Optional[Team]:
        """Get team by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM teams WHERE id = ?", (team_id,)
            ).fetchone()
            if row:
                return self._row_to_team(row)
            return None
        finally:
            conn.close()

    def list_teams(self, limit: int = 100, offset: int = 0) -> List[Team]:
        """List teams with pagination."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM teams ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return [self._row_to_team(row) for row in rows]
        finally:
            conn.close()

    def update_team(self, team: Team) -> Team:
        """Update team."""
        team.updated_at = datetime.utcnow()
        conn = self._get_connection()
        try:
            conn.execute(
                """UPDATE teams SET name=?, description=?, updated_at=? WHERE id=?""",
                (team.name, team.description, team.updated_at.isoformat(), team.id),
            )
            conn.commit()
            return team
        finally:
            conn.close()

    def delete_team(self, team_id: str) -> bool:
        """Delete team."""
        conn = self._get_connection()
        try:
            conn.execute("DELETE FROM team_members WHERE team_id = ?", (team_id,))
            conn.execute("DELETE FROM teams WHERE id = ?", (team_id,))
            conn.commit()
            return True
        finally:
            conn.close()

    def add_team_member(
        self, team_id: str, user_id: str, role: str = "member"
    ) -> TeamMember:
        """Add user to team."""
        member = TeamMember(team_id=team_id, user_id=user_id, role=role)
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO team_members VALUES (?, ?, ?, ?)""",
                (team_id, user_id, role, member.added_at.isoformat()),
            )
            conn.commit()
            return member
        finally:
            conn.close()

    def remove_team_member(self, team_id: str, user_id: str) -> bool:
        """Remove user from team."""
        conn = self._get_connection()
        try:
            conn.execute(
                "DELETE FROM team_members WHERE team_id = ? AND user_id = ?",
                (team_id, user_id),
            )
            conn.commit()
            return True
        finally:
            conn.close()

    def list_team_members(self, team_id: str) -> List[Dict[str, Any]]:
        """List all members of a team with user details."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                """SELECT u.*, tm.role as team_role, tm.added_at
                   FROM team_members tm
                   JOIN users u ON tm.user_id = u.id
                   WHERE tm.team_id = ?""",
                (team_id,),
            ).fetchall()
            return [
                {
                    **self._row_to_user(row).to_dict(),
                    "team_role": row["team_role"],
                    "added_at": row["added_at"],
                }
                for row in rows
            ]
        finally:
            conn.close()

    def _row_to_user(self, row) -> User:
        """Convert database row to User object."""
        return User(
            id=row["id"],
            email=row["email"],
            password_hash=row["password_hash"],
            first_name=row["first_name"],
            last_name=row["last_name"],
            role=UserRole(row["role"]),
            status=UserStatus(row["status"]),
            department=row["department"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            last_login_at=(
                datetime.fromisoformat(row["last_login_at"])
                if row["last_login_at"]
                else None
            ),
        )

    def _row_to_team(self, row) -> Team:
        """Convert database row to Team object."""
        return Team(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )
