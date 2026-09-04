"""Which user database you open must not depend on where you started.

UserDB defaulted to the relative string "data/users.db". Measured on this repo:

    ./data/users.db             79 users
    ./suite-api/data/users.db    0 users

So anything started from suite-api/ authenticated against an EMPTY database:
every login 401s, and every signup writes into a file nothing else reads. That
is exactly how "the password hash verifies in-process but login returns 401"
happens, and it cost a debugging session before anyone looked at the path.

Third instance of one defect class this session — the advisory-body lookup read
the wrong feeds.db, and the call graph landed outside the data directory. A
relative path is a join whose other half is the working directory.

The fallback deliberately stays <repo>/data/users.db rather than moving to
FIXOPS_DATA_DIR: relocating would orphan the accounts already there, and this
change is about cwd, not migration.
"""

from __future__ import annotations

import os
import pathlib


def test_the_default_path_is_absolute() -> None:
    from core.user_db import default_user_db_path

    assert default_user_db_path().is_absolute(), (
        "a relative default makes the working directory part of the lookup"
    )


def test_the_path_does_not_change_with_cwd(monkeypatch, tmp_path) -> None:
    from core.user_db import default_user_db_path

    monkeypatch.delenv("FIXOPS_USERS_DB", raising=False)
    from_here = default_user_db_path()
    monkeypatch.chdir(tmp_path)
    assert default_user_db_path() == from_here


def test_it_still_points_at_the_historical_location(monkeypatch) -> None:
    """Not a migration. The existing accounts must remain findable."""
    from core.user_db import default_user_db_path

    monkeypatch.delenv("FIXOPS_USERS_DB", raising=False)
    path = default_user_db_path()
    assert path.parent.name == "data"
    assert path.name == "users.db"


def test_an_explicit_override_wins(monkeypatch, tmp_path) -> None:
    """Deployments that place it elsewhere need a way to say so."""
    target = tmp_path / "custom" / "users.db"
    monkeypatch.setenv("FIXOPS_USERS_DB", str(target))
    from core.user_db import default_user_db_path

    assert default_user_db_path() == target


def test_an_explicit_constructor_argument_still_wins(tmp_path) -> None:
    """Tests and tools pass a path directly; that must keep working."""
    from core.user_db import UserDB

    db = UserDB(str(tmp_path / "explicit.db"))
    assert db.db_path == tmp_path / "explicit.db"
