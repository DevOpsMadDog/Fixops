from __future__ import annotations

from pathlib import Path

CHECK_DIRECTORIES = [
    Path("core"),
    Path("apps"),
    Path("fixops-enterprise") / "src",
]


def test_no_wip_imports() -> None:
    for directory in CHECK_DIRECTORIES:
        for path in directory.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            assert "import WIP" not in text, f"disallowed import in {path}"
            assert "from WIP" not in text, f"disallowed import in {path}"
