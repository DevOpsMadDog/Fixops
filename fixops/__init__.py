"""Compatibility package exposing the public FixOps CLI entrypoints."""

from typing import TYPE_CHECKING

__all__ = ["main"]

if TYPE_CHECKING:  # pragma: no cover - import only for type checkers
    from core.cli import main as _main


def __getattr__(name: str):  # pragma: no cover - runtime compatibility shim
    if name == "_main":
        from core.cli import main as _main

        return _main
    raise AttributeError(name)


def main() -> int:
    """Invoke :func:`core.cli.main` for compatibility with ``python -m fixops``."""

    from core.cli import main as _main

    return _main()
