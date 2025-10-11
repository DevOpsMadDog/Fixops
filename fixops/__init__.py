"""Compatibility package exposing the public FixOps CLI entrypoints."""

from core.cli import main as _main

__all__ = ["_main"]


def main() -> int:
    """Invoke :func:`core.cli.main` for compatibility with ``python -m fixops``."""

    return _main()
