"""Compatibility package exposing the public FixOps CLI entrypoints."""

__all__ = ["_main", "main"]


def _main(*args, **kwargs):
    from core.cli import main as cli_main

    return cli_main(*args, **kwargs)


def main() -> int:
    """Invoke :func:`core.cli.main` for compatibility with ``python -m fixops``."""

    return _main()
