"""CLI wrapper forwarding to :mod:`core.cli`."""

from core.cli import build_parser, main

__all__ = ["build_parser", "main"]


if __name__ == "__main__":  # pragma: no cover - CLI convenience
    raise SystemExit(main())
