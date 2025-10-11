"""Allow ``python -m fixops`` to behave like the CLI."""

from . import main

if __name__ == "__main__":  # pragma: no cover - CLI convenience
    raise SystemExit(main())
