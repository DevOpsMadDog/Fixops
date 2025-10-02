"""Backend package for FixOps simplified ingestion pipeline."""

__all__ = ["create_app"]


def __getattr__(name: str):
    if name == "create_app":
        from .app import create_app as _create_app

        return _create_app
    raise AttributeError(name)
