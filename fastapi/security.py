from typing import Optional


class APIKeyHeader:
    def __init__(self, name: str, *, auto_error: bool = True) -> None:
        self.name = name
        self.auto_error = auto_error


__all__ = ["APIKeyHeader"]
