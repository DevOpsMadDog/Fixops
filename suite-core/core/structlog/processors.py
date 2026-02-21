"""Subset of ``structlog.processors`` used by the FixOps codebase."""

from __future__ import annotations

import datetime as _dt
import json
from typing import Any, Dict


class TimeStamper:
    def __init__(self, fmt: str = "iso") -> None:
        self.fmt = fmt

    def __call__(
        self, logger, method_name: str, event_dict: Dict[str, Any]
    ) -> Dict[str, Any]:
        timestamp = _dt.datetime.utcnow()
        if self.fmt == "iso":
            event_dict.setdefault("timestamp", timestamp.isoformat())
        else:
            event_dict.setdefault("timestamp", str(timestamp))
        return event_dict


class StackInfoRenderer:
    def __call__(
        self, logger, method_name: str, event_dict: Dict[str, Any]
    ) -> Dict[str, Any]:
        return event_dict


def format_exc_info(
    logger, method_name: str, event_dict: Dict[str, Any]
) -> Dict[str, Any]:
    return event_dict


class UnicodeDecoder:
    def __call__(
        self, logger, method_name: str, event_dict: Dict[str, Any]
    ) -> Dict[str, Any]:
        return event_dict


class JSONRenderer:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs

    def __call__(self, logger, method_name: str, event_dict: Dict[str, Any]) -> str:
        return json.dumps(event_dict, **self.kwargs)


__all__ = [
    "TimeStamper",
    "StackInfoRenderer",
    "format_exc_info",
    "UnicodeDecoder",
    "JSONRenderer",
]
