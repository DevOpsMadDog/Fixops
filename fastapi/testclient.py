"""Extremely small subset of the real FastAPI TestClient."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from . import HTTPException, RequestValidationError, set_request_headers


@dataclass
class _Response:
    status_code: int
    _json: Any

    def json(self) -> Any:
        return self._json


class TestClient:
    def __init__(self, app) -> None:  # type: ignore[annotation-unchecked]
        self.app = app

    def post(
        self,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> _Response:
        return self._request("POST", path, json or {}, headers or {})

    def get(
        self, path: str, headers: Optional[Dict[str, str]] = None
    ) -> _Response:
        return self._request("GET", path, None, headers or {})

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]],
        headers: Dict[str, str],
    ) -> _Response:
        try:
            set_request_headers(headers)
            payload = self.app._handle(method, path, body)  # type: ignore[attr-defined]
            status = 200
        except RequestValidationError as exc:
            payload = {"detail": exc.errors}
            status = 422
        except HTTPException as exc:
            payload = {"detail": exc.detail}
            status = exc.status_code
        finally:
            set_request_headers({})
        return _Response(status_code=status, _json=payload)
