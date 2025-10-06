"""Extremely small subset of the real FastAPI TestClient."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from . import HTTPException, RequestValidationError, UploadFile, set_request_headers, set_request_files


@dataclass
class _Response:
    status_code: int
    _json: Any

    def json(self) -> Any:
        return self._json


class TestClient:
    def __init__(self, app) -> None:  # type: ignore[annotation-unchecked]
        self.app = app
        self._session_id: Optional[str] = None

    def post(
        self,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, Tuple[str, Any, Optional[str]]]] = None,
    ) -> _Response:
        return self._request("POST", path, json or {}, headers or {}, files)

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
        files: Optional[Dict[str, Tuple[str, Any, Optional[str]]]] = None,
    ) -> _Response:
        try:
            headers = dict(headers)
            if "X-Fixops-Run-Id" not in headers and self._session_id:
                headers["X-Fixops-Run-Id"] = self._session_id
            set_request_headers(headers)
            uploads: Dict[str, UploadFile] = {}
            if files:
                for field, spec in files.items():
                    if not isinstance(spec, tuple) or len(spec) < 2:
                        raise TypeError("Files must be provided as (filename, content[, content_type]) tuples")
                    filename = spec[0] or "upload"
                    content = spec[1]
                    content_type = spec[2] if len(spec) > 2 else None
                    upload = UploadFile(filename=filename, content_type=content_type)
                    raw = content.encode("utf-8") if isinstance(content, str) else bytes(content)
                    upload._buffer.extend(raw)  # type: ignore[attr-defined]
                    uploads[field] = upload
            set_request_files(uploads)
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
            set_request_files({})
        if isinstance(payload, dict) and "session_id" in payload:
            self._session_id = str(payload["session_id"])
        return _Response(status_code=status, _json=payload)
