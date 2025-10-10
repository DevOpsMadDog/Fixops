from typing import Iterable, Sequence


class CORSMiddleware:
    def __init__(
        self,
        app,
        *,
        allow_origins: Sequence[str] | Iterable[str] = (),
        allow_credentials: bool = False,
        allow_methods: Sequence[str] | Iterable[str] = (),
        allow_headers: Sequence[str] | Iterable[str] = (),
    ) -> None:
        self.app = app
        self.allow_origins = tuple(allow_origins)
        self.allow_credentials = allow_credentials
        self.allow_methods = tuple(allow_methods)
        self.allow_headers = tuple(allow_headers)


__all__ = ["CORSMiddleware"]
