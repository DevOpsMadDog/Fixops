"""Shared filesystem-path safety primitive for API endpoints.

Several endpoints accept a caller-supplied absolute path and read/write/scan it
(code-intel repo parsing, air-gap bundle export/import, scanner targets). Without
a boundary an authenticated user could point the server at arbitrary paths.

`safe_fs_path` is the single hardening primitive:
  - ALWAYS rejects null bytes and parent-traversal (`..`) segments (defense-in-depth;
    no legitimate caller path needs these).
  - When the given allowlist env var (os.pathsep-separated absolute roots) is SET,
    requires the resolved path to live within one of the roots — the SCIF lockdown.
  - When the env var is UNSET, returns the resolved path (passthrough) so existing
    operator workflows (self-scan, USB export to operator-chosen paths) are not broken.
    Deployments opt into the allowlist to lock the surface down.

Returns the resolved Path when allowed, else None. Callers decide how to degrade
(404 / worker-defer / treat-as-remote).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


def safe_fs_path(raw: Optional[str], allowlist_env: str) -> Optional[Path]:
    if not raw or "\x00" in raw or ".." in raw.replace("\\", "/").split("/"):
        return None
    try:
        resolved = Path(raw).expanduser().resolve()
    except (OSError, ValueError, RuntimeError):
        return None
    roots = [r for r in os.environ.get(allowlist_env, "").split(os.pathsep) if r.strip()]
    if roots:
        for root in roots:
            try:
                resolved.relative_to(Path(root).expanduser().resolve())
                return resolved
            except ValueError:
                continue
        return None  # outside every configured allowlist root
    return resolved
