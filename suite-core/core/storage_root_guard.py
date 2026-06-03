"""Shared storage-root allowlist guard (SCIF hardening).

Several engines read or scan a caller-supplied filesystem path (root/target/file).
Per-engine path-within-root containment is not enough — the *root itself* must be
confined to an allowlisted base, otherwise an authenticated caller can read or scan
arbitrary paths (``/etc/passwd``, ``~/.ssh``, app secrets) and receive the contents
back as findings/file-content.

This module centralizes the allowlist logic so every path-handling engine enforces
the same policy. Each engine passes its own env var (e.g. ``FIXOPS_DLP_ALLOWED_ROOTS``)
so roots can be tuned per surface; when unset a safe default is used.

Default policy (``include_tempdir=True``): system scratch dir + fleet workspace bases
— permits scratch/workspace, blocks ``/etc``, ``/home``, ``/root``, app source.
Stricter default (``include_tempdir=False``): fleet workspace bases only.
"""

from __future__ import annotations

import os
import tempfile
from typing import List, Optional

# Fleet workspace bases used by the IDE-gateway / scanner fleet.
_FLEET_ROOTS = ("/tmp/fixops-fleet", "/private/tmp/fixops-fleet")


def allowed_roots(
    env_var: str,
    include_tempdir: bool = True,
    extra: Optional[List[str]] = None,
) -> List[str]:
    """Resolve the allowlisted root bases for a given env var.

    If ``env_var`` is set (os.pathsep-separated absolute paths) it is authoritative;
    otherwise the fleet defaults (optionally + the system temp dir) are used. ``extra``
    appends caller-supplied bases (e.g. a test's tmp workspace).
    """
    env = os.environ.get(env_var, "").strip()
    if env:
        roots = [
            os.path.realpath(os.path.abspath(p))
            for p in env.split(os.pathsep)
            if p.strip()
        ]
    else:
        candidates = list(_FLEET_ROOTS)
        if include_tempdir:
            # System scratch dirs (low-sensitivity; /etc, /home, /root stay blocked).
            # /tmp + /private/tmp cover Linux and macOS (gettempdir() is /var/folders on macOS).
            candidates[:0] = [tempfile.gettempdir(), "/tmp", "/private/tmp"]
        roots = []
        for c in candidates:
            try:
                roots.append(os.path.realpath(os.path.abspath(c)))
            except OSError:
                continue
    if extra:
        roots = roots + [
            os.path.realpath(os.path.abspath(p)) for p in extra if p
        ]
    return roots


def assert_path_allowed(
    path: str,
    env_var: str,
    include_tempdir: bool = True,
    extra: Optional[List[str]] = None,
    label: str = "path",
) -> None:
    """Raise ``ValueError`` if ``path`` is outside the storage-root allowlist.

    Defence-in-depth against arbitrary filesystem read/scan via a caller-supplied
    path. Path-within-root containment (rejecting ``..`` etc.) is enforced separately
    by each engine; this bounds the *root* the caller may point at.
    """
    if not path:
        raise ValueError(f"{label} is required")
    real = os.path.realpath(os.path.abspath(path))
    for base in allowed_roots(env_var, include_tempdir, extra):
        if real == base or real.startswith(base + os.sep):
            return
    raise ValueError(
        f"{label} is not within an allowed storage root (set {env_var} to permit it)"
    )
