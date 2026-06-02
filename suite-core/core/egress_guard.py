"""SPEC-005 — Active socket-level egress guard for enforced air-gap mode.

The SPEC-005 boot block already disables telemetry, forces HF offline, and the
feed/LLM layers each carry their own ``FIXOPS_AIRGAP_MODE=enforced`` checks.
Those are per-call-site guards, which the Red-Team debate line flagged as
incomplete: *"Can any outbound slip past under enforced? (HF, feeds, license
check, package fetch)"*.  A new dependency, a forgotten guard, or a transitive
library call could still open a socket to the public internet, while the
``/api/v1/airgap/status`` endpoint reported ``egress_blocked: true``.

This module closes that gap with a single, central, defense-in-depth control:
under enforced mode it wraps ``socket.socket.connect`` / ``connect_ex`` so that
any TCP/UDP connection to a **public** address is refused at the socket layer,
regardless of which library opened it.  Loopback and RFC1918 / link-list /
CGNAT (internal SCIF network) destinations are allowed — a SCIF has zero
*internet* egress, but the app still talks to local DBs and internal services.

The guard is OFF by default and only installs when explicitly requested
(``install_egress_guard()`` is called from the enforced-mode boot block), so it
can never affect normal or test runs that do not set the env var.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from typing import Optional

logger = logging.getLogger(__name__)

# Sentinels recording the original (unwrapped) socket methods so the guard is
# idempotent and reversible.
_ORIG_CONNECT = None
_ORIG_CONNECT_EX = None
_INSTALLED = False


class EgressBlockedError(OSError):
    """Raised when an outbound connection to a public address is refused."""


def _is_internal_ip(ip: str) -> bool:
    """Return True for addresses that are allowed under enforced air-gap.

    Allowed = anything that is NOT routable public internet:
      * loopback (127.0.0.0/8, ::1)
      * RFC1918 private (10/8, 172.16/12, 192.168/16) + IPv6 ULA (fc00::/7)
      * link-local (169.254/16, fe80::/10)
      * CGNAT shared address space (100.64/10)
      * unspecified / reserved / multicast (not public unicast egress)
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        # Not an IP literal (e.g. a hostname slipped through unresolved). Treat
        # as NON-internal so it is blocked — under enforced air-gap an
        # unresolved public hostname must not connect.
        return False
    if addr.is_loopback or addr.is_private or addr.is_link_local:
        return True
    if addr.is_unspecified or addr.is_reserved or addr.is_multicast:
        return True
    # 100.64.0.0/10 (CGNAT) is not flagged is_private by ipaddress; allow it as
    # internal SCIF address space.
    try:
        if addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):
            return True
    except ValueError:  # pragma: no cover - defensive
        pass
    return False


def _extract_host(address) -> Optional[str]:
    """Pull the host/IP out of a connect() address argument.

    AF_INET → (host, port); AF_INET6 → (host, port, flow, scope).
    AF_UNIX → str path (always allowed, returns None).
    """
    if isinstance(address, (tuple, list)) and address:
        return str(address[0])
    return None  # AF_UNIX path or unknown family — allowed


def _check(address) -> None:
    host = _extract_host(address)
    if host is None:
        return  # AF_UNIX / unknown — not an internet egress vector
    if _is_internal_ip(host):
        return
    logger.warning(
        "airgap(enforced): blocked outbound connection to public address %s", host
    )
    raise EgressBlockedError(
        f"FIXOPS_AIRGAP_MODE=enforced: outbound connection to public address "
        f"{host!r} refused by egress guard (SPEC-005)."
    )


def install_egress_guard() -> bool:
    """Install the socket-level egress guard. Idempotent. Returns True if active."""
    global _ORIG_CONNECT, _ORIG_CONNECT_EX, _INSTALLED
    if _INSTALLED:
        return True

    _ORIG_CONNECT = socket.socket.connect
    _ORIG_CONNECT_EX = socket.socket.connect_ex

    def _guarded_connect(self, address):  # noqa: ANN001
        _check(address)
        return _ORIG_CONNECT(self, address)

    def _guarded_connect_ex(self, address):  # noqa: ANN001
        _check(address)
        return _ORIG_CONNECT_EX(self, address)

    socket.socket.connect = _guarded_connect  # type: ignore[assignment]
    socket.socket.connect_ex = _guarded_connect_ex  # type: ignore[assignment]
    _INSTALLED = True
    logger.warning(
        "airgap(enforced): socket egress guard INSTALLED — public internet "
        "egress is blocked; loopback/RFC1918/link-local allowed."
    )
    return True


def uninstall_egress_guard() -> None:
    """Restore the original socket methods (used by tests / mode changes)."""
    global _INSTALLED
    if not _INSTALLED:
        return
    if _ORIG_CONNECT is not None:
        socket.socket.connect = _ORIG_CONNECT  # type: ignore[assignment]
    if _ORIG_CONNECT_EX is not None:
        socket.socket.connect_ex = _ORIG_CONNECT_EX  # type: ignore[assignment]
    _INSTALLED = False


def is_egress_guard_installed() -> bool:
    """Return True when the active socket-level egress guard is in place."""
    return _INSTALLED


def maybe_install_for_airgap() -> bool:
    """Install the guard iff FIXOPS_AIRGAP_MODE=enforced. Returns guard state."""
    if os.environ.get("FIXOPS_AIRGAP_MODE", "").strip().lower() == "enforced":
        return install_egress_guard()
    return False
