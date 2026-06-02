"""SPEC-005 — tests for the active socket-level egress guard.

Verifies the central defense-in-depth control that blocks public-internet
egress under FIXOPS_AIRGAP_MODE=enforced while leaving loopback / internal
(RFC1918) connectivity intact.
"""

import socket

import pytest

from core.egress_guard import (
    EgressBlockedError,
    _is_internal_ip,
    install_egress_guard,
    is_egress_guard_installed,
    uninstall_egress_guard,
)


@pytest.fixture
def guard():
    """Install the guard for the test, always uninstall afterwards."""
    install_egress_guard()
    try:
        yield
    finally:
        uninstall_egress_guard()


# ---------------------------------------------------------------------------
# Address classification
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ip", [
    "127.0.0.1", "127.5.5.5", "::1",
    "10.0.0.1", "172.16.0.1", "192.168.1.1",
    "169.254.1.1", "fe80::1", "fc00::1",
    "100.64.0.1",  # CGNAT shared space
])
def test_internal_addresses_allowed(ip):
    assert _is_internal_ip(ip) is True


@pytest.mark.parametrize("ip", [
    "8.8.8.8",        # Google DNS
    "1.1.1.1",        # Cloudflare
    "151.101.0.223",  # PyPI/Fastly
    "140.82.112.3",   # GitHub
    "2606:4700:4700::1111",  # Cloudflare v6
])
def test_public_addresses_classified_external(ip):
    assert _is_internal_ip(ip) is False


def test_unresolved_hostname_is_blocked_by_default():
    # A hostname that slipped through unresolved must be treated as external.
    assert _is_internal_ip("evil.example.com") is False


# ---------------------------------------------------------------------------
# Install / uninstall lifecycle
# ---------------------------------------------------------------------------

def test_install_uninstall_idempotent():
    assert is_egress_guard_installed() is False
    install_egress_guard()
    assert is_egress_guard_installed() is True
    install_egress_guard()  # idempotent
    assert is_egress_guard_installed() is True
    uninstall_egress_guard()
    assert is_egress_guard_installed() is False
    uninstall_egress_guard()  # idempotent
    assert is_egress_guard_installed() is False


# ---------------------------------------------------------------------------
# Enforcement behaviour
# ---------------------------------------------------------------------------

def test_public_connect_refused_when_installed(guard):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises((EgressBlockedError, OSError)) as exc:
            s.connect(("8.8.8.8", 443))
        assert "egress guard" in str(exc.value).lower() or "refused" in str(exc.value).lower()
    finally:
        s.close()


def test_loopback_connect_not_refused_by_guard(guard):
    # Connecting to a closed loopback port raises ConnectionRefusedError from
    # the OS — NOT our EgressBlockedError. That proves the guard let it through.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    try:
        with pytest.raises(OSError) as exc:
            s.connect(("127.0.0.1", 59999))  # almost certainly nothing listening
        assert not isinstance(exc.value, EgressBlockedError)
    finally:
        s.close()


def test_no_guard_when_not_installed():
    # With the guard uninstalled, classification still works but connect() is
    # not intercepted (the method is the original).
    assert is_egress_guard_installed() is False
