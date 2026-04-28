"""SSRF protection utilities for ALDECI webhook and callback endpoints.

Provides:
- validate_url(url) — reject internal/private IPs and dangerous schemes
- validate_url_with_dns(url) — resolve DNS then validate resolved IP
- is_private_ip(ip) → bool — check RFC1918/RFC5737/link-local ranges
- sanitize_redirect_url(url, allowed_domains) — for SSO redirects

Raises SSRFError on violation.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import List
from urllib.parse import urlparse

from core.exceptions import SSRFError

# ---------------------------------------------------------------------------
# Private / reserved IP ranges (RFC1918, RFC5737, link-local, loopback, etc.)
# ---------------------------------------------------------------------------

_PRIVATE_NETWORKS = [
    # Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    # Link-local
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    # RFC1918 private ranges
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # RFC5737 documentation ranges
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    # Unspecified / any
    ipaddress.ip_network("0.0.0.0/8"),
    # Multicast
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
    # Unique local (IPv6 private)
    ipaddress.ip_network("fc00::/7"),
    # IPv4-mapped IPv6 private ranges are handled via unwrapping below
]

# Hostnames that should never be resolved/contacted
_BLOCKED_HOSTNAMES = frozenset(
    [
        "localhost",
        "metadata.google.internal",
        "169.254.169.254",  # AWS/GCP/Azure IMDS
        "metadata.azure.com",
        "100.100.100.200",  # Alibaba IMDS
    ]
)

# Allowed URL schemes for webhook targets
_ALLOWED_SCHEMES = frozenset(["http", "https"])

# Decimal/hex/octal IP pattern helpers
_DECIMAL_IP_RE = re.compile(r"^(\d+)$")  # e.g. 2130706433 → 127.0.0.1
_HEX_IP_RE = re.compile(r"^0x[0-9a-fA-F]+$")


def is_private_ip(ip: str) -> bool:
    """Return True if *ip* falls within any private/reserved range.

    Handles:
    - Standard IPv4 dotted notation
    - IPv6 addresses
    - IPv4-mapped IPv6 (::ffff:10.0.0.1)
    - Decimal integer IPs (2130706433 → 127.0.0.1)
    - Hex IPs (0x7f000001 → 127.0.0.1)
    """
    ip = ip.strip().lower()

    # Decimal integer IP (e.g. 2130706433)
    if _DECIMAL_IP_RE.match(ip):
        try:
            addr = ipaddress.ip_address(int(ip))
            return _is_addr_private(addr)
        except (ValueError, OverflowError):
            return True  # Malformed — treat as private to be safe

    # Hex IP (e.g. 0x7f000001)
    if _HEX_IP_RE.match(ip):
        try:
            addr = ipaddress.ip_address(int(ip, 16))
            return _is_addr_private(addr)
        except (ValueError, OverflowError):
            return True

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        # Not a parseable IP — caller should have validated hostname separately
        return False

    return _is_addr_private(addr)


def _is_addr_private(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check an ip_address object against all private networks."""
    # Unwrap IPv4-mapped IPv6 addresses
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    for net in _PRIVATE_NETWORKS:
        if addr in net:
            return True

    # Python's built-in checks as a backstop
    if addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_reserved:
        return True

    return False


def _parse_and_basic_check(url: str) -> tuple[str, str]:
    """Parse URL and return (scheme, hostname). Raises SSRFError on basic violations."""
    if not url or not url.strip():
        raise SSRFError("URL must not be empty")

    url = url.strip()

    # Reject double-encoded schemes (e.g. http%3A%2F%2F)
    if "%" in url:
        from urllib.parse import unquote
        url_decoded = unquote(url)
        if url_decoded != url:
            # Re-parse decoded version to catch double-encoding bypass
            url = url_decoded

    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise SSRFError(f"Malformed URL: {exc}") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise SSRFError(
            f"URL scheme '{scheme}' is not allowed. Only http and https are permitted."
        )

    hostname = (parsed.hostname or "").lower().rstrip(".")

    if not hostname:
        raise SSRFError("URL must contain a valid hostname")

    # Strip brackets from IPv6 literals
    if hostname.startswith("[") and hostname.endswith("]"):
        hostname = hostname[1:-1]

    # Block known dangerous hostnames
    if hostname in _BLOCKED_HOSTNAMES:
        raise SSRFError(f"Hostname '{hostname}' is explicitly blocked (internal/metadata endpoint)")

    # Block variations of localhost
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise SSRFError(f"Hostname '{hostname}' resolves to loopback and is blocked")

    return scheme, hostname


def validate_url(url: str) -> str:
    """Validate *url* for SSRF safety without performing DNS resolution.

    Checks:
    - Scheme is http or https
    - Hostname is not a known internal/metadata endpoint
    - Hostname is not a raw private/loopback/link-local IP
    - URL is not double-encoded to bypass checks

    Returns the (possibly decoded) URL on success.
    Raises SSRFError on any violation.
    """
    scheme, hostname = _parse_and_basic_check(url)

    # If the hostname looks like a raw IP address, validate it directly
    try:
        addr = ipaddress.ip_address(hostname)
        if _is_addr_private(addr):
            raise SSRFError(
                f"URL target '{hostname}' is a private/reserved IP address and is blocked"
            )
    except ValueError:
        pass  # Not an IP literal — will need DNS resolution for full check

    # Decimal / hex IP bypasses in hostname position
    if _DECIMAL_IP_RE.match(hostname):
        if is_private_ip(hostname):
            raise SSRFError(f"Decimal IP '{hostname}' resolves to a private address and is blocked")

    if _HEX_IP_RE.match(hostname):
        if is_private_ip(hostname):
            raise SSRFError(f"Hex IP '{hostname}' resolves to a private address and is blocked")

    return url


def validate_url_with_dns(url: str) -> str:
    """Validate *url* for SSRF safety including DNS resolution.

    Performs all checks from validate_url(), then additionally resolves the
    hostname and verifies no resolved IP falls within private ranges.

    Returns the URL on success.
    Raises SSRFError on any violation.
    """
    url = validate_url(url)

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if hostname.startswith("[") and hostname.endswith("]"):
        hostname = hostname[1:-1]

    # Skip DNS resolution for raw IP literals (already checked in validate_url)
    try:
        ipaddress.ip_address(hostname)
        return url  # Already validated above
    except ValueError:
        pass

    # DNS resolution
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFError(f"DNS resolution failed for '{hostname}': {exc}") from exc

    resolved_ips = set()
    for family, _type, _proto, _canonname, sockaddr in results:
        ip = sockaddr[0]
        resolved_ips.add(ip)

    for ip in resolved_ips:
        if is_private_ip(ip):
            raise SSRFError(
                f"DNS resolution of '{hostname}' returned private IP '{ip}' — SSRF blocked"
            )

    return url


def sanitize_redirect_url(url: str, allowed_domains: List[str]) -> str:
    """Validate a post-SSO redirect URL against an allowlist of domains.

    Rules:
    - Must be http or https
    - Must not target internal/private IPs
    - Hostname must match one of *allowed_domains* (exact or subdomain match)
    - If *allowed_domains* is empty, only relative paths (starting with /) are accepted

    Returns the URL on success.
    Raises SSRFError on any violation.
    """
    if not url:
        raise SSRFError("Redirect URL must not be empty")

    # Allow relative paths without domain checks
    if url.startswith("/") and not url.startswith("//"):
        # Relative path — safe by construction (no external host)
        return url

    # Full URL: apply SSRF validation first
    validate_url(url)

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")

    if not allowed_domains:
        raise SSRFError(
            "Absolute redirect URLs are not permitted when no allowed_domains are configured"
        )

    # Check hostname against allowlist (exact match or subdomain)
    for domain in allowed_domains:
        domain = domain.lower().lstrip("*").lstrip(".")
        if hostname == domain or hostname.endswith("." + domain):
            return url

    raise SSRFError(
        f"Redirect to '{hostname}' is not permitted — not in allowed_domains list"
    )
