import requests
import json

BASE = "http://host.docker.internal:8000"

def report(label, resp):
    print(f"\n{'='*60}")
    print(f"[{label}]")
    print(f"  Status: {resp.status_code}")
    try:
        body = resp.json()
        print(f"  Body:   {json.dumps(body, indent=2)[:1500]}")
    except Exception:
        print(f"  Body:   {resp.text[:800]}")

# -------------------------------------------------------
# a) Health check
# -------------------------------------------------------
print("\n### HEALTH CHECKS ###")
for path in ["/api/v1/health", "/health", "/api/health"]:
    try:
        r = requests.get(BASE + path, timeout=5)
        report(f"GET {path}", r)
    except Exception as e:
        print(f"\n[GET {path}] ERROR: {e}")

# -------------------------------------------------------
# b) POST /api/v1/dast/scan WITHOUT authentication
# -------------------------------------------------------
print("\n### DAST SCAN WITHOUT AUTH ###")
try:
    r = requests.post(BASE + "/api/v1/dast/scan",
                      json={"target_url": "http://example.com"},
                      timeout=5)
    report("POST /api/v1/dast/scan (no auth)", r)
except Exception as e:
    print(f"\n[POST /api/v1/dast/scan] ERROR: {e}")

# -------------------------------------------------------
# c) Register a test user
# -------------------------------------------------------
print("\n### REGISTRATION ###")
reg_paths = [
    ("POST", "/api/v1/auth/register"),
    ("POST", "/api/v1/auth/signup"),
    ("POST", "/api/v1/users/register"),
    ("GET",  "/api/v1/auth/register"),
]
for method, path in reg_paths:
    try:
        if method == "POST":
            r = requests.post(BASE + path,
                              json={"username": "testuser",
                                    "email": "test@example.com",
                                    "password": "Test1234!"},
                              timeout=5)
        else:
            r = requests.get(BASE + path, timeout=5)
        report(f"{method} {path}", r)
    except Exception as e:
        print(f"\n[{method} {path}] ERROR: {e}")

# -------------------------------------------------------
# d) Login with common credentials
# -------------------------------------------------------
print("\n### LOGIN ATTEMPTS ###")
login_cred_sets = [
    {"username": "admin",            "password": "admin"},
    {"username": "admin",            "password": "password"},
    {"username": "admin",            "password": "admin123"},
    {"email": "admin@example.com",   "password": "admin"},
    {"email": "admin@fixops.io",     "password": "admin"},
    {"username": "testuser",         "password": "Test1234!"},
    {"email": "test@example.com",    "password": "Test1234!"},
]
token = None
for path in ["/api/v1/auth/login", "/api/v1/auth/token", "/api/v1/login"]:
    for creds in login_cred_sets:
        try:
            r = requests.post(BASE + path, json=creds, timeout=5)
            report(f"POST {path} creds={json.dumps(creds)}", r)
            if r.status_code == 200:
                data = r.json()
                candidate = data.get("access_token") or data.get("token") or data.get("jwt")
                if candidate:
                    token = candidate
                    print(f"  >>> TOKEN OBTAINED: {token[:60]}...")
                    break
        except Exception as e:
            print(f"\n[POST {path}] ERROR: {e}")
            break
    if token:
        break

# -------------------------------------------------------
# e) API Documentation
# -------------------------------------------------------
print("\n### API DOCUMENTATION ###")
for path in ["/docs", "/openapi.json", "/redoc", "/api/v1/openapi.json"]:
    try:
        r = requests.get(BASE + path, timeout=5)
        print(f"\n{'='*60}")
        print(f"[GET {path}]")
        print(f"  Status: {r.status_code}")
        if r.status_code == 200 and "application/json" in r.headers.get("content-type",""):
            try:
                doc = r.json()
                paths_list = list(doc.get("paths", {}).keys())[:30]
                print(f"  API Paths ({len(paths_list)} shown): {paths_list}")
            except Exception:
                pass
        else:
            print(f"  Body snippet: {r.text[:400].replace(chr(10),' ')}")
    except Exception as e:
        print(f"\n[GET {path}] ERROR: {e}")

# -------------------------------------------------------
# f) API Key creation with write:integrations scope
# -------------------------------------------------------
print("\n### API KEY ENDPOINTS ###")
headers_auth = {"Authorization": f"Bearer {token}"} if token else {}
headers_note = "with auth" if token else "WITHOUT auth"

for path in ["/api/v1/api-keys", "/api/v1/apikeys", "/api/v1/auth/api-keys",
             "/api/v1/integrations/api-keys"]:
    try:
        r = requests.get(BASE + path, headers=headers_auth, timeout=5)
        report(f"GET {path} ({headers_note})", r)
    except Exception as e:
        print(f"\n[GET {path}] ERROR: {e}")
    try:
        r2 = requests.post(BASE + path,
                           json={"name": "test-key", "scopes": ["write:integrations"]},
                           headers=headers_auth, timeout=5)
        report(f"POST {path} scopes=[write:integrations] ({headers_note})", r2)
    except Exception as e:
        print(f"\n[POST {path}] ERROR: {e}")

# -------------------------------------------------------
# Summary
# -------------------------------------------------------
print("\n### SUMMARY ###")
print(f"  Token obtained: {'YES - ' + token[:40] + '...' if token else 'NO'}")
