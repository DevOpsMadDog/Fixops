"""Test P4.2: GitHub webhook integration."""
import json
import urllib.request

API = "http://localhost:8000"


def post(path, payload, headers):
    req = urllib.request.Request(
        f"{API}{path}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    return json.loads(urllib.request.urlopen(req).read())


# Test 1: Push event
print("=== Test 1: GitHub Push Webhook ===")
resp = post("/api/v1/webhooks/github", {
    "ref": "refs/heads/main",
    "before": "abc123",
    "after": "def456",
    "repository": {"full_name": "acme-corp/web-app", "id": 12345},
    "sender": {"login": "dev-user"},
    "commits": [{
        "id": "def456",
        "message": "fix: update dependency",
        "added": ["package-lock.json"],
        "modified": ["package.json", "src/auth.ts"],
        "removed": [],
    }],
    "head_commit": {"id": "def456", "message": "fix: update dependency"},
}, {"X-GitHub-Event": "push", "X-GitHub-Delivery": "test-001"})
print(f"  Status: {resp['status']}")
print(f"  Event type: {resp['event_type']}")
print(f"  Repository: {resp['repository']}")
print(f"  Changed files: {resp['changed_files_count']}")
print(f"  Pipeline triggered: {resp['pipeline_triggered']}")
assert resp["status"] == "received"
assert resp["event_type"] == "push"
assert resp["changed_files_count"] == 3
print("  PASS")

# Test 2: PR event (opened)
print("\n=== Test 2: GitHub PR Opened Webhook ===")
resp2 = post("/api/v1/webhooks/github", {
    "action": "opened",
    "repository": {"full_name": "acme-corp/web-app", "id": 12345},
    "sender": {"login": "dev-user"},
    "pull_request": {
        "number": 42,
        "title": "Fix XSS vulnerability",
        "head": {"ref": "fix/xss-vuln", "sha": "aaa111bbb222"},
        "base": {"ref": "main"},
        "state": "open",
    },
}, {"X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "test-002"})
print(f"  Status: {resp2['status']}")
print(f"  Event type: {resp2['event_type']}")
print(f"  Pipeline triggered: {resp2['pipeline_triggered']}")
assert resp2["status"] == "received"
assert resp2["event_type"] == "pull_request"
print("  PASS")

# Test 3: Ping event (no pipeline trigger)
print("\n=== Test 3: GitHub Ping Webhook ===")
resp3 = post("/api/v1/webhooks/github", {
    "repository": {"full_name": "acme-corp/web-app"},
    "sender": {"login": "github"},
}, {"X-GitHub-Event": "ping", "X-GitHub-Delivery": "test-003"})
print(f"  Status: {resp3['status']}")
print(f"  Pipeline triggered: {resp3['pipeline_triggered']}")
assert resp3["pipeline_triggered"] is False
print("  PASS")

print("\n=== P4.2 GITHUB WEBHOOK INTEGRATION COMPLETE ===")

