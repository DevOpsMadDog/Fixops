"""API-level tests for the Material Change Detection router.

Tests all 7 endpoints with realistic payloads to exercise the full
diff analysis pipeline through the API layer.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-api"))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.material_change_router import router


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


AUTH_DIFF = """\
diff --git a/auth/login.py b/auth/login.py
--- a/auth/login.py
+++ b/auth/login.py
@@ -10,6 +10,8 @@ def login(username, password):
     user = db.find_user(username)
-        if user.check_password(password):
+        if password == "admin":
+            return True
+        elif user.check_password(password):
             return create_session(user)
"""

CRYPTO_DIFF = """\
diff --git a/crypto/utils.py b/crypto/utils.py
--- a/crypto/utils.py
+++ b/crypto/utils.py
@@ -5,3 +5,4 @@ import hashlib
 def hash_password(pw):
-    return hashlib.sha256(pw.encode()).hexdigest()
+    return hashlib.md5(pw.encode()).hexdigest()
+    # Note: downgraded to MD5 for speed
"""

INFRA_DIFF = """\
diff --git a/deploy/main.tf b/deploy/main.tf
--- a/deploy/main.tf
+++ b/deploy/main.tf
@@ -5,3 +5,5 @@ resource "aws_security_group" "web" {
   ingress {
-    cidr_blocks = ["10.0.0.0/8"]
+    cidr_blocks = ["0.0.0.0/0"]
   }
+  publicly_accessible = true
"""

SECRETS_DIFF = """\
diff --git a/config.py b/config.py
new file mode 100644
--- /dev/null
+++ b/config.py
@@ -0,0 +1,3 @@
+API_KEY = "sk-1234567890abcdef"
+password = "supersecretpassword"
+AKIA1234567890123456
"""

JS_DIFF = """\
diff --git a/app.js b/app.js
--- a/app.js
+++ b/app.js
@@ -10,3 +10,5 @@ const express = require('express');
 app.get('/search', (req, res) => {
+  document.write(req.query.q);
+  eval(req.query.q);
   res.send(results);
"""

DEPENDENCY_DIFF = """\
diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,3 +1,3 @@
-flask==2.0.0
+flask==1.0.0
 requests>=2.28
+log4j==2.14.0
"""


class TestAnalyzeDiff:
    def test_auth_change(self, client):
        r = client.post("/api/v1/changes/analyze-diff", json={"diff": AUTH_DIFF})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, (dict, list))

    def test_crypto_change(self, client):
        r = client.post("/api/v1/changes/analyze-diff", json={"diff": CRYPTO_DIFF})
        assert r.status_code == 200

    def test_infra_change(self, client):
        r = client.post("/api/v1/changes/analyze-diff", json={"diff": INFRA_DIFF})
        assert r.status_code == 200

    def test_secrets_change(self, client):
        r = client.post("/api/v1/changes/analyze-diff", json={"diff": SECRETS_DIFF})
        assert r.status_code == 200

    def test_js_xss_change(self, client):
        r = client.post("/api/v1/changes/analyze-diff", json={"diff": JS_DIFF})
        assert r.status_code == 200

    def test_empty_diff(self, client):
        r = client.post("/api/v1/changes/analyze-diff", json={"diff": ""})
        assert r.status_code in (200, 422)

    def test_dependency_change(self, client):
        r = client.post("/api/v1/changes/analyze-diff", json={"diff": DEPENDENCY_DIFF})
        assert r.status_code == 200


class TestAnalyzePR:
    def test_single_file(self, client):
        r = client.post("/api/v1/changes/analyze-pr", json={
            "pr_id": "PR-100",
            "repo": "test-org/test-repo",
            "file_diffs": [{"path": "auth/login.py", "diff": AUTH_DIFF}]
        })
        assert r.status_code == 200
        data = r.json()
        assert "pr_id" in data or isinstance(data, dict)

    def test_multi_file(self, client):
        r = client.post("/api/v1/changes/analyze-pr", json={
            "pr_id": "PR-200",
            "repo": "test-org/test-repo",
            "file_diffs": [
                {"path": "auth/login.py", "diff": AUTH_DIFF},
                {"path": "deploy/main.tf", "diff": INFRA_DIFF},
                {"path": "crypto/utils.py", "diff": CRYPTO_DIFF},
            ]
        })
        assert r.status_code == 200

    def test_pr_with_secrets(self, client):
        r = client.post("/api/v1/changes/analyze-pr", json={
            "pr_id": "PR-300",
            "repo": "test-org/test-repo",
            "file_diffs": [
                {"path": "config.py", "diff": SECRETS_DIFF},
            ]
        })
        assert r.status_code == 200

    def test_empty_file_diffs(self, client):
        r = client.post("/api/v1/changes/analyze-pr", json={
            "pr_id": "PR-400",
            "repo": "test-org/test-repo",
            "file_diffs": []
        })
        assert r.status_code in (200, 422)


class TestClassify:
    def test_classify_auth(self, client):
        r = client.post("/api/v1/changes/classify", json={
            "file_diffs": [{"path": "auth.py", "diff": AUTH_DIFF}]
        })
        assert r.status_code == 200

    def test_classify_mixed(self, client):
        r = client.post("/api/v1/changes/classify", json={
            "file_diffs": [
                {"path": "auth.py", "diff": AUTH_DIFF},
                {"path": "deploy.tf", "diff": INFRA_DIFF}
            ]
        })
        assert r.status_code == 200


class TestReviewChecklist:
    def test_auth_checklist(self, client):
        r = client.post("/api/v1/changes/review-checklist", json={
            "categories": ["auth"],
            "file_diffs": [{"path": "auth.py", "diff": AUTH_DIFF}]
        })
        assert r.status_code == 200

    def test_multi_category_checklist(self, client):
        r = client.post("/api/v1/changes/review-checklist", json={
            "categories": ["auth", "crypto", "data_flow", "infrastructure"],
            "file_diffs": [{"path": "auth.py", "diff": AUTH_DIFF}]
        })
        assert r.status_code == 200


class TestVelocity:
    def test_get_velocity(self, client):
        r = client.get("/api/v1/changes/velocity/test-repo")
        assert r.status_code in (200, 404)

    def test_get_velocity_nested_path(self, client):
        r = client.get("/api/v1/changes/velocity/org/repo-name")
        assert r.status_code in (200, 404)


class TestRiskProfile:
    def test_get_risk_profile(self, client):
        r = client.get("/api/v1/changes/risk-profile/test-repo")
        assert r.status_code in (200, 404)


class TestHealth:
    def test_health(self, client):
        r = client.get("/api/v1/changes/health")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, dict)
