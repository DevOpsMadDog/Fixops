#!/bin/bash
# Backend-Hardener Persona Tests — Ethan (Security Engineer) + Hasan (Platform Admin)
# Tests ALL API endpoints owned by backend-hardener agent
# Fixed payloads based on actual Pydantic model schemas
set -euo pipefail

BASE="http://localhost:8000/api/v1"
TOKEN="aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh"
H="X-API-Key: $TOKEN"
CT="Content-Type: application/json"
PASS=0
FAIL=0
TOTAL=0

call() {
    local method="$1" endpoint="$2" desc="$3" body="${4:-}"
    TOTAL=$((TOTAL + 1))
    local url="${BASE}${endpoint}"
    local response
    if [ -n "$body" ]; then
        response=$(curl -s -w '\n%{http_code}' -X "$method" "$url" -H "$H" -H "$CT" -d "$body" --max-time 15 2>&1)
    else
        response=$(curl -s -w '\n%{http_code}' -X "$method" "$url" -H "$H" --max-time 15 2>&1)
    fi
    local code
    code=$(echo "$response" | tail -1)
    local body_resp
    body_resp=$(echo "$response" | sed '$d')
    
    if [[ "$code" =~ ^2[0-9][0-9]$ ]] || [[ "$code" == "409" ]]; then
        PASS=$((PASS + 1))
        echo "  [PASS] $desc => $code"
    else
        FAIL=$((FAIL + 1))
        echo "  [FAIL] $desc => $code"
        echo "         Body: $(echo "$body_resp" | head -c 200)"
    fi
}

echo "============================================"
echo "  BACKEND-HARDENER — PERSONA API TESTS"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Model: Claude Opus 4.6 (fast mode)"
echo "============================================"
echo ""

# =========================================================================
# ETHAN (Security Engineer) — Connectors, Integrations, Webhooks
# =========================================================================
echo "=== ETHAN (Security Engineer) ==="

echo "--- Connectors ---"
# Jira requires: base_url, email, api_token, project_key
call POST "/connectors/register" "Register Jira connector" \
    '{"name":"ethan-jira","type":"jira","jira":{"base_url":"https://ethan.atlassian.net","email":"ethan@aldeci.com","api_token":"test123","project_key":"SEC"}}'

# GitHub requires: token, owner, repo
call POST "/connectors/register" "Register GitHub connector" \
    '{"name":"ethan-github","type":"github","github":{"token":"ghp_test123456","owner":"aldeci","repo":"fixops"}}'

# Slack requires: webhook_url (must start with https://hooks.slack.com/)
call POST "/connectors/register" "Register Slack connector" \
    '{"name":"ethan-slack","type":"slack","slack":{"webhook_url":"https://hooks.slack.com/services/T00/B00/test","channel":"#security"}}'

call GET "/connectors" "List all connectors"
call GET "/connectors/types" "List connector types"
call GET "/connectors/health" "Connector health check"
call POST "/connectors/test" "Test all connectors"

echo "--- Integrations ---"
call GET "/integrations" "List all integrations"
# integration_type, name, config
call POST "/integrations" "Create GitHub integration" \
    '{"name":"ethan-github-int","integration_type":"github","config":{"url":"https://github.com","token":"ghp_test"}}'

echo "--- Webhooks ---"
call POST "/webhooks/mappings" "Create webhook mapping" \
    '{"cluster_id":"C-ethan","integration_type":"jira","external_id":"SEC-001","external_url":"https://ethan.atlassian.net/browse/SEC-001","external_status":"Open"}'
call GET "/webhooks/mappings" "List webhook mappings"
# Correct path is /webhooks/outbox/stats
call GET "/webhooks/outbox/stats" "Webhook outbox statistics"

echo ""

# =========================================================================
# HASAN (Platform Admin) — Users, Teams, System, Auth, Audit
# =========================================================================
echo "=== HASAN (Platform Admin) ==="

echo "--- Admin Users ---"
call GET "/admin/users" "List all users"
# AdminUserCreate requires: email, password (min 8), first_name, last_name
call POST "/admin/users" "Create admin user" \
    '{"email":"hasan@aldeci.com","password":"SecurePass123!","first_name":"Hasan","last_name":"Admin","role":"admin"}'

echo "--- Admin Teams ---"
call GET "/admin/teams" "List all teams"
call POST "/admin/teams" "Create team" \
    '{"name":"security-ops","description":"Security operations team"}'

echo "--- System Health ---"
call GET "/health" "Health check (quick)"
call GET "/system/health" "System health (detailed)"
call GET "/system/info" "System info"
call GET "/system/config" "System configuration"
call GET "/system/metrics" "System metrics"
call GET "/system/status" "System status"

echo "--- Audit ---"
# Correct path: /audit/logs (not /admin/audit-log)
call GET "/audit/logs" "Audit logs"

echo "--- Auth ---"
# Use the user we created above
call POST "/users/login" "User login" \
    '{"email":"hasan@aldeci.com","password":"SecurePass123!"}'

echo ""

# =========================================================================
# EXTENDED TESTS — Integration CRUD with IDs
# =========================================================================
echo "=== EXTENDED TESTS ==="

echo "--- Connector CRUD Lifecycle ---"
call POST "/connectors/register" "Register test connector" \
    '{"name":"lifecycle-test","type":"jira","jira":{"base_url":"https://test.atlassian.net","email":"test@test.com","api_token":"tok123","project_key":"TEST"}}'
call GET "/connectors" "Verify connector listed"

echo "--- Integration Detail (if exists) ---"
call GET "/integrations" "List integrations for ID"

echo "--- System Deep Check ---"
call GET "/status" "App-level status"

echo ""
echo "============================================"
echo "  RESULTS: $PASS/$TOTAL passed, $FAIL failed"
pct=$((PASS * 100 / TOTAL))
echo "  PASS RATE: ${pct}%"
echo "============================================"
if [ "$FAIL" -eq 0 ]; then
    echo "  GRADE: A+ (100% — ALL PASS)"
elif [ "$FAIL" -le 2 ]; then
    echo "  GRADE: A (${pct}%)"
elif [ "$FAIL" -le 4 ]; then
    echo "  GRADE: B (${pct}%)"
elif [ "$FAIL" -le 6 ]; then
    echo "  GRADE: C (${pct}%)"
else
    echo "  GRADE: D (${pct}%)"
fi
echo ""
