#!/bin/bash
H="X-API-Key: test-token-123"
CT="Content-Type: application/json"
BASE="http://localhost:8000/api/v1/vulns/discovered"

echo "=== Seeding Discovered Vulnerabilities ==="

# 1. SQL Injection
curl -s -X POST -H "$H" -H "$CT" "$BASE" -d '{"title":"SQL Injection in User Login Endpoint","description":"Discovered during manual penetration testing - user input in login form is not properly sanitized allowing SQL injection attacks that can bypass authentication and extract sensitive data.","severity":"critical","impact_type":"sql_injection","attack_vector":"network","discovery_source":"pentest_manual","discovered_by":"ALdeci Red Team","discovered_date":"2026-02-08T10:00:00Z","affected_components":[{"vendor":"acme-corp","product":"web-portal","version":"2.3.1"}],"affected_versions":"< 2.4.0","cvss_score":10.0,"internal_only":true}' | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'1. SQL Injection -> {d.get(\"vuln_id\",d.get(\"detail\",\"?\"))}')" 2>&1

# 2. RCE
curl -s -X POST -H "$H" -H "$CT" "$BASE" -d '{"title":"Remote Code Execution via Deserialization","description":"Unsafe deserialization of user-controlled input in the message queue consumer allows arbitrary code execution on the application server with service account privileges.","severity":"critical","impact_type":"remote_code_execution","attack_vector":"network","discovery_source":"pentest_automated","discovered_by":"ALdeci MPTE","discovered_date":"2026-02-07T14:30:00Z","affected_components":[{"vendor":"acme-corp","product":"message-processor","version":"1.8.0"}],"affected_versions":"1.5.0 - 1.8.2","cvss_score":9.8,"internal_only":true}' | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'2. RCE -> {d.get(\"vuln_id\",d.get(\"detail\",\"?\"))}')" 2>&1

# 3. XSS
curl -s -X POST -H "$H" -H "$CT" "$BASE" -d '{"title":"Stored XSS in User Profile Bio Field","description":"The user profile biography field does not sanitize HTML input allowing attackers to inject malicious JavaScript that executes when other users view the profile enabling session hijacking.","severity":"high","impact_type":"cross_site_scripting","attack_vector":"network","discovery_source":"code_review","discovered_by":"Security Code Review","discovered_date":"2026-02-06T09:15:00Z","affected_components":[{"vendor":"acme-corp","product":"user-service","version":"3.2.0"}],"affected_versions":"< 3.3.0","cvss_score":7.5,"internal_only":true}' | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'3. XSS -> {d.get(\"vuln_id\",d.get(\"detail\",\"?\"))}')" 2>&1

# 4. SSRF
curl -s -X POST -H "$H" -H "$CT" "$BASE" -d '{"title":"Server-Side Request Forgery in Image Proxy","description":"The image proxy endpoint accepts arbitrary URLs without validation allowing attackers to scan internal networks access cloud metadata endpoints and exfiltrate internal service data from the cluster.","severity":"high","impact_type":"server_side_request_forgery","attack_vector":"network","discovery_source":"bug_bounty","discovered_by":"Bug Bounty Reporter 4421","discovered_date":"2026-02-05T16:45:00Z","affected_components":[{"vendor":"acme-corp","product":"media-service","version":"1.1.0"}],"affected_versions":"< 1.2.0","cvss_score":8.1,"internal_only":false,"notify_vendor":true}' | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'4. SSRF -> {d.get(\"vuln_id\",d.get(\"detail\",\"?\"))}')" 2>&1

# 5. IDOR
curl -s -X POST -H "$H" -H "$CT" "$BASE" -d '{"title":"Privilege Escalation via IDOR in Admin API","description":"The admin API endpoints use predictable sequential IDs without proper authorization checks so any authenticated user can modify other users accounts by changing the user ID parameter.","severity":"high","impact_type":"insecure_direct_object_reference","attack_vector":"network","discovery_source":"pentest_manual","discovered_by":"ALdeci Red Team","discovered_date":"2026-02-04T11:20:00Z","affected_components":[{"vendor":"acme-corp","product":"admin-api","version":"4.0.1"}],"affected_versions":"3.0.0 - 4.0.1","cvss_score":8.8,"internal_only":true}' | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'5. IDOR -> {d.get(\"vuln_id\",d.get(\"detail\",\"?\"))}')" 2>&1

# 6. Auth Bypass
curl -s -X POST -H "$H" -H "$CT" "$BASE" -d '{"title":"Authentication Bypass in JWT Validation","description":"The JWT token validation accepts tokens signed with the none algorithm so an attacker can forge arbitrary JWT tokens without knowing the signing key and gain access to any account.","severity":"critical","impact_type":"authentication_bypass","attack_vector":"network","discovery_source":"fuzzing","discovered_by":"ALdeci Fuzzing Engine","discovered_date":"2026-02-03T08:00:00Z","affected_components":[{"vendor":"acme-corp","product":"auth-gateway","version":"2.0.0"}],"affected_versions":"< 2.1.0","cvss_score":9.1,"internal_only":true}' | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'6. AuthBypass -> {d.get(\"vuln_id\",d.get(\"detail\",\"?\"))}')" 2>&1

echo ""
echo "=== Verifying seeded data ==="
curl -s -H "$H" "$BASE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Total discovered vulns: {len(d)}')" 2>&1

