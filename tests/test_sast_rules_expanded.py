"""
Comprehensive tests for ALdeci SAST Engine expanded rules (SAST-001 to SAST-110).

Tests validate:
1. Rule count and structure (110 rules, 10/10 OWASP categories)
2. Detection of real vulnerability patterns across all OWASP Top 10 categories
3. False positive resistance — safe code should not trigger rules
4. Multi-language support (Python, JavaScript, Java, Go, Ruby, PHP)
5. Taint flow analysis
6. OWASP category reporting

Written by security-analyst for P1 competitive moat mission.
Pillar: V3 — Decision Intelligence (native SAST credibility)
"""

import os
import sys

import pytest

# Ensure suite paths
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.sast_engine import (
    OWASP_CATEGORIES,
    SAST_RULES,
    SASTEngine,
)


# ── Fixtures ──────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def engine():
    return SASTEngine()


# ══════════════════════════════════════════════════════════════════
# Rule Structure & Coverage Tests
# ══════════════════════════════════════════════════════════════════


class TestRuleStructure:
    """Verify rule definitions are well-formed."""

    def test_rule_count_at_least_100(self):
        assert len(SAST_RULES) >= 100, f"Expected 100+ rules, got {len(SAST_RULES)}"

    def test_rule_count_exact(self):
        assert len(SAST_RULES) == 110

    def test_no_duplicate_ids(self):
        ids = [r[0] for r in SAST_RULES]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {[x for x in ids if ids.count(x) > 1]}"

    def test_all_rules_have_8_fields(self):
        for rule in SAST_RULES:
            assert len(rule) == 8, f"Rule {rule[0]} has {len(rule)} fields, expected 8"

    def test_all_severities_valid(self):
        valid = {"critical", "high", "medium", "low", "info"}
        for rule in SAST_RULES:
            assert rule[2] in valid, f"Rule {rule[0]} has invalid severity: {rule[2]}"

    def test_all_cwes_formatted(self):
        for rule in SAST_RULES:
            assert rule[3].startswith("CWE-"), f"Rule {rule[0]} CWE not formatted: {rule[3]}"

    def test_all_rules_have_languages(self):
        for rule in SAST_RULES:
            assert len(rule[7]) > 0, f"Rule {rule[0]} has no languages"

    def test_owasp_coverage_all_10(self):
        assert len(OWASP_CATEGORIES) == 10

    def test_owasp_all_rules_mapped(self):
        mapped = set()
        for rules in OWASP_CATEGORIES.values():
            mapped.update(rules)
        rule_ids = {r[0] for r in SAST_RULES}
        unmapped = rule_ids - mapped
        assert len(unmapped) == 0, f"Unmapped rules: {unmapped}"

    def test_unique_cwes_at_least_50(self):
        cwes = set(r[3] for r in SAST_RULES)
        assert len(cwes) >= 50, f"Expected 50+ CWEs, got {len(cwes)}"


class TestEngineAPI:
    """Test engine public API methods."""

    def test_get_rule_count(self, engine):
        assert engine.get_rule_count() == 110

    def test_get_owasp_coverage(self, engine):
        coverage = engine.get_owasp_coverage()
        assert coverage["total_rules"] == 110
        assert coverage["owasp_categories_covered"] == 10
        assert "categories" in coverage
        for cat in [
            "A01:BrokenAccessControl",
            "A02:CryptographicFailures",
            "A03:Injection",
        ]:
            assert cat in coverage["categories"]

    def test_findings_by_owasp_returns_all_categories(self, engine):
        result = engine.scan_code("x = 1", "test.py")
        groups = engine.get_findings_by_owasp(result)
        assert len(groups) == 10


# ══════════════════════════════════════════════════════════════════
# A01 — Broken Access Control
# ══════════════════════════════════════════════════════════════════


class TestA01BrokenAccessControl:

    def test_cors_wildcard_detected(self, engine):
        code = 'allow_origins = ["*"]'
        result = engine.scan_code(code, "app.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-019" in rules

    def test_jwt_none_algorithm(self, engine):
        code = "token = jwt.decode(data, algorithms=['none'])"
        result = engine.scan_code(code, "auth.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-021" in rules

    def test_unrestricted_file_upload(self, engine):
        code = "uploaded_file.save(filepath)"
        result = engine.scan_code(code, "upload.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-020" in rules

    def test_admin_route_flagged(self, engine):
        code = '@router.post("/admin/users")'
        result = engine.scan_code(code, "admin.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-024" in rules


# ══════════════════════════════════════════════════════════════════
# A02 — Cryptographic Failures
# ══════════════════════════════════════════════════════════════════


class TestA02CryptographicFailures:

    def test_weak_rsa_key(self, engine):
        code = "key = rsa.generate(1024)"
        result = engine.scan_code(code, "crypto.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-025" in rules

    def test_ecb_mode(self, engine):
        code = "cipher = AES.ECB(key)"
        result = engine.scan_code(code, "crypto.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-027" in rules

    def test_disabled_ssl_verify(self, engine):
        code = "requests.get(url, verify=False)"
        result = engine.scan_code(code, "client.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-028" in rules

    def test_hardcoded_encryption_key(self, engine):
        code = 'ENCRYPTION_KEY = "YWJjZGVmZ2hpamtsbW5vcHFy"'
        result = engine.scan_code(code, "config.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-031" in rules

    def test_weak_tls_version(self, engine):
        code = "ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)"
        result = engine.scan_code(code, "server.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-030" in rules

    def test_plaintext_password_comparison(self, engine):
        code = "if password == request.form['password']:"
        result = engine.scan_code(code, "auth.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-033" in rules

    def test_hardcoded_jwt_secret(self, engine):
        code = 'JWT_SECRET = "supersecretkey123"'
        result = engine.scan_code(code, "config.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-076" in rules


# ══════════════════════════════════════════════════════════════════
# A03 — Injection
# ══════════════════════════════════════════════════════════════════


class TestA03Injection:

    def test_sql_injection_fstring(self, engine):
        code = 'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")'
        result = engine.scan_code(code, "db.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-001" in rules

    def test_sql_injection_concat(self, engine):
        code = "cursor.execute(\"SELECT * FROM users WHERE id=\" + user_id)"
        result = engine.scan_code(code, "db.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-002" in rules

    def test_xss_innerhtml(self, engine):
        code = "element.innerHTML = userInput"
        result = engine.scan_code(code, "app.js")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-003" in rules

    def test_command_injection(self, engine):
        code = 'os.system("rm -rf " + request.args.get("path"))'
        result = engine.scan_code(code, "admin.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-004" in rules

    def test_nosql_injection(self, engine):
        code = 'db.find({"$where": request.args.get("query")})'
        result = engine.scan_code(code, "mongo.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-035" in rules

    def test_ssti_template_injection(self, engine):
        code = 'render_template_string(request.args.get("template"))'
        result = engine.scan_code(code, "views.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-036" in rules

    def test_xpath_injection(self, engine):
        code = 'doc.xpath("/users/user[@id=" + request.args["id"])'
        result = engine.scan_code(code, "xml_handler.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-040" in rules

    def test_react_dangerous_html(self, engine):
        code = 'return <div dangerouslySetInnerHTML={{ __html: userInput }} />'
        result = engine.scan_code(code, "Component.tsx")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-045" in rules

    def test_orm_raw_query(self, engine):
        code = 'session.text(f"SELECT * FROM {table}")'
        result = engine.scan_code(code, "models.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-046" in rules

    def test_graphql_injection(self, engine):
        code = 'client.graphql(f"query {{ user(id: {request.args[\'id\']}) }}")'
        result = engine.scan_code(code, "api.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-047" in rules

    def test_ldap_injection(self, engine):
        code = 'ldap.search("ou=users," + request.args.get("base"))'
        result = engine.scan_code(code, "ldap_auth.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-016" in rules


# ══════════════════════════════════════════════════════════════════
# A04 — Insecure Design
# ══════════════════════════════════════════════════════════════════


class TestA04InsecureDesign:

    def test_unsafe_type_cast(self, engine):
        code = "count = int(request.args.get('count'))"
        result = engine.scan_code(code, "views.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-052" in rules

    def test_missing_rate_limit_on_login(self, engine):
        code = '@router.post("/login")'
        result = engine.scan_code(code, "auth.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-053" in rules


# ══════════════════════════════════════════════════════════════════
# A05 — Security Misconfiguration
# ══════════════════════════════════════════════════════════════════


class TestA05SecurityMisconfiguration:

    def test_debug_mode(self, engine):
        code = "DEBUG = True"
        result = engine.scan_code(code, "settings.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-055" in rules

    def test_default_credentials(self, engine):
        code = 'conn = connect("admin", "admin")'
        result = engine.scan_code(code, "db.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-056" in rules

    def test_binding_all_interfaces(self, engine):
        code = 'host = "0.0.0.0"'
        result = engine.scan_code(code, "server.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-059" in rules

    def test_graphql_introspection(self, engine):
        code = "introspection = True"
        result = engine.scan_code(code, "schema.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-064" in rules


# ══════════════════════════════════════════════════════════════════
# A06 — Vulnerable Components
# ══════════════════════════════════════════════════════════════════


class TestA06VulnerableComponents:

    def test_unsafe_yaml_load(self, engine):
        code = "data = yaml.load(raw_input)"
        result = engine.scan_code(code, "config.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-065" in rules

    def test_subprocess_shell_true(self, engine):
        code = "subprocess.call(cmd, shell=True)"
        result = engine.scan_code(code, "runner.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-067" in rules


# ══════════════════════════════════════════════════════════════════
# A07 — Authentication Failures
# ══════════════════════════════════════════════════════════════════


class TestA07AuthenticationFailures:

    def test_hardcoded_secret(self, engine):
        code = 'api_key = "sk-1234567890abcdef"'
        result = engine.scan_code(code, "config.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-006" in rules

    def test_password_hash_md5(self, engine):
        code = "hash = md5(password.encode())"
        result = engine.scan_code(code, "auth.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-070" in rules

    def test_credential_in_url(self, engine):
        code = 'url = "http://admin:password123@db.example.com"'
        result = engine.scan_code(code, "connect.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-072" in rules

    def test_aws_key_hardcoded(self, engine):
        code = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        result = engine.scan_code(code, "config.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-108" in rules

    def test_private_key_in_source(self, engine):
        code = '-----BEGIN RSA PRIVATE KEY-----'
        result = engine.scan_code(code, "keys.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-109" in rules


# ══════════════════════════════════════════════════════════════════
# A08 — Integrity Failures
# ══════════════════════════════════════════════════════════════════


class TestA08IntegrityFailures:

    def test_unsafe_eval(self, engine):
        code = "result = eval(user_expression)"
        result = engine.scan_code(code, "calc.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-077" in rules

    def test_pickle_loads(self, engine):
        code = "data = pickle.loads(network_data)"
        result = engine.scan_code(code, "handler.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-081" in rules

    def test_insecure_tempfile(self, engine):
        code = "tmp = tempfile.mktemp()"
        result = engine.scan_code(code, "io_handler.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-079" in rules

    def test_mass_assignment(self, engine):
        code = "user.update(**request.json)"
        result = engine.scan_code(code, "models.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-080" in rules

    def test_insecure_deserialization(self, engine):
        code = "yaml.load(data)"
        result = engine.scan_code(code, "parser.py")
        rules = {f.rule_id for f in result.findings}
        # yaml.load without Loader
        assert "SAST-007" in rules or "SAST-065" in rules


# ══════════════════════════════════════════════════════════════════
# A09 — Logging/Monitoring Failures
# ══════════════════════════════════════════════════════════════════


class TestA09LoggingFailures:

    def test_bare_except(self, engine):
        code = "except:\n    pass"
        result = engine.scan_code(code, "handler.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-083" in rules

    def test_pii_in_logs(self, engine):
        code = "logger.info(f'User email: {user.email}')"
        result = engine.scan_code(code, "service.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-088" in rules

    def test_sensitive_data_logged(self, engine):
        code = "logger.info(f'Auth token: {token}')"
        result = engine.scan_code(code, "auth.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-014" in rules


# ══════════════════════════════════════════════════════════════════
# A10 — SSRF
# ══════════════════════════════════════════════════════════════════


class TestA10SSRF:

    def test_ssrf_basic(self, engine):
        code = 'requests.get(f"http://{request.args[\'host\']}/api")'
        result = engine.scan_code(code, "proxy.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-011" in rules

    def test_cloud_metadata_access(self, engine):
        code = "resp = requests.get('http://169.254.169.254/latest/meta-data')"
        result = engine.scan_code(code, "cloud.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-089" in rules

    def test_file_scheme(self, engine):
        code = "data = urlopen('file:///etc/passwd')"
        result = engine.scan_code(code, "reader.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-091" in rules


# ══════════════════════════════════════════════════════════════════
# Language-Specific Rules
# ══════════════════════════════════════════════════════════════════


class TestLanguageSpecific:

    def test_php_include_injection(self, engine):
        code = "include($_GET['page']);"
        result = engine.scan_code(code, "index.php")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-093" in rules

    def test_php_type_juggling(self, engine):
        code = 'if ($token == "") {'
        result = engine.scan_code(code, "auth.php")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-094" in rules

    def test_go_error_not_checked(self, engine):
        code = "data, _ := ioutil.ReadAll(r.Body)"
        result = engine.scan_code(code, "handler.go")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-097" in rules

    def test_ruby_mass_assignment(self, engine):
        code = "user.update_attributes(params)"
        result = engine.scan_code(code, "controller.rb")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-098" in rules


# ══════════════════════════════════════════════════════════════════
# False Positive Resistance
# ══════════════════════════════════════════════════════════════════


class TestFalsePositiveResistance:
    """Safe code should NOT trigger findings."""

    def test_safe_parameterized_query(self, engine):
        code = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
        result = engine.scan_code(code, "db.py")
        sql_findings = [f for f in result.findings if f.rule_id in ("SAST-001", "SAST-002")]
        assert len(sql_findings) == 0

    def test_safe_yaml_load(self, engine):
        code = "data = yaml.safe_load(raw)"
        result = engine.scan_code(code, "config.py")
        yaml_findings = [f for f in result.findings if f.rule_id == "SAST-065"]
        assert len(yaml_findings) == 0

    def test_safe_subprocess(self, engine):
        code = 'subprocess.run(["ls", "-la"], check=True)'
        result = engine.scan_code(code, "runner.py")
        cmd_findings = [f for f in result.findings if f.rule_id == "SAST-067"]
        assert len(cmd_findings) == 0

    def test_empty_code_no_findings(self, engine):
        result = engine.scan_code("", "empty.py")
        assert result.total_findings == 0

    def test_comment_lines_ignored(self, engine):
        code = "# cursor.execute(f'SELECT * FROM {table}')"
        result = engine.scan_code(code, "db.py")
        sql_findings = [f for f in result.findings if f.rule_id == "SAST-001"]
        assert len(sql_findings) == 0

    def test_safe_literal_eval(self, engine):
        code = "import ast\nresult = ast.literal_eval(expr)"
        result = engine.scan_code(code, "parser.py")
        eval_findings = [f for f in result.findings if f.rule_id == "SAST-077"]
        assert len(eval_findings) == 0


# ══════════════════════════════════════════════════════════════════
# Multi-file & Taint Flow
# ══════════════════════════════════════════════════════════════════


class TestMultiFileAndTaint:

    def test_scan_multiple_files(self, engine):
        files = {
            "app.py": "DEBUG = True\n",
            "db.py": 'cursor.execute(f"SELECT * FROM t WHERE id={x}")\n',
            "safe.py": "def hello():\n    return 42\n",
        }
        result = engine.scan_files(files)
        assert result.files_scanned == 3
        assert result.total_findings >= 2

    def test_taint_flow_python(self, engine):
        code = """
user_input = request.args.get('q')
query = "SELECT * FROM items WHERE name = '" + user_input + "'"
cursor.execute(query)
"""
        result = engine.scan_code(code, "search.py")
        assert len(result.taint_flows) > 0

    def test_severity_distribution(self, engine):
        code = """
import pickle, os, yaml
data = pickle.loads(raw)
DEBUG = True
eval(user_input)
api_key = "sk-realkey123456789"
"""
        result = engine.scan_code(code, "vuln.py")
        assert result.by_severity.get("critical", 0) > 0


# ══════════════════════════════════════════════════════════════════
# Cross-Cutting Security Rules
# ══════════════════════════════════════════════════════════════════


class TestCrossCuttingRules:

    def test_timing_attack_comparison(self, engine):
        code = "if token == api_key:"
        result = engine.scan_code(code, "auth.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-101" in rules

    def test_docker_root_user(self, engine):
        code = "USER root"
        result = engine.scan_code(code, "Dockerfile")
        # Dockerfile isn't a recognized language, falls to UNKNOWN
        rules = {f.rule_id for f in result.findings}
        assert "SAST-105" in rules

    def test_sql_like_injection(self, engine):
        code = "query = f\"SELECT * FROM items WHERE name LIKE '%{request.args['q']}%'\""
        result = engine.scan_code(code, "search.py")
        rules = {f.rule_id for f in result.findings}
        assert "SAST-107" in rules


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--timeout=30"])
