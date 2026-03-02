"""Unit tests for RASP Engine — suite-evidence-risk/risk/runtime/rasp.py

Covers: RASPRuleEngine, RASPProtector, attack detection, rate limiting
Target: 353 LOC, 0% baseline → high coverage ROI
Pillar: V3 (decision intelligence), V5 (runtime verification)
"""



from risk.runtime.rasp import (
    AttackType,
    ProtectionAction,
    RASPConfig,
    RASPIncident,
    RASPProtector,
    RASPResult,
    RASPRuleEngine,
)


# ── Enums ──────────────────────────────────────────────────────────────────

class TestAttackType:
    def test_all_attack_types(self):
        expected = [
            "sql_injection", "command_injection", "xss", "path_traversal",
            "deserialization", "authentication_bypass", "authorization_bypass",
            "rate_limit_exceeded", "malicious_payload",
        ]
        for val in expected:
            assert AttackType(val).value == val

    def test_enum_count(self):
        assert len(AttackType) == 9


class TestProtectionAction:
    def test_all_actions(self):
        assert ProtectionAction.BLOCK.value == "block"
        assert ProtectionAction.LOG.value == "log"
        assert ProtectionAction.ALERT.value == "alert"
        assert ProtectionAction.RATE_LIMIT.value == "rate_limit"


# ── RASPConfig ──────────────────────────────────────────────────────────────

class TestRASPConfig:
    def test_defaults(self):
        config = RASPConfig()
        assert config.enabled is True
        assert config.mode == "blocking"
        assert config.block_sql_injection is True
        assert config.block_command_injection is True
        assert config.block_xss is True
        assert config.block_path_traversal is True
        assert config.block_deserialization is True
        assert config.rate_limit_enabled is True
        assert config.rate_limit_requests_per_minute == 100
        assert config.whitelist_ips == []
        assert config.blacklist_ips == []
        assert config.alert_on_block is True

    def test_custom_config(self):
        config = RASPConfig(
            enabled=False,
            mode="monitoring",
            rate_limit_requests_per_minute=50,
            whitelist_ips=["127.0.0.1"],
            blacklist_ips=["10.0.0.1"],
        )
        assert config.enabled is False
        assert config.mode == "monitoring"
        assert config.rate_limit_requests_per_minute == 50
        assert "127.0.0.1" in config.whitelist_ips
        assert "10.0.0.1" in config.blacklist_ips


# ── RASPIncident ──────────────────────────────────────────────────────────────

class TestRASPIncident:
    def test_create_incident(self):
        incident = RASPIncident(
            attack_type=AttackType.SQL_INJECTION,
            action_taken=ProtectionAction.BLOCK,
            source_ip="192.168.1.1",
            blocked=True,
        )
        assert incident.attack_type == AttackType.SQL_INJECTION
        assert incident.action_taken == ProtectionAction.BLOCK
        assert incident.source_ip == "192.168.1.1"
        assert incident.blocked is True
        assert incident.user_id is None
        assert incident.request_path == ""
        assert incident.request_method == ""
        assert incident.request_headers == {}
        assert incident.request_body is None
        assert incident.confidence == 1.0
        assert incident.timestamp is not None


# ── RASPRuleEngine ──────────────────────────────────────────────────────────

class TestRASPRuleEngine:
    def setup_method(self):
        self.config = RASPConfig()
        self.engine = RASPRuleEngine(self.config)

    def test_disabled_engine_returns_none(self):
        config = RASPConfig(enabled=False)
        engine = RASPRuleEngine(config)
        result = engine.evaluate_request("1.2.3.4", "/api/test", "GET", {})
        assert result is None

    def test_blacklisted_ip_blocked(self):
        config = RASPConfig(blacklist_ips=["10.0.0.1"])
        engine = RASPRuleEngine(config)
        result = engine.evaluate_request("10.0.0.1", "/api/test", "GET", {})
        assert result is not None
        assert result.attack_type == AttackType.MALICIOUS_PAYLOAD
        assert result.blocked is True

    def test_whitelisted_ip_allowed(self):
        config = RASPConfig(whitelist_ips=["127.0.0.1"])
        engine = RASPRuleEngine(config)
        result = engine.evaluate_request("127.0.0.1", "/api/test", "GET", {})
        assert result is None

    def test_clean_request_no_incident(self):
        result = self.engine.evaluate_request("1.2.3.4", "/api/users", "GET", {})
        assert result is None

    # SQL Injection Detection
    def test_detect_sql_injection_union_select(self):
        result = self.engine.evaluate_request(
            "1.2.3.4", "/api/users?id=1 UNION SELECT * FROM passwords", "GET", {}
        )
        assert result is not None
        assert result.attack_type == AttackType.SQL_INJECTION
        assert result.blocked is True

    def test_detect_sql_injection_or_1_equals_1(self):
        result = self.engine.evaluate_request(
            "1.2.3.4", "/api/login", "POST", {}, request_body="username=admin' OR 1=1--"
        )
        assert result is not None
        assert result.attack_type == AttackType.SQL_INJECTION

    def test_detect_sql_injection_drop_table(self):
        result = self.engine.evaluate_request(
            "1.2.3.4", "/api/data", "POST", {}, request_body="'; DROP TABLE users--"
        )
        assert result is not None
        assert result.attack_type == AttackType.SQL_INJECTION

    def test_sql_injection_disabled(self):
        config = RASPConfig(block_sql_injection=False, block_command_injection=False, block_xss=False, block_path_traversal=False, rate_limit_enabled=False)
        engine = RASPRuleEngine(config)
        result = engine.evaluate_request(
            "1.2.3.4", "/api/users?id=1 UNION SELECT *", "GET", {}
        )
        assert result is None

    # Command Injection Detection
    def test_detect_command_injection_semicolon_ls(self):
        result = self.engine.evaluate_request(
            "1.2.3.4", "/api/exec", "POST", {}, request_body="file=test; ls -la"
        )
        assert result is not None
        assert result.attack_type == AttackType.COMMAND_INJECTION

    def test_detect_command_injection_pipe_whoami(self):
        result = self.engine.evaluate_request(
            "1.2.3.4", "/api/exec", "POST", {}, request_body="input=test | whoami"
        )
        assert result is not None
        assert result.attack_type == AttackType.COMMAND_INJECTION

    def test_detect_command_injection_backtick(self):
        result = self.engine.evaluate_request(
            "1.2.3.4", "/api/exec", "POST", {}, request_body="cmd=`whoami`"
        )
        assert result is not None
        assert result.attack_type == AttackType.COMMAND_INJECTION

    def test_detect_command_injection_dollar_paren(self):
        result = self.engine.evaluate_request(
            "1.2.3.4", "/api/exec", "POST", {}, request_body="cmd=$(whoami)"
        )
        assert result is not None
        assert result.attack_type == AttackType.COMMAND_INJECTION

    # XSS Detection
    def test_detect_xss_script_tag(self):
        result = self.engine.evaluate_request(
            "1.2.3.4", "/api/comment", "POST", {}, request_body="<script>alert('xss')</script>"
        )
        assert result is not None
        assert result.attack_type == AttackType.XSS

    def test_detect_xss_javascript_protocol(self):
        result = self.engine.evaluate_request(
            "1.2.3.4", "/api/link?url=javascript:alert(1)", "GET", {}
        )
        assert result is not None
        assert result.attack_type == AttackType.XSS

    def test_detect_xss_event_handler(self):
        result = self.engine.evaluate_request(
            "1.2.3.4", "/api/img", "POST", {}, request_body='<img onerror="alert(1)">'
        )
        assert result is not None
        assert result.attack_type == AttackType.XSS

    def test_detect_xss_document_cookie(self):
        result = self.engine.evaluate_request(
            "1.2.3.4", "/api/x", "POST", {}, request_body="document.cookie"
        )
        assert result is not None
        assert result.attack_type == AttackType.XSS

    # Path Traversal Detection
    def test_detect_path_traversal_dotdot(self):
        result = self.engine.evaluate_request(
            "1.2.3.4", "/api/files/../../../etc/passwd", "GET", {}
        )
        assert result is not None
        assert result.attack_type == AttackType.PATH_TRAVERSAL

    def test_detect_path_traversal_etc_passwd(self):
        result = self.engine.evaluate_request(
            "1.2.3.4", "/api/read?file=/etc/passwd", "GET", {}
        )
        assert result is not None
        assert result.attack_type == AttackType.PATH_TRAVERSAL

    def test_detect_path_traversal_url_encoded(self):
        result = self.engine.evaluate_request(
            "1.2.3.4", "/api/files/..%2F..%2Fetc/passwd", "GET", {}
        )
        assert result is not None
        assert result.attack_type == AttackType.PATH_TRAVERSAL

    # Rate Limiting
    def test_rate_limit_enforcement(self):
        config = RASPConfig(rate_limit_requests_per_minute=5, block_sql_injection=False, block_command_injection=False, block_xss=False, block_path_traversal=False)
        engine = RASPRuleEngine(config)
        # First 5 requests pass
        for i in range(5):
            result = engine.evaluate_request("1.2.3.4", f"/api/data/{i}", "GET", {})
            assert result is None, f"Request {i} should pass"
        # 6th request should be rate limited
        result = engine.evaluate_request("1.2.3.4", "/api/data/6", "GET", {})
        assert result is not None
        assert result.attack_type == AttackType.RATE_LIMIT_EXCEEDED
        assert result.action_taken == ProtectionAction.RATE_LIMIT

    def test_rate_limit_per_ip(self):
        config = RASPConfig(rate_limit_requests_per_minute=2, block_sql_injection=False, block_command_injection=False, block_xss=False, block_path_traversal=False)
        engine = RASPRuleEngine(config)
        # IP A: 2 requests OK
        for i in range(2):
            assert engine.evaluate_request("1.1.1.1", "/api", "GET", {}) is None
        # IP A: 3rd blocked
        assert engine.evaluate_request("1.1.1.1", "/api", "GET", {}) is not None
        # IP B: still allowed
        assert engine.evaluate_request("2.2.2.2", "/api", "GET", {}) is None

    def test_rate_limit_disabled(self):
        config = RASPConfig(rate_limit_enabled=False, block_sql_injection=False, block_command_injection=False, block_xss=False, block_path_traversal=False)
        engine = RASPRuleEngine(config)
        for i in range(200):
            assert engine.evaluate_request("1.2.3.4", "/api", "GET", {}) is None

    def test_request_includes_user_id(self):
        config = RASPConfig(blacklist_ips=["10.0.0.1"])
        engine = RASPRuleEngine(config)
        result = engine.evaluate_request("10.0.0.1", "/api", "GET", {}, user_id="user123")
        assert result.user_id == "user123"


# ── RASPProtector ──────────────────────────────────────────────────────────

class TestRASPProtector:
    def setup_method(self):
        self.protector = RASPProtector()

    def test_init_default(self):
        p = RASPProtector()
        assert p.config.enabled is True
        assert isinstance(p.rule_engine, RASPRuleEngine)
        assert p.incidents == []

    def test_init_custom_config(self):
        config = RASPConfig(mode="monitoring")
        p = RASPProtector(config)
        assert p.config.mode == "monitoring"

    def test_protect_clean_request(self):
        should_block, incident = self.protector.protect_request(
            source_ip="1.2.3.4",
            request_path="/api/users",
            request_method="GET",
            request_headers={"Content-Type": "application/json"},
        )
        assert should_block is False
        assert incident is None

    def test_protect_sql_injection(self):
        should_block, incident = self.protector.protect_request(
            source_ip="1.2.3.4",
            request_path="/api/users?id=1 UNION SELECT *",
            request_method="GET",
            request_headers={},
        )
        assert should_block is True
        assert incident is not None
        assert incident.attack_type == AttackType.SQL_INJECTION

    def test_protect_disabled(self):
        config = RASPConfig(enabled=False)
        protector = RASPProtector(config)
        should_block, incident = protector.protect_request(
            source_ip="1.2.3.4",
            request_path="/api/users?id=1 UNION SELECT *",
            request_method="GET",
            request_headers={},
        )
        assert should_block is False
        assert incident is None

    def test_incidents_accumulated(self):
        self.protector.protect_request("1.2.3.4", "/api?id=1 UNION SELECT *", "GET", {})
        self.protector.protect_request("1.2.3.4", "/api?x=<script>alert(1)</script>", "GET", {})
        assert len(self.protector.incidents) == 2

    def test_get_protection_stats(self):
        self.protector.protect_request("1.2.3.4", "/api?id=1 UNION SELECT *", "GET", {})
        self.protector.protect_request("2.2.2.2", "/api?x=<script>x</script>", "GET", {})
        stats = self.protector.get_protection_stats()
        assert isinstance(stats, RASPResult)
        assert stats.total_incidents == 2
        assert stats.blocked_requests == 2
        assert stats.protection_enabled is True
        assert "sql_injection" in stats.incidents_by_type
        assert "xss" in stats.incidents_by_type

    def test_get_protection_stats_empty(self):
        stats = self.protector.get_protection_stats()
        assert stats.total_incidents == 0
        assert stats.blocked_requests == 0
        assert stats.incidents_by_type == {}

    def test_clear_incidents(self):
        self.protector.protect_request("1.2.3.4", "/api?id=1 UNION SELECT *", "GET", {})
        assert len(self.protector.incidents) == 1
        self.protector.clear_incidents()
        assert len(self.protector.incidents) == 0

    def test_protect_with_user_id(self):
        config = RASPConfig(blacklist_ips=["evil.ip"])
        protector = RASPProtector(config)
        should_block, incident = protector.protect_request(
            source_ip="evil.ip",
            request_path="/api",
            request_method="GET",
            request_headers={},
            user_id="attacker42",
        )
        assert should_block is True
        assert incident.user_id == "attacker42"

    def test_protect_with_body(self):
        should_block, incident = self.protector.protect_request(
            source_ip="1.2.3.4",
            request_path="/api/comment",
            request_method="POST",
            request_headers={"Content-Type": "text/plain"},
            request_body="'; DROP TABLE users--",
        )
        assert should_block is True
        assert incident.attack_type == AttackType.SQL_INJECTION


# ── RASPResult Dataclass ──────────────────────────────────────────────────

class TestRASPResult:
    def test_create_result(self):
        result = RASPResult(
            incidents=[],
            total_incidents=0,
            blocked_requests=0,
            incidents_by_type={},
            protection_enabled=True,
        )
        assert result.total_incidents == 0
        assert result.protection_enabled is True
        assert result.timestamp is not None
