"""Tests for enterprise features module."""


import pytest
from risk.reachability.enterprise_features import (
    SLA,
    EnterpriseConfig,
    EnterpriseReachabilityService,
    TenantConfig,
    TenantTier,
)


class TestSLAEnum:
    """Tests for SLA enumeration."""

    def test_sla_values(self):
        """Test SLA enum values."""
        assert SLA.STANDARD.value == "standard"
        assert SLA.PREMIUM.value == "premium"
        assert SLA.ENTERPRISE.value == "enterprise"

    def test_sla_members(self):
        """Test SLA enum has expected members."""
        assert len(SLA) == 3
        assert SLA.STANDARD in SLA
        assert SLA.PREMIUM in SLA
        assert SLA.ENTERPRISE in SLA


class TestTenantTierEnum:
    """Tests for TenantTier enumeration."""

    def test_tenant_tier_values(self):
        """Test TenantTier enum values."""
        assert TenantTier.FREE.value == "free"
        assert TenantTier.PROFESSIONAL.value == "professional"
        assert TenantTier.ENTERPRISE.value == "enterprise"
        assert TenantTier.ENTERPRISE_PLUS.value == "enterprise_plus"

    def test_tenant_tier_members(self):
        """Test TenantTier enum has expected members."""
        assert len(TenantTier) == 4


class TestTenantConfig:
    """Tests for TenantConfig dataclass."""

    def test_tenant_config_creation(self):
        """Test creating a TenantConfig."""
        config = TenantConfig(
            tenant_id="tenant-123",
            tier=TenantTier.ENTERPRISE,
            sla=SLA.ENTERPRISE,
            max_concurrent_analyses=10,
            max_repositories=100,
            max_components=1000,
        )
        assert config.tenant_id == "tenant-123"
        assert config.tier == TenantTier.ENTERPRISE
        assert config.sla == SLA.ENTERPRISE
        assert config.max_concurrent_analyses == 10
        assert config.max_repositories == 100
        assert config.max_components == 1000

    def test_tenant_config_defaults(self):
        """Test TenantConfig default values."""
        config = TenantConfig(
            tenant_id="tenant-456",
            tier=TenantTier.FREE,
            sla=SLA.STANDARD,
            max_concurrent_analyses=1,
            max_repositories=5,
            max_components=50,
        )
        assert config.rate_limit_per_minute == 60
        assert config.storage_quota_gb == 10
        assert config.retention_days == 90
        assert config.features == set()

    def test_tenant_config_with_features(self):
        """Test TenantConfig with custom features."""
        config = TenantConfig(
            tenant_id="tenant-789",
            tier=TenantTier.ENTERPRISE_PLUS,
            sla=SLA.ENTERPRISE,
            max_concurrent_analyses=50,
            max_repositories=500,
            max_components=5000,
            features={"advanced_analysis", "custom_rules", "api_access"},
            rate_limit_per_minute=1000,
            storage_quota_gb=100,
            retention_days=365,
        )
        assert "advanced_analysis" in config.features
        assert config.rate_limit_per_minute == 1000
        assert config.storage_quota_gb == 100
        assert config.retention_days == 365


class TestEnterpriseConfig:
    """Tests for EnterpriseConfig dataclass."""

    def test_enterprise_config_defaults(self):
        """Test EnterpriseConfig default values."""
        config = EnterpriseConfig()
        assert config.enable_multi_tenancy is True
        assert config.enable_rbac is True
        assert config.enable_audit_logging is True
        assert config.enable_rate_limiting is True
        assert config.enable_quota_management is True
        assert config.enable_sla_monitoring is True
        assert config.default_sla == SLA.ENTERPRISE
        assert config.max_workers_per_tenant == 10
        assert config.global_rate_limit == 1000

    def test_enterprise_config_custom(self):
        """Test EnterpriseConfig with custom values."""
        config = EnterpriseConfig(
            enable_multi_tenancy=False,
            enable_rbac=False,
            enable_audit_logging=False,
            enable_rate_limiting=False,
            enable_quota_management=False,
            enable_sla_monitoring=False,
            default_sla=SLA.STANDARD,
            max_workers_per_tenant=5,
            global_rate_limit=500,
        )
        assert config.enable_multi_tenancy is False
        assert config.enable_rbac is False
        assert config.default_sla == SLA.STANDARD
        assert config.max_workers_per_tenant == 5


class TestEnterpriseReachabilityService:
    """Tests for EnterpriseReachabilityService."""

    @pytest.fixture
    def service(self):
        """Create a service instance for testing."""
        return EnterpriseReachabilityService()

    @pytest.fixture
    def tenant_config(self):
        """Create a tenant config for testing."""
        return TenantConfig(
            tenant_id="test-tenant",
            tier=TenantTier.ENTERPRISE,
            sla=SLA.ENTERPRISE,
            max_concurrent_analyses=10,
            max_repositories=100,
            max_components=1000,
            rate_limit_per_minute=60,
        )

    def test_service_initialization(self, service):
        """Test service initialization."""
        assert service.config is not None
        assert service.tenants == {}
        assert service.rate_limiter == {}
        assert service.quota_usage == {}
        assert service.sla_metrics == {}
        assert service.audit_log == []

    def test_service_with_custom_config(self):
        """Test service with custom config."""
        config = EnterpriseConfig(enable_rate_limiting=False)
        service = EnterpriseReachabilityService(config=config)
        assert service.config.enable_rate_limiting is False

    def test_register_tenant(self, service, tenant_config):
        """Test registering a tenant."""
        service.register_tenant(tenant_config)

        assert "test-tenant" in service.tenants
        assert service.tenants["test-tenant"] == tenant_config
        assert "test-tenant" in service.quota_usage
        assert service.quota_usage["test-tenant"]["analyses"] == 0
        assert service.quota_usage["test-tenant"]["repositories"] == 0
        assert "test-tenant" in service.sla_metrics
        assert service.sla_metrics["test-tenant"]["total_requests"] == 0
        assert service.sla_metrics["test-tenant"]["uptime_percentage"] == 100.0

    def test_check_rate_limit_unregistered_tenant(self, service):
        """Test rate limit check for unregistered tenant."""
        result = service.check_rate_limit("unknown-tenant")
        assert result is False

    def test_check_rate_limit_within_limit(self, service, tenant_config):
        """Test rate limit check within limit."""
        service.register_tenant(tenant_config)

        # First request should be allowed
        result = service.check_rate_limit("test-tenant")
        assert result is True

    def test_check_rate_limit_exceeded(self, service, tenant_config):
        """Test rate limit check when exceeded."""
        tenant_config.rate_limit_per_minute = 5
        service.register_tenant(tenant_config)

        # Make requests up to the limit
        for _ in range(5):
            result = service.check_rate_limit("test-tenant")
            assert result is True

        # Next request should be denied
        result = service.check_rate_limit("test-tenant")
        assert result is False

    def test_check_rate_limit_disabled(self, tenant_config):
        """Test rate limit check when disabled."""
        config = EnterpriseConfig(enable_rate_limiting=False)
        service = EnterpriseReachabilityService(config=config)
        service.register_tenant(tenant_config)

        # Should always return True when disabled
        for _ in range(100):
            result = service.check_rate_limit("test-tenant")
            assert result is True

    def test_check_quota_unregistered_tenant(self, service):
        """Test quota check for unregistered tenant."""
        result = service.check_quota("unknown-tenant", "analyses")
        assert result is False

    def test_check_quota_analyses(self, service, tenant_config):
        """Test quota check for analyses."""
        service.register_tenant(tenant_config)

        # Should have quota available
        result = service.check_quota("test-tenant", "analyses", 5)
        assert result is True

        # Should not have quota for more than max
        result = service.check_quota("test-tenant", "analyses", 15)
        assert result is False

    def test_check_quota_repositories(self, service, tenant_config):
        """Test quota check for repositories."""
        service.register_tenant(tenant_config)

        result = service.check_quota("test-tenant", "repositories", 50)
        assert result is True

        result = service.check_quota("test-tenant", "repositories", 150)
        assert result is False

    def test_check_quota_components(self, service, tenant_config):
        """Test quota check for components."""
        service.register_tenant(tenant_config)

        result = service.check_quota("test-tenant", "components", 500)
        assert result is True

        result = service.check_quota("test-tenant", "components", 1500)
        assert result is False

    def test_check_quota_storage(self, service, tenant_config):
        """Test quota check for storage."""
        service.register_tenant(tenant_config)

        result = service.check_quota("test-tenant", "storage", 5)
        assert result is True

        result = service.check_quota("test-tenant", "storage", 15)
        assert result is False

    def test_check_quota_unknown_resource(self, service, tenant_config):
        """Test quota check for unknown resource."""
        service.register_tenant(tenant_config)

        # Unknown resource should return True
        result = service.check_quota("test-tenant", "unknown_resource", 100)
        assert result is True

    def test_check_quota_disabled(self, tenant_config):
        """Test quota check when disabled."""
        config = EnterpriseConfig(enable_quota_management=False)
        service = EnterpriseReachabilityService(config=config)
        service.register_tenant(tenant_config)

        # Should always return True when disabled
        result = service.check_quota("test-tenant", "analyses", 1000)
        assert result is True

    def test_record_usage(self, service, tenant_config):
        """Test recording resource usage."""
        service.register_tenant(tenant_config)

        service.record_usage("test-tenant", "analyses", 5)
        assert service.quota_usage["test-tenant"]["analyses"] == 5

        service.record_usage("test-tenant", "analyses", 3)
        assert service.quota_usage["test-tenant"]["analyses"] == 8

    def test_record_usage_unknown_tenant(self, service):
        """Test recording usage for unknown tenant."""
        # Should not raise error
        service.record_usage("unknown-tenant", "analyses", 5)

    def test_record_sla_metric_success(self, service, tenant_config):
        """Test recording SLA metric for successful request."""
        service.register_tenant(tenant_config)

        service.record_sla_metric("test-tenant", success=True, response_time_ms=100.0)

        metrics = service.sla_metrics["test-tenant"]
        assert metrics["total_requests"] == 1
        assert metrics["successful_requests"] == 1
        assert metrics["failed_requests"] == 0
        assert metrics["uptime_percentage"] == 100.0

    def test_record_sla_metric_failure(self, service, tenant_config):
        """Test recording SLA metric for failed request."""
        service.register_tenant(tenant_config)

        service.record_sla_metric("test-tenant", success=False, response_time_ms=500.0)

        metrics = service.sla_metrics["test-tenant"]
        assert metrics["total_requests"] == 1
        assert metrics["successful_requests"] == 0
        assert metrics["failed_requests"] == 1
        assert metrics["uptime_percentage"] == 0.0

    def test_record_sla_metric_mixed(self, service, tenant_config):
        """Test recording mixed SLA metrics."""
        service.register_tenant(tenant_config)

        # 9 successes, 1 failure = 90% uptime
        for _ in range(9):
            service.record_sla_metric(
                "test-tenant", success=True, response_time_ms=100.0
            )
        service.record_sla_metric("test-tenant", success=False, response_time_ms=500.0)

        metrics = service.sla_metrics["test-tenant"]
        assert metrics["total_requests"] == 10
        assert metrics["successful_requests"] == 9
        assert metrics["failed_requests"] == 1
        assert metrics["uptime_percentage"] == 90.0

    def test_record_sla_metric_unknown_tenant(self, service):
        """Test recording SLA metric for unknown tenant."""
        # Should not raise error
        service.record_sla_metric(
            "unknown-tenant", success=True, response_time_ms=100.0
        )

    def test_audit_log_event(self, service, tenant_config):
        """Test audit logging."""
        service.register_tenant(tenant_config)

        service.audit_log_event(
            tenant_id="test-tenant",
            user_id="user-123",
            action="analyze",
            resource="CVE-2024-1234",
            details={"component": "test-lib"},
        )

        assert len(service.audit_log) == 1
        event = service.audit_log[0]
        assert event["tenant_id"] == "test-tenant"
        assert event["user_id"] == "user-123"
        assert event["action"] == "analyze"
        assert event["resource"] == "CVE-2024-1234"
        assert event["details"]["component"] == "test-lib"
        assert "timestamp" in event

    def test_audit_log_disabled(self, tenant_config):
        """Test audit logging when disabled."""
        config = EnterpriseConfig(enable_audit_logging=False)
        service = EnterpriseReachabilityService(config=config)
        service.register_tenant(tenant_config)

        service.audit_log_event(
            tenant_id="test-tenant",
            user_id="user-123",
            action="analyze",
            resource="CVE-2024-1234",
        )

        assert len(service.audit_log) == 0

    def test_audit_log_truncation(self, service, tenant_config):
        """Test audit log truncation at 10000 events."""
        service.register_tenant(tenant_config)

        # Add more than 10000 events
        for i in range(10005):
            service.audit_log_event(
                tenant_id="test-tenant",
                user_id="user-123",
                action=f"action-{i}",
                resource=f"resource-{i}",
            )

        # Should be truncated to 10000
        assert len(service.audit_log) == 10000
        # Should keep the most recent events
        assert service.audit_log[-1]["action"] == "action-10004"

    def test_get_tenant_metrics_unknown_tenant(self, service):
        """Test getting metrics for unknown tenant."""
        result = service.get_tenant_metrics("unknown-tenant")
        assert result == {}

    def test_get_tenant_metrics(self, service, tenant_config):
        """Test getting tenant metrics."""
        service.register_tenant(tenant_config)
        service.record_usage("test-tenant", "analyses", 5)
        service.record_sla_metric("test-tenant", success=True, response_time_ms=100.0)

        metrics = service.get_tenant_metrics("test-tenant")

        assert metrics["tenant_id"] == "test-tenant"
        assert metrics["tier"] == "enterprise"
        assert metrics["sla"] == "enterprise"
        assert metrics["quota_usage"]["analyses"] == 5
        assert metrics["quota_limits"]["max_concurrent_analyses"] == 10
        assert metrics["sla_metrics"]["total_requests"] == 1

    def test_get_global_metrics_empty(self, service):
        """Test getting global metrics with no tenants."""
        metrics = service.get_global_metrics()

        assert metrics["total_tenants"] == 0
        assert metrics["total_analyses"] == 0
        assert metrics["overall_uptime_percentage"] == 100.0
        assert metrics["active_tenants"] == 0

    def test_get_global_metrics(self, service, tenant_config):
        """Test getting global metrics."""
        service.register_tenant(tenant_config)
        service.record_usage("test-tenant", "analyses", 5)
        service.record_sla_metric("test-tenant", success=True, response_time_ms=100.0)

        # Add another tenant
        tenant2 = TenantConfig(
            tenant_id="tenant-2",
            tier=TenantTier.PROFESSIONAL,
            sla=SLA.PREMIUM,
            max_concurrent_analyses=5,
            max_repositories=50,
            max_components=500,
        )
        service.register_tenant(tenant2)
        service.record_usage("tenant-2", "analyses", 3)

        metrics = service.get_global_metrics()

        assert metrics["total_tenants"] == 2
        assert metrics["total_analyses"] == 8
        assert metrics["active_tenants"] == 2
        assert metrics["tier_distribution"]["enterprise"] == 1
        assert metrics["tier_distribution"]["professional"] == 1
