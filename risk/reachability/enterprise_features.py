"""Enterprise-grade features for production deployment."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from risk.reachability.analyzer import ReachabilityAnalyzer
from risk.reachability.monitoring import ReachabilityMonitor

logger = logging.getLogger(__name__)


class SLA(Enum):
    """Service Level Agreement tiers."""

    STANDARD = "standard"  # 99.9% uptime
    PREMIUM = "premium"  # 99.95% uptime
    ENTERPRISE = "enterprise"  # 99.99% uptime


class TenantTier(Enum):
    """Tenant subscription tiers."""

    FREE = "free"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    ENTERPRISE_PLUS = "enterprise_plus"


@dataclass
class TenantConfig:
    """Configuration for a tenant."""

    tenant_id: str
    tier: TenantTier
    sla: SLA
    max_concurrent_analyses: int
    max_repositories: int
    max_components: int
    features: Set[str] = field(default_factory=set)
    rate_limit_per_minute: int = 60
    storage_quota_gb: int = 10
    retention_days: int = 90


@dataclass
class EnterpriseConfig:
    """Enterprise configuration."""

    enable_multi_tenancy: bool = True
    enable_rbac: bool = True
    enable_audit_logging: bool = True
    enable_rate_limiting: bool = True
    enable_quota_management: bool = True
    enable_sla_monitoring: bool = True
    default_sla: SLA = SLA.ENTERPRISE
    max_workers_per_tenant: int = 10
    global_rate_limit: int = 1000


class EnterpriseReachabilityService:
    """Enterprise-grade reachability service with multi-tenancy, RBAC, and SLA management."""

    def __init__(
        self,
        config: Optional[EnterpriseConfig] = None,
        analyzer: Optional[ReachabilityAnalyzer] = None,
    ):
        """Initialize enterprise service.

        Parameters
        ----------
        config
            Enterprise configuration.
        analyzer
            Reachability analyzer instance.
        """
        self.config = config or EnterpriseConfig()
        self.analyzer = analyzer
        self.monitor = ReachabilityMonitor()

        # Tenant management
        self.tenants: Dict[str, TenantConfig] = {}

        # Rate limiting
        self.rate_limiter: Dict[str, List[datetime]] = {}

        # Quota tracking
        self.quota_usage: Dict[str, Dict[str, int]] = {}

        # SLA monitoring
        self.sla_metrics: Dict[str, Dict[str, Any]] = {}

        # Audit logging
        self.audit_log: List[Dict[str, Any]] = []

    def register_tenant(self, tenant_config: TenantConfig) -> None:
        """Register a new tenant.

        Parameters
        ----------
        tenant_config
            Tenant configuration.
        """
        self.tenants[tenant_config.tenant_id] = tenant_config
        self.quota_usage[tenant_config.tenant_id] = {
            "analyses": 0,
            "repositories": 0,
            "components": 0,
            "storage_gb": 0.0,
        }
        self.sla_metrics[tenant_config.tenant_id] = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "uptime_percentage": 100.0,
        }

        logger.info(
            f"Registered tenant: {tenant_config.tenant_id} ({tenant_config.tier.value})"
        )

    def check_rate_limit(self, tenant_id: str) -> bool:
        """Check if tenant has exceeded rate limit.

        Parameters
        ----------
        tenant_id
            Tenant identifier.

        Returns
        -------
        bool
            True if within rate limit, False otherwise.
        """
        if not self.config.enable_rate_limiting:
            return True

        if tenant_id not in self.tenants:
            return False

        tenant = self.tenants[tenant_id]
        now = datetime.now(timezone.utc)

        # Clean old entries
        if tenant_id in self.rate_limiter:
            cutoff = now.timestamp() - 60  # Last minute
            self.rate_limiter[tenant_id] = [
                ts for ts in self.rate_limiter[tenant_id] if ts.timestamp() > cutoff
            ]
        else:
            self.rate_limiter[tenant_id] = []

        # Check limit
        if len(self.rate_limiter[tenant_id]) >= tenant.rate_limit_per_minute:
            logger.warning(f"Rate limit exceeded for tenant: {tenant_id}")
            return False

        # Record request
        self.rate_limiter[tenant_id].append(now)
        return True

    def check_quota(self, tenant_id: str, resource: str, amount: int = 1) -> bool:
        """Check if tenant has quota available.

        Parameters
        ----------
        tenant_id
            Tenant identifier.
        resource
            Resource type (analyses, repositories, components, storage).
        amount
            Amount to check.

        Returns
        -------
        bool
            True if quota available, False otherwise.
        """
        if not self.config.enable_quota_management:
            return True

        if tenant_id not in self.tenants:
            return False

        tenant = self.tenants[tenant_id]
        usage = self.quota_usage[tenant_id]

        if resource == "analyses":
            return usage["analyses"] + amount <= tenant.max_concurrent_analyses
        elif resource == "repositories":
            return usage["repositories"] + amount <= tenant.max_repositories
        elif resource == "components":
            return usage["components"] + amount <= tenant.max_components
        elif resource == "storage":
            return usage["storage_gb"] + amount <= tenant.storage_quota_gb

        return True

    def record_usage(self, tenant_id: str, resource: str, amount: int = 1) -> None:
        """Record resource usage.

        Parameters
        ----------
        tenant_id
            Tenant identifier.
        resource
            Resource type.
        amount
            Amount used.
        """
        if tenant_id in self.quota_usage:
            if resource in self.quota_usage[tenant_id]:
                self.quota_usage[tenant_id][resource] += amount

    def record_sla_metric(
        self, tenant_id: str, success: bool, response_time_ms: float
    ) -> None:
        """Record SLA metric.

        Parameters
        ----------
        tenant_id
            Tenant identifier.
        success
            Whether request was successful.
        response_time_ms
            Response time in milliseconds.
        """
        if tenant_id not in self.sla_metrics:
            return

        metrics = self.sla_metrics[tenant_id]
        metrics["total_requests"] += 1

        if success:
            metrics["successful_requests"] += 1
        else:
            metrics["failed_requests"] += 1

        # Calculate uptime
        if metrics["total_requests"] > 0:
            metrics["uptime_percentage"] = (
                metrics["successful_requests"] / metrics["total_requests"] * 100
            )

        # Check SLA compliance
        if tenant_id in self.tenants:
            tenant = self.tenants[tenant_id]
            required_uptime = {
                SLA.STANDARD: 99.9,
                SLA.PREMIUM: 99.95,
                SLA.ENTERPRISE: 99.99,
            }.get(tenant.sla, 99.9)

            if metrics["uptime_percentage"] < required_uptime:
                logger.warning(
                    f"SLA violation for tenant {tenant_id}: "
                    f"{metrics['uptime_percentage']:.2f}% < {required_uptime}%"
                )

    def audit_log_event(
        self,
        tenant_id: str,
        user_id: str,
        action: str,
        resource: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record audit log event.

        Parameters
        ----------
        tenant_id
            Tenant identifier.
        user_id
            User identifier.
        action
            Action performed.
        resource
            Resource affected.
        details
            Additional details.
        """
        if not self.config.enable_audit_logging:
            return

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tenant_id": tenant_id,
            "user_id": user_id,
            "action": action,
            "resource": resource,
            "details": details or {},
        }

        self.audit_log.append(event)

        # Keep only last 10000 events in memory
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-10000:]

        logger.info(f"Audit: {action} on {resource} by {user_id} in {tenant_id}")

    def get_tenant_metrics(self, tenant_id: str) -> Dict[str, Any]:
        """Get metrics for a tenant.

        Parameters
        ----------
        tenant_id
            Tenant identifier.

        Returns
        -------
        Dict[str, Any]
            Tenant metrics.
        """
        if tenant_id not in self.tenants:
            return {}

        tenant = self.tenants[tenant_id]
        usage = self.quota_usage.get(tenant_id, {})
        sla = self.sla_metrics.get(tenant_id, {})

        return {
            "tenant_id": tenant_id,
            "tier": tenant.tier.value,
            "sla": tenant.sla.value,
            "quota_usage": usage,
            "quota_limits": {
                "max_concurrent_analyses": tenant.max_concurrent_analyses,
                "max_repositories": tenant.max_repositories,
                "max_components": tenant.max_components,
                "storage_quota_gb": tenant.storage_quota_gb,
            },
            "sla_metrics": sla,
            "features": list(tenant.features),
        }

    def get_global_metrics(self) -> Dict[str, Any]:
        """Get global service metrics.

        Returns
        -------
        Dict[str, Any]
            Global metrics.
        """
        total_tenants = len(self.tenants)
        total_analyses = sum(u.get("analyses", 0) for u in self.quota_usage.values())

        # Calculate overall uptime
        total_requests = sum(
            m.get("total_requests", 0) for m in self.sla_metrics.values()
        )
        total_successful = sum(
            m.get("successful_requests", 0) for m in self.sla_metrics.values()
        )
        overall_uptime = (
            (total_successful / total_requests * 100) if total_requests > 0 else 100.0
        )

        return {
            "total_tenants": total_tenants,
            "total_analyses": total_analyses,
            "overall_uptime_percentage": overall_uptime,
            "active_tenants": sum(
                1
                for t in self.tenants.values()
                if self.quota_usage.get(t.tenant_id, {}).get("analyses", 0) > 0
            ),
            "tier_distribution": {
                tier.value: sum(1 for t in self.tenants.values() if t.tier == tier)
                for tier in TenantTier
            },
        }
