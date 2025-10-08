"""
Enterprise structured logging with compliance and security features
"""

import asyncio
import json
import time
from datetime import datetime
from typing import Dict, Any, Optional

import structlog
from structlog.processors import JSONRenderer

from src.config.settings import get_settings
from src.db.session import DatabaseManager
from src.models.user_sqlite import UserAuditLog

settings = get_settings()


def setup_structured_logging():
    """Configure structured logging for enterprise compliance"""
    
    # Configure structlog processors
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        JSONRenderer()  # JSON format for log aggregation
    ]
    
    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


async def log_security_event(
    action: str,
    user_id: Optional[str] = None,
    ip_address: str = "unknown",
    user_agent: Optional[str] = None,
    resource: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    success: bool = True,
    error_message: Optional[str] = None
) -> None:
    """
    Log security events for audit compliance
    This runs asynchronously to not impact hot path performance
    """
    try:
        # Create audit log entry
        async with DatabaseManager.get_session_context() as session:
            audit_log = UserAuditLog(
                user_id=user_id,
                action=action,
                resource=resource,
                resource_id=resource_id,
                details=json.dumps(details or {}),  # Convert dict to JSON string
                ip_address=ip_address,
                user_agent=user_agent,
                success=success,
                error_message=error_message
            )
            session.add(audit_log)
            
        # Also log to structured logger for real-time monitoring
        logger = structlog.get_logger()
        logger.info(
            "Security event",
            action=action,
            user_id=user_id,
            ip_address=ip_address,
            resource=resource,
            success=success,
            timestamp=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        # Never let logging failures impact the application
        logger = structlog.get_logger()
        logger.error(f"Failed to log security event: {str(e)}")


class PerformanceLogger:
    """Logger for performance monitoring and optimization"""
    
    @staticmethod
    def log_hot_path_performance(
        endpoint: str,
        latency_us: float,
        user_id: Optional[str] = None,
        additional_context: Optional[Dict[str, Any]] = None
    ):
        """Log hot path performance metrics"""
        logger = structlog.get_logger()
        
        context = {
            "endpoint": endpoint,
            "latency_us": latency_us,
            "target_us": settings.HOT_PATH_TARGET_LATENCY_US,
            "exceeded_target": latency_us > settings.HOT_PATH_TARGET_LATENCY_US,
            "user_id": user_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if additional_context:
            context.update(additional_context)
        
        if latency_us > settings.HOT_PATH_TARGET_LATENCY_US:
            logger.warning("Hot path latency exceeded", **context)
        else:
            logger.info("Hot path performance", **context)
    
    @staticmethod
    def log_database_performance(
        operation: str,
        duration_ms: float,
        table: Optional[str] = None,
        additional_context: Optional[Dict[str, Any]] = None
    ):
        """Log database operation performance"""
        logger = structlog.get_logger()
        
        context = {
            "operation": operation,
            "duration_ms": duration_ms,
            "table": table,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if additional_context:
            context.update(additional_context)
        
        if duration_ms > 100:  # Log slow queries
            logger.warning("Slow database operation", **context)
        else:
            logger.debug("Database operation", **context)
    
    @staticmethod 
    def log_cache_performance(
        operation: str,
        cache_hit: bool,
        duration_us: Optional[float] = None,
        key: Optional[str] = None
    ):
        """Log cache operation performance"""
        logger = structlog.get_logger()
        
        logger.debug(
            "Cache operation",
            operation=operation,
            cache_hit=cache_hit,
            duration_us=duration_us,
            key=key,
            timestamp=datetime.utcnow().isoformat()
        )


class ComplianceLogger:
    """Logger for compliance and regulatory requirements"""
    
    @staticmethod
    async def log_data_access(
        user_id: str,
        data_type: str,
        operation: str,
        record_ids: Optional[list] = None,
        justification: Optional[str] = None,
        ip_address: str = "unknown"
    ):
        """Log data access for compliance (GDPR, HIPAA, etc.)"""
        await log_security_event(
            action=f"data_access_{operation}",
            user_id=user_id,
            ip_address=ip_address,
            details={
                "data_type": data_type,
                "operation": operation,
                "record_ids": record_ids or [],
                "justification": justification,
                "compliance_event": True
            }
        )
    
    @staticmethod
    async def log_admin_action(
        admin_user_id: str,
        action: str,
        target_user_id: Optional[str] = None,
        changes: Optional[Dict[str, Any]] = None,
        ip_address: str = "unknown"
    ):
        """Log administrative actions for audit trails"""
        await log_security_event(
            action=f"admin_{action}",
            user_id=admin_user_id,
            ip_address=ip_address,
            details={
                "target_user_id": target_user_id,
                "changes": changes or {},
                "admin_action": True
            }
        )
    
    @staticmethod
    async def log_config_change(
        user_id: str,
        config_type: str,
        old_value: Any,
        new_value: Any,
        ip_address: str = "unknown"
    ):
        """Log configuration changes for security compliance"""
        await log_security_event(
            action="config_change",
            user_id=user_id,
            ip_address=ip_address,
            details={
                "config_type": config_type,
                "old_value": str(old_value),
                "new_value": str(new_value),
                "compliance_event": True
            }
        )


# Initialize structured logging
setup_structured_logging()