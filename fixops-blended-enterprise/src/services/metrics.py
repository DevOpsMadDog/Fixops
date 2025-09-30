"""
FixOps Prometheus Metrics
Bank-grade monitoring and observability
"""

from prometheus_client import Counter, Histogram, Gauge, Info, CollectorRegistry, generate_latest
import time
from typing import Dict, Any
import structlog

logger = structlog.get_logger()

# Create custom registry for FixOps metrics
fixops_registry = CollectorRegistry()

# Decision Engine Metrics
DECISIONS_TOTAL = Counter(
    'fixops_decisions_total',
    'Total number of security decisions made',
    ['decision', 'environment', 'confidence_level'],
    registry=fixops_registry
)

DECISION_LATENCY = Histogram(
    'fixops_decision_latency_seconds',
    'Time taken to make security decisions',
    ['service_type', 'environment'],
    registry=fixops_registry
)

CONSENSUS_SCORE = Histogram(
    'fixops_consensus_score',
    'Consensus confidence scores',
    ['decision_outcome'],
    registry=fixops_registry
)

# Component Health Metrics
COMPONENT_STATUS = Gauge(
    'fixops_component_healthy',
    'Health status of core components',
    ['component'],
    registry=fixops_registry
)

EVIDENCE_RECORDS = Counter(
    'fixops_evidence_records_total',
    'Total evidence records stored',
    ['evidence_type'],
    registry=fixops_registry
)

# Security Metrics
SECURITY_FINDINGS = Counter(
    'fixops_security_findings_total',
    'Security findings processed',
    ['severity', 'category', 'source'],
    registry=fixops_registry
)

BLOCKED_DEPLOYMENTS = Counter(
    'fixops_blocked_deployments_total',
    'Deployments blocked by security concerns',
    ['reason', 'environment'],
    registry=fixops_registry
)

# Business Metrics
BUSINESS_IMPACT = Counter(
    'fixops_business_impact_decisions',
    'Decisions categorized by business impact',
    ['impact_level', 'service_type'],
    registry=fixops_registry
)

# Performance Metrics
HOT_PATH_LATENCY = Histogram(
    'fixops_hot_path_latency_microseconds',
    'Hot path processing latency in microseconds',
    ['endpoint'],
    buckets=[50, 100, 200, 299, 500, 1000, 2000, 5000],
    registry=fixops_registry
)

# System Info
FIXOPS_INFO = Info(
    'fixops_system_info',
    'FixOps system information',
    registry=fixops_registry
)

class FixOpsMetrics:
    """FixOps metrics collector for bank monitoring"""
    
    @staticmethod
    def initialize():
        """Initialize metrics with system info"""
        FIXOPS_INFO.info({
            'version': '1.0.0',
            'service': 'decision-engine',
            'environment': 'production'
        })
        
        # Initialize component health
        components = ['vector_db', 'llm_rag', 'consensus_checker', 'golden_regression', 'policy_engine', 'sbom_injection']
        for component in components:
            COMPONENT_STATUS.labels(component=component).set(1)
    
    @staticmethod
    def record_decision(decision: str, environment: str, confidence: float, latency_seconds: float, service_type: str = "unknown"):
        """Record decision metrics"""
        # Categorize confidence level
        confidence_level = "high" if confidence >= 0.85 else "medium" if confidence >= 0.70 else "low"
        
        DECISIONS_TOTAL.labels(
            decision=decision.lower(),
            environment=environment,
            confidence_level=confidence_level
        ).inc()
        
        DECISION_LATENCY.labels(
            service_type=service_type,
            environment=environment
        ).observe(latency_seconds)
        
        CONSENSUS_SCORE.labels(
            decision_outcome=decision.lower()
        ).observe(confidence)
        
        # Record blocked deployments
        if decision == "BLOCK":
            BLOCKED_DEPLOYMENTS.labels(
                reason="security_issues",
                environment=environment
            ).inc()
    
    @staticmethod
    def record_security_findings(findings: list):
        """Record security findings metrics"""
        for finding in findings:
            SECURITY_FINDINGS.labels(
                severity=finding.get("severity", "unknown"),
                category=finding.get("category", "unknown"),
                source=finding.get("source", "unknown")
            ).inc()
    
    @staticmethod
    def record_evidence(evidence_type: str = "decision"):
        """Record evidence storage"""
        EVIDENCE_RECORDS.labels(evidence_type=evidence_type).inc()
    
    @staticmethod
    def record_business_impact(impact_level: str, service_type: str):
        """Record business impact metrics"""
        BUSINESS_IMPACT.labels(
            impact_level=impact_level,
            service_type=service_type
        ).inc()
    
    @staticmethod
    def record_hot_path_latency(endpoint: str, latency_us: float):
        """Record hot path latency for bank SLA monitoring"""
        HOT_PATH_LATENCY.labels(endpoint=endpoint).observe(latency_us)
    
    @staticmethod
    def update_component_health(component: str, healthy: bool):
        """Update component health status"""
        COMPONENT_STATUS.labels(component=component).set(1 if healthy else 0)
    
    @staticmethod
    def get_metrics() -> str:
        """Get Prometheus metrics in text format"""
        return generate_latest(fixops_registry)

# Initialize metrics on import
FixOpsMetrics.initialize()