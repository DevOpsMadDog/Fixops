"""Coverage tests for core.security_connectors."""
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.security_connectors import (
    AWSSecurityHubConnector, AzureSecurityCenterConnector, ConnectorHealth, ConnectorOutcome,
)


class TestAWSSecurityHubConnector:
    def test_instantiation(self):
        conn = AWSSecurityHubConnector(settings={"region": "us-east-1"})
        assert conn is not None

    def test_health_check(self):
        conn = AWSSecurityHubConnector(settings={})
        result = conn.health_check()
        assert isinstance(result, ConnectorHealth)

    def test_get_metrics(self):
        conn = AWSSecurityHubConnector(settings={})
        metrics = conn.get_metrics()
        assert isinstance(metrics, dict)

    def test_get_findings(self):
        conn = AWSSecurityHubConnector(settings={})
        result = conn.get_findings(severity="HIGH", max_results=10)
        assert isinstance(result, ConnectorOutcome)

    def test_batch_update_findings(self):
        conn = AWSSecurityHubConnector(settings={})
        result = conn.batch_update_findings(
            finding_ids=[{"Id": "F1", "ProductArn": "arn:aws:test"}],
            workflow_status="RESOLVED",
        )
        assert isinstance(result, ConnectorOutcome)


class TestAzureSecurityCenterConnector:
    def test_instantiation(self):
        conn = AzureSecurityCenterConnector(settings={"subscription_id": "test-sub"})
        assert conn is not None

    def test_health_check(self):
        conn = AzureSecurityCenterConnector(settings={})
        result = conn.health_check()
        assert isinstance(result, ConnectorHealth)

    def test_get_metrics(self):
        conn = AzureSecurityCenterConnector(settings={})
        metrics = conn.get_metrics()
        assert isinstance(metrics, dict)

    def test_get_alerts(self):
        conn = AzureSecurityCenterConnector(settings={})
        result = conn.get_alerts()
        assert isinstance(result, ConnectorOutcome)

    def test_get_assessments(self):
        conn = AzureSecurityCenterConnector(settings={})
        result = conn.get_assessments()
        assert isinstance(result, ConnectorOutcome)
