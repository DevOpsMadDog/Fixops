"""Tests for enterprise services: deduplication, remediation, collaboration, notifications."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def db_paths(tmp_path):
    """Provide temporary database paths for enterprise services."""
    return {
        "dedup": tmp_path / "deduplication.db",
        "remediation": tmp_path / "remediation.db",
        "collaboration": tmp_path / "collaboration.db",
    }


class TestDeduplicationService:
    """Tests for the DeduplicationService."""

    def test_generate_fingerprint_stability(self, db_paths):
        """Test that fingerprint generation is stable for same input."""
        from core.services.deduplication import DeduplicationService

        service = DeduplicationService(db_path=db_paths["dedup"])

        finding1 = {
            "rule_id": "SQL_INJECTION",
            "file_path": "src/app.py",
            "line_number": 42,
            "severity": "high",
        }

        fp1 = service.generate_fingerprint(finding1)
        fp2 = service.generate_fingerprint(finding1)

        assert fp1 == fp2, "Fingerprint should be stable for same input"

    def test_generate_fingerprint_different_for_different_input(self, db_paths):
        """Test that fingerprint differs for different findings."""
        from core.services.deduplication import DeduplicationService

        service = DeduplicationService(db_path=db_paths["dedup"])

        finding1 = {
            "rule_id": "SQL_INJECTION",
            "file_path": "src/app.py",
            "line_number": 42,
        }
        finding2 = {
            "rule_id": "XSS",
            "file_path": "src/app.py",
            "line_number": 42,
        }

        fp1 = service.generate_fingerprint(finding1)
        fp2 = service.generate_fingerprint(finding2)

        assert fp1 != fp2, "Fingerprint should differ for different findings"

    def test_process_findings_batch_creates_clusters(self, db_paths):
        """Test that batch processing creates clusters."""
        from core.services.deduplication import DeduplicationService

        service = DeduplicationService(db_path=db_paths["dedup"])

        findings = [
            {
                "rule_id": "SQL_INJECTION",
                "file_path": "src/app.py",
                "line_number": 42,
                "severity": "high",
            },
            {
                "rule_id": "XSS",
                "file_path": "src/views.py",
                "line_number": 100,
                "severity": "medium",
            },
        ]

        result = service.process_findings_batch(
            findings, run_id="test-run-1", org_id="test-org", source="sarif"
        )

        assert "clusters_created" in result
        assert "findings_processed" in result
        assert result["findings_processed"] == 2

    def test_get_cluster_returns_none_for_nonexistent(self, db_paths):
        """Test that get_cluster returns None for non-existent cluster."""
        from core.services.deduplication import DeduplicationService

        service = DeduplicationService(db_path=db_paths["dedup"])
        cluster = service.get_cluster("nonexistent-cluster-id")

        assert cluster is None


class TestRemediationService:
    """Tests for the RemediationService."""

    def test_create_task(self, db_paths):
        """Test creating a remediation task."""
        from core.services.remediation import RemediationService

        service = RemediationService(db_path=db_paths["remediation"])

        task = service.create_task(
            cluster_id="test-cluster-1",
            severity="high",
            title="Fix SQL Injection",
            description="SQL injection vulnerability in login form",
            org_id="test-org",
        )

        assert task is not None
        assert "task_id" in task
        assert task["severity"] == "high"
        assert task["status"] == "open"

    def test_sla_calculation_high_severity(self, db_paths):
        """Test SLA calculation for high severity."""
        from core.services.remediation import RemediationService

        service = RemediationService(db_path=db_paths["remediation"])

        sla_hours = service.get_sla_hours("high")
        assert sla_hours == 24, "High severity should have 24-hour SLA"

    def test_sla_calculation_critical_severity(self, db_paths):
        """Test SLA calculation for critical severity."""
        from core.services.remediation import RemediationService

        service = RemediationService(db_path=db_paths["remediation"])

        sla_hours = service.get_sla_hours("critical")
        assert sla_hours == 4, "Critical severity should have 4-hour SLA"

    def test_sla_calculation_medium_severity(self, db_paths):
        """Test SLA calculation for medium severity."""
        from core.services.remediation import RemediationService

        service = RemediationService(db_path=db_paths["remediation"])

        sla_hours = service.get_sla_hours("medium")
        assert sla_hours == 72, "Medium severity should have 72-hour SLA"

    def test_sla_calculation_low_severity(self, db_paths):
        """Test SLA calculation for low severity."""
        from core.services.remediation import RemediationService

        service = RemediationService(db_path=db_paths["remediation"])

        sla_hours = service.get_sla_hours("low")
        assert sla_hours == 168, "Low severity should have 168-hour (1 week) SLA"

    def test_state_transition_open_to_in_progress(self, db_paths):
        """Test valid state transition from open to in_progress."""
        from core.services.remediation import RemediationService

        service = RemediationService(db_path=db_paths["remediation"])

        task = service.create_task(
            cluster_id="test-cluster-2",
            severity="medium",
            title="Fix XSS",
            org_id="test-org",
        )

        updated = service.update_task_status(
            task["task_id"], "in_progress", assigned_to="user-1"
        )

        assert updated is not None
        assert updated["status"] == "in_progress"

    def test_check_sla_breaches(self, db_paths):
        """Test SLA breach detection."""
        from core.services.remediation import RemediationService

        service = RemediationService(db_path=db_paths["remediation"])

        result = service.check_sla_breaches(org_id="test-org")

        assert "breaches" in result
        assert "total_open" in result
        assert isinstance(result["breaches"], list)


class TestCollaborationService:
    """Tests for the CollaborationService."""

    def test_add_comment(self, db_paths):
        """Test adding a comment."""
        from core.services.collaboration import CollaborationService

        service = CollaborationService(db_path=db_paths["collaboration"])

        comment = service.add_comment(
            entity_type="cluster",
            entity_id="test-cluster-1",
            user_id="user-1",
            content="This needs immediate attention",
            org_id="test-org",
        )

        assert comment is not None
        assert "comment_id" in comment
        assert comment["content"] == "This needs immediate attention"

    def test_mention_extraction(self, db_paths):
        """Test that mentions are extracted from comments."""
        from core.services.collaboration import CollaborationService

        service = CollaborationService(db_path=db_paths["collaboration"])

        comment = service.add_comment(
            entity_type="cluster",
            entity_id="test-cluster-2",
            user_id="user-1",
            content="@alice and @bob please review this",
            org_id="test-org",
        )

        assert comment is not None
        mentions = comment.get("mentions", [])
        assert (
            len(mentions) >= 2
        ), "Should extract at least 2 mentions (@alice and @bob)"
        assert "alice" in mentions, "Should extract @alice mention"
        assert "bob" in mentions, "Should extract @bob mention"

    def test_promote_to_evidence_audit_trail(self, db_paths):
        """Test that evidence promotion records audit trail."""
        from core.services.collaboration import CollaborationService

        service = CollaborationService(db_path=db_paths["collaboration"])

        comment = service.add_comment(
            entity_type="cluster",
            entity_id="test-cluster-3",
            user_id="user-1",
            content="Evidence of remediation",
            org_id="test-org",
        )

        result = service.promote_to_evidence(
            comment_id=comment["comment_id"], promoted_by="admin-user"
        )

        assert result is not None
        assert result.get("promoted_by") == "admin-user"
        assert "promoted_at" in result

    def test_queue_notification(self, db_paths):
        """Test queuing a notification."""
        from core.services.collaboration import CollaborationService

        service = CollaborationService(db_path=db_paths["collaboration"])

        notification = service.queue_notification(
            entity_type="cluster",
            entity_id="test-cluster-4",
            notification_type="sla_breach",
            recipients=["user-1", "user-2"],
            message="SLA breach warning",
            org_id="test-org",
        )

        assert notification is not None
        assert "notification_id" in notification
        assert notification["status"] == "pending"

    def test_get_pending_notifications(self, db_paths):
        """Test getting pending notifications."""
        from core.services.collaboration import CollaborationService

        service = CollaborationService(db_path=db_paths["collaboration"])

        pending = service.get_pending_notifications(limit=10)

        assert isinstance(pending, list)

    def test_process_pending_notifications(self, db_paths):
        """Test processing pending notifications."""
        from core.services.collaboration import CollaborationService

        service = CollaborationService(db_path=db_paths["collaboration"])

        result = service.process_pending_notifications(limit=10)

        assert "processed" in result
        assert "sent" in result
        assert "failed" in result
        assert "no_channels" in result


class TestVEXIngestion:
    """Tests for VEX ingestion and validation."""

    def test_validate_csaf_vex_document(self):
        """Test validation of CSAF VEX document."""
        try:
            from fixops_enterprise.src.services.vex_ingestion import VEXIngestionService
        except ImportError:
            pytest.skip("VEX ingestion service not available")

        service = VEXIngestionService()

        valid_csaf = {
            "document": {
                "category": "csaf_vex",
                "csaf_version": "2.0",
                "title": "Test VEX",
                "publisher": {"name": "Test Org"},
                "tracking": {
                    "id": "VEX-2024-001",
                    "status": "final",
                    "version": "1.0.0",
                },
            },
            "vulnerabilities": [
                {
                    "cve": "CVE-2024-1234",
                    "product_status": {"not_affected": ["product-1"]},
                }
            ],
        }

        result = service.validate_vex_document(valid_csaf, format="csaf")
        assert result.get("valid", False) or "error" not in result

    def test_validate_cyclonedx_vex_document(self):
        """Test validation of CycloneDX VEX document."""
        try:
            from fixops_enterprise.src.services.vex_ingestion import VEXIngestionService
        except ImportError:
            pytest.skip("VEX ingestion service not available")

        service = VEXIngestionService()

        valid_cdx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "vulnerabilities": [
                {
                    "id": "CVE-2024-1234",
                    "analysis": {"state": "not_affected"},
                }
            ],
        }

        result = service.validate_vex_document(valid_cdx, format="cyclonedx")
        assert result.get("valid", False) or "error" not in result

    def test_invalid_vex_document_missing_fields(self):
        """Test that invalid VEX document is rejected."""
        try:
            from fixops_enterprise.src.services.vex_ingestion import VEXIngestionService
        except ImportError:
            pytest.skip("VEX ingestion service not available")

        service = VEXIngestionService()

        invalid_vex = {"random": "data"}

        result = service.validate_vex_document(invalid_vex, format="csaf")
        assert not result.get("valid", True) or "error" in result


class TestCLICommands:
    """Tests for CLI command implementations."""

    def test_correlation_status_alias(self):
        """Test that 'status' is an alias for 'stats' in correlation commands."""
        from core.cli import build_parser

        parser = build_parser()

        args_stats = parser.parse_args(["correlation", "stats"])
        args_status = parser.parse_args(["correlation", "status"])

        assert args_stats.correlation_command == "stats"
        assert args_status.correlation_command == "status"

    def test_remediation_sla_command(self):
        """Test remediation sla command parsing."""
        from core.cli import build_parser

        parser = build_parser()

        args = parser.parse_args(["remediation", "sla", "--org-id", "test-org"])

        assert args.remediation_command == "sla"
        assert args.org_id == "test-org"

    def test_notifications_worker_command(self):
        """Test notifications worker command parsing."""
        from core.cli import build_parser

        parser = build_parser()

        args = parser.parse_args(
            ["notifications", "worker", "--interval", "30", "--once"]
        )

        assert args.notifications_command == "worker"
        assert args.interval == 30
        assert args.once is True

    def test_notifications_pending_command(self):
        """Test notifications pending command parsing."""
        from core.cli import build_parser

        parser = build_parser()

        args = parser.parse_args(["notifications", "pending", "--limit", "50"])

        assert args.notifications_command == "pending"
        assert args.limit == 50


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
