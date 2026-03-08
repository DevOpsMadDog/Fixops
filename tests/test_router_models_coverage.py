"""Tests for router Pydantic models — validation, remediation, collaboration request classes."""


class TestRemediationModels:
    def test_create_task_request(self):
        from apps.api.remediation_router import CreateTaskRequest
        req = CreateTaskRequest(
            cluster_id="cluster-1",
            org_id="org-1",
            app_id="APP-001",
            title="Fix SQL injection",
            severity="CRITICAL",
        )
        assert req.cluster_id == "cluster-1"
        assert req.severity == "CRITICAL"
        assert req.description is None
        assert req.assignee is None

    def test_create_task_request_full(self):
        from apps.api.remediation_router import CreateTaskRequest
        req = CreateTaskRequest(
            cluster_id="c1",
            org_id="o1",
            app_id="APP-001",
            title="Fix XSS",
            severity="HIGH",
            description="Fix reflected XSS in login form",
            assignee="alice",
            assignee_email="alice@acme.com",
            metadata={"scanner": "dast"},
        )
        assert req.description == "Fix reflected XSS in login form"
        assert req.metadata["scanner"] == "dast"

    def test_update_status_request(self):
        from apps.api.remediation_router import UpdateStatusRequest
        req = UpdateStatusRequest(status="in_progress")
        assert req.status == "in_progress"
        assert req.changed_by is None

    def test_update_status_request_with_user(self):
        from apps.api.remediation_router import UpdateStatusRequest
        req = UpdateStatusRequest(status="resolved", changed_by="bob")
        assert req.changed_by == "bob"

    def test_router_exists(self):
        from apps.api.remediation_router import router
        assert router is not None
        assert router.prefix == "/api/v1/remediation"


class TestCollaborationModels:
    def test_add_comment_request(self):
        from apps.api.collaboration_router import AddCommentRequest
        req = AddCommentRequest(
            entity_type="finding",
            entity_id="f-001",
            org_id="org-1",
            author="alice",
            content="This is a comment",
        )
        assert req.entity_type == "finding"
        assert req.is_internal is True
        assert req.parent_comment_id is None

    def test_add_watcher_request(self):
        from apps.api.collaboration_router import AddWatcherRequest
        req = AddWatcherRequest(
            entity_type="ticket",
            entity_id="t-001",
            user_id="user-1",
        )
        assert req.entity_type == "ticket"
        assert req.user_email is None

    def test_collaboration_router_exists(self):
        from apps.api.collaboration_router import router
        assert router is not None
        assert router.prefix == "/api/v1/collaboration"

    def test_get_slack_webhook(self, monkeypatch):
        from apps.api.collaboration_router import _get_slack_webhook_url
        monkeypatch.delenv("FIXOPS_SLACK_WEBHOOK_URL", raising=False)
        assert _get_slack_webhook_url() is None

    def test_get_slack_webhook_set(self, monkeypatch):
        from apps.api.collaboration_router import _get_slack_webhook_url
        monkeypatch.setenv("FIXOPS_SLACK_WEBHOOK_URL", "https://hooks.slack.com/test")
        assert _get_slack_webhook_url() == "https://hooks.slack.com/test"


class TestValidationModels:
    def test_validation_result(self):
        from apps.api.validation_router import ValidationResult
        result = ValidationResult(
            valid=True,
            input_type="sarif",
            detected_format="sarif-2.1.0",
            findings_count=5,
        )
        assert result.valid is True
        assert result.findings_count == 5
        assert result.warnings == []
        assert result.errors == []

    def test_validation_result_invalid(self):
        from apps.api.validation_router import ValidationResult
        result = ValidationResult(
            valid=False,
            input_type="unknown",
            errors=["Unsupported format"],
        )
        assert result.valid is False
        assert len(result.errors) == 1

    def test_validation_router_exists(self):
        from apps.api.validation_router import router
        assert router is not None
        assert router.prefix == "/api/v1/validate"

    def test_max_validation_size(self):
        from apps.api.validation_router import MAX_VALIDATION_SIZE
        assert MAX_VALIDATION_SIZE == 8 * 1024 * 1024


class TestPoliciesModels:
    def test_policies_router_exists(self):
        from apps.api.policies_router import router
        assert router is not None

    def test_audit_router_exists(self):
        from apps.api.audit_router import router
        assert router is not None

    def test_system_router_exists(self):
        from apps.api.system_router import router
        assert router is not None

    def test_admin_router_exists(self):
        from apps.api.admin_router import router
        assert router is not None

    def test_users_router_exists(self):
        from apps.api.users_router import router
        assert router is not None

    def test_teams_router_exists(self):
        from apps.api.teams_router import router
        assert router is not None

    def test_auth_router_exists(self):
        from apps.api.auth_router import router
        assert router is not None
