"""Tests for core.logging_config — structured logging with correlation IDs."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.logging_config import (
    add_correlation_id,
    add_service_context,
    clear_correlation_id,
    get_correlation_id,
    redact_sensitive_data,
    set_correlation_id,
)


# ── Correlation ID ──────────────────────────────────────────────────

class TestCorrelationId:
    def test_default_is_none(self):
        clear_correlation_id()
        assert get_correlation_id() is None

    def test_set_and_get(self):
        set_correlation_id("corr-123")
        assert get_correlation_id() == "corr-123"
        clear_correlation_id()

    def test_clear(self):
        set_correlation_id("corr-456")
        clear_correlation_id()
        assert get_correlation_id() is None

    def test_overwrite(self):
        set_correlation_id("first")
        set_correlation_id("second")
        assert get_correlation_id() == "second"
        clear_correlation_id()


# ── add_correlation_id processor ────────────────────────────────────

class TestAddCorrelationId:
    def test_adds_when_present(self):
        set_correlation_id("req-789")
        event_dict = {"event": "test"}
        result = add_correlation_id(None, "info", event_dict)
        assert result["correlation_id"] == "req-789"
        clear_correlation_id()

    def test_skips_when_absent(self):
        clear_correlation_id()
        event_dict = {"event": "test"}
        result = add_correlation_id(None, "info", event_dict)
        assert "correlation_id" not in result


# ── add_service_context processor ───────────────────────────────────

class TestAddServiceContext:
    def test_adds_service(self):
        event_dict = {"event": "test"}
        result = add_service_context(None, "info", event_dict)
        assert "service" in result
        assert result["service"] == "fixops-api"

    def test_adds_environment(self):
        event_dict = {"event": "test"}
        result = add_service_context(None, "info", event_dict)
        assert "environment" in result

    def test_adds_version(self):
        event_dict = {"event": "test"}
        result = add_service_context(None, "info", event_dict)
        assert "version" in result

    def test_does_not_overwrite(self):
        event_dict = {"event": "test", "service": "custom-service"}
        result = add_service_context(None, "info", event_dict)
        assert result["service"] == "custom-service"


# ── redact_sensitive_data processor ─────────────────────────────────

class TestRedactSensitiveData:
    def test_redacts_password(self):
        event_dict = {"event": "login", "password": "secret123"}
        result = redact_sensitive_data(None, "info", event_dict)
        assert result["password"] == "***REDACTED***"

    def test_redacts_token(self):
        event_dict = {"event": "auth", "token": "jwt-abc-123"}
        result = redact_sensitive_data(None, "info", event_dict)
        assert result["token"] == "***REDACTED***"

    def test_redacts_api_key(self):
        event_dict = {"event": "request", "api_key": "sk-12345"}
        result = redact_sensitive_data(None, "info", event_dict)
        assert result["api_key"] == "***REDACTED***"

    def test_redacts_authorization(self):
        event_dict = {"event": "request", "authorization": "Bearer xyz"}
        result = redact_sensitive_data(None, "info", event_dict)
        assert result["authorization"] == "***REDACTED***"

    def test_preserves_non_sensitive(self):
        event_dict = {"event": "test", "user": "john", "status": "ok"}
        result = redact_sensitive_data(None, "info", event_dict)
        assert result["user"] == "john"
        assert result["status"] == "ok"

    def test_case_insensitive(self):
        event_dict = {"event": "test", "Password": "secret"}
        result = redact_sensitive_data(None, "info", event_dict)
        assert result["Password"] == "***REDACTED***"

    def test_nested_dict_redacted(self):
        event_dict = {
            "event": "test",
            "config": {"api_key": "key123", "host": "localhost"},
        }
        result = redact_sensitive_data(None, "info", event_dict)
        assert result["config"]["api_key"] == "***REDACTED***"
        assert result["config"]["host"] == "localhost"
