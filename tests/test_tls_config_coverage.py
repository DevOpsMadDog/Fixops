"""Tests for core.tls_config — TLS verification configuration."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.tls_config import tls_verify


class TestTlsVerify:
    def test_default_is_true(self, monkeypatch):
        monkeypatch.delenv("FIXOPS_TLS_VERIFY", raising=False)
        monkeypatch.delenv("FIXOPS_CA_BUNDLE", raising=False)
        assert tls_verify() is True

    def test_verify_false(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_TLS_VERIFY", "false")
        monkeypatch.delenv("FIXOPS_CA_BUNDLE", raising=False)
        assert tls_verify() is False

    def test_verify_false_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_TLS_VERIFY", "FALSE")
        monkeypatch.delenv("FIXOPS_CA_BUNDLE", raising=False)
        assert tls_verify() is False

    def test_verify_false_with_whitespace(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_TLS_VERIFY", "  false  ")
        monkeypatch.delenv("FIXOPS_CA_BUNDLE", raising=False)
        assert tls_verify() is False

    def test_ca_bundle_path(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_TLS_VERIFY", "true")
        monkeypatch.setenv("FIXOPS_CA_BUNDLE", "/etc/ssl/custom-ca.pem")
        assert tls_verify() == "/etc/ssl/custom-ca.pem"

    def test_ca_bundle_overrides_default(self, monkeypatch):
        monkeypatch.delenv("FIXOPS_TLS_VERIFY", raising=False)
        monkeypatch.setenv("FIXOPS_CA_BUNDLE", "/opt/certs/ca.pem")
        assert tls_verify() == "/opt/certs/ca.pem"

    def test_empty_ca_bundle_returns_true(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_TLS_VERIFY", "true")
        monkeypatch.setenv("FIXOPS_CA_BUNDLE", "")
        assert tls_verify() is True

    def test_whitespace_ca_bundle_returns_true(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_TLS_VERIFY", "true")
        monkeypatch.setenv("FIXOPS_CA_BUNDLE", "   ")
        assert tls_verify() is True

    def test_verify_true_explicit(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_TLS_VERIFY", "true")
        monkeypatch.delenv("FIXOPS_CA_BUNDLE", raising=False)
        assert tls_verify() is True
