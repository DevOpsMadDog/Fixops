"""Tests for risk.dependency_realtime module.

Covers: RealTimeDependencyScanner, WebhookHandler, data classes,
watch/unwatch, callbacks, scan cycle (mocked network), webhook processing.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from risk.dependency_realtime import (
    DependencyUpdate,
    RealTimeDependencyScanner,
    VulnerabilityAlert,
    WebhookHandler,
)


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def scanner() -> RealTimeDependencyScanner:
    return RealTimeDependencyScanner()


@pytest.fixture
def scanner_with_deps(scanner) -> RealTimeDependencyScanner:
    scanner.watch_dependency("requests", "pypi", "2.31.0")
    scanner.watch_dependency("express", "npm", "4.18.2")
    return scanner


@pytest.fixture
def webhook_handler(scanner) -> WebhookHandler:
    return WebhookHandler(scanner)


# ── Data classes ──────────────────────────────────────────────────────────


class TestDataClasses:
    def test_dependency_update(self):
        u = DependencyUpdate(
            package_name="requests",
            package_manager="pypi",
            old_version="2.30.0",
            new_version="2.31.0",
            vulnerability_count=0,
            critical_vulnerability_count=0,
        )
        assert u.package_name == "requests"
        assert u.timestamp is not None

    def test_vulnerability_alert(self):
        a = VulnerabilityAlert(
            cve_id="CVE-2024-0001",
            package_name="flask",
            package_version="2.0.0",
            severity="critical",
            description="Remote code execution",
        )
        assert a.cve_id == "CVE-2024-0001"
        assert a.severity == "critical"
        assert a.timestamp is not None


# ── Scanner init ──────────────────────────────────────────────────────────


class TestScannerInit:
    def test_defaults(self, scanner):
        assert scanner.watched_dependencies == {}
        assert scanner.update_callbacks == []
        assert scanner.alert_callbacks == []
        assert scanner.scanning is False
        assert scanner.scan_interval == 60

    def test_custom_interval(self):
        s = RealTimeDependencyScanner({"scan_interval": 30})
        assert s.scan_interval == 30


# ── Watch / unwatch ───────────────────────────────────────────────────────


class TestWatchDependency:
    def test_watch(self, scanner):
        scanner.watch_dependency("requests", "pypi", "2.31.0")
        assert "pypi:requests" in scanner.watched_dependencies
        dep = scanner.watched_dependencies["pypi:requests"]
        assert dep["package_name"] == "requests"
        assert dep["current_version"] == "2.31.0"
        assert dep["last_scan"] is None

    def test_watch_with_metadata(self, scanner):
        scanner.watch_dependency(
            "spring-core", "maven", "6.1.0", {"group_id": "org.springframework"}
        )
        dep = scanner.watched_dependencies["maven:spring-core"]
        assert dep["metadata"]["group_id"] == "org.springframework"

    def test_unwatch(self, scanner_with_deps):
        scanner_with_deps.unwatch_dependency("requests", "pypi")
        assert "pypi:requests" not in scanner_with_deps.watched_dependencies
        assert "npm:express" in scanner_with_deps.watched_dependencies

    def test_unwatch_nonexistent(self, scanner):
        # Should not raise
        scanner.unwatch_dependency("ghost", "npm")


# ── Callbacks ─────────────────────────────────────────────────────────────


class TestCallbacks:
    def test_register_update_callback(self, scanner):
        cb = MagicMock()
        scanner.register_update_callback(cb)
        assert cb in scanner.update_callbacks

    def test_register_alert_callback(self, scanner):
        cb = MagicMock()
        scanner.register_alert_callback(cb)
        assert cb in scanner.alert_callbacks

    def test_multiple_callbacks(self, scanner):
        cb1 = MagicMock()
        cb2 = MagicMock()
        scanner.register_update_callback(cb1)
        scanner.register_update_callback(cb2)
        assert len(scanner.update_callbacks) == 2


# ── Start / stop monitoring ───────────────────────────────────────────────


class TestMonitoring:
    def test_stop_monitoring(self, scanner):
        scanner.scanning = True
        scanner.stop_monitoring()
        assert scanner.scanning is False

    @pytest.mark.asyncio
    async def test_start_monitoring_sets_scanning(self, scanner):
        """Start monitoring sets scanning flag, then we stop it."""
        scanner.scan_interval = 0.01
        # Mock _scan_cycle to stop after first call
        call_count = 0

        async def mock_scan():
            nonlocal call_count
            call_count += 1
            if call_count >= 1:
                scanner.scanning = False

        scanner._scan_cycle = mock_scan
        await scanner.start_monitoring()
        assert call_count >= 1
        assert scanner.scanning is False


# ── Scan cycle (mocked network) ──────────────────────────────────────────


class TestScanCycle:
    @pytest.mark.asyncio
    async def test_scan_cycle_calls_check_methods(self, scanner_with_deps):
        scanner_with_deps._check_for_updates = AsyncMock(return_value=None)
        scanner_with_deps._check_for_vulnerabilities = AsyncMock(return_value=[])

        await scanner_with_deps._scan_cycle()

        assert scanner_with_deps._check_for_updates.call_count == 2
        assert scanner_with_deps._check_for_vulnerabilities.call_count == 2

    @pytest.mark.asyncio
    async def test_scan_cycle_notifies_update_callbacks(self, scanner):
        scanner.watch_dependency("pkg", "npm", "1.0.0")
        scanner._check_for_updates = AsyncMock(
            return_value={"new_version": "2.0.0", "vulnerability_count": 0}
        )
        scanner._check_for_vulnerabilities = AsyncMock(return_value=[])

        updates_received = []
        scanner.register_update_callback(lambda u: updates_received.append(u))

        await scanner._scan_cycle()
        assert len(updates_received) == 1
        assert updates_received[0].new_version == "2.0.0"
        # Version should be updated
        assert scanner.watched_dependencies["npm:pkg"]["current_version"] == "2.0.0"

    @pytest.mark.asyncio
    async def test_scan_cycle_notifies_alert_callbacks(self, scanner):
        scanner.watch_dependency("pkg", "npm", "1.0.0")
        scanner._check_for_updates = AsyncMock(return_value=None)
        alert = VulnerabilityAlert(
            cve_id="CVE-2024-0001",
            package_name="pkg",
            package_version="1.0.0",
            severity="critical",
            description="RCE",
        )
        scanner._check_for_vulnerabilities = AsyncMock(return_value=[alert])

        alerts_received = []
        scanner.register_alert_callback(lambda a: alerts_received.append(a))

        await scanner._scan_cycle()
        assert len(alerts_received) == 1
        assert alerts_received[0].cve_id == "CVE-2024-0001"

    @pytest.mark.asyncio
    async def test_scan_cycle_callback_error_doesnt_crash(self, scanner):
        scanner.watch_dependency("pkg", "npm", "1.0.0")
        scanner._check_for_updates = AsyncMock(
            return_value={"new_version": "2.0.0"}
        )
        scanner._check_for_vulnerabilities = AsyncMock(return_value=[])
        scanner.register_update_callback(lambda u: (_ for _ in ()).throw(ValueError))
        # Should not raise
        await scanner._scan_cycle()

    @pytest.mark.asyncio
    async def test_scan_cycle_handles_dep_error(self, scanner):
        scanner.watch_dependency("bad", "npm", "1.0.0")
        scanner._check_for_updates = AsyncMock(
            side_effect=RuntimeError("network fail")
        )
        # Should not raise
        await scanner._scan_cycle()

    @pytest.mark.asyncio
    async def test_scan_cycle_updates_last_scan(self, scanner):
        scanner.watch_dependency("pkg", "npm", "1.0.0")
        scanner._check_for_updates = AsyncMock(return_value=None)
        scanner._check_for_vulnerabilities = AsyncMock(return_value=[])
        await scanner._scan_cycle()
        assert scanner.watched_dependencies["npm:pkg"]["last_scan"] is not None


# ── _check_for_updates (mocked httpx) ────────────────────────────────────


class TestCheckForUpdates:
    @pytest.mark.asyncio
    async def test_empty_package_name(self, scanner):
        result = await scanner._check_for_updates(
            {"package_name": "", "package_manager": "npm", "current_version": "1.0"}
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_empty_package_manager(self, scanner):
        result = await scanner._check_for_updates(
            {"package_name": "pkg", "package_manager": "", "current_version": "1.0"}
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_httpx_import_error(self, scanner):
        """When httpx is not importable, returns None."""
        dep_info = {
            "package_name": "pkg",
            "package_manager": "npm",
            "current_version": "1.0",
        }
        with patch.dict("sys.modules", {"httpx": None}):
            result = await scanner._check_for_updates(dep_info)
            assert result is None


# ── _check_for_vulnerabilities (mocked) ──────────────────────────────────


class TestCheckForVulnerabilities:
    @pytest.mark.asyncio
    async def test_empty_package_name(self, scanner):
        result = await scanner._check_for_vulnerabilities(
            {"package_name": "", "current_version": "1.0", "package_manager": "npm"}
        )
        assert result == []

    @pytest.mark.asyncio
    async def test_empty_version(self, scanner):
        result = await scanner._check_for_vulnerabilities(
            {"package_name": "pkg", "current_version": "", "package_manager": "npm"}
        )
        assert result == []

    @pytest.mark.asyncio
    async def test_unknown_ecosystem(self, scanner):
        """Unknown package manager returns empty alerts."""
        dep = {
            "package_name": "pkg",
            "current_version": "1.0",
            "package_manager": "unknown_pm",
        }
        with patch.dict("sys.modules", {"httpx": None}):
            result = await scanner._check_for_vulnerabilities(dep)
            assert result == []


# ── WebhookHandler ────────────────────────────────────────────────────────


class TestWebhookHandler:
    @pytest.mark.asyncio
    async def test_vulnerability_discovered(self, webhook_handler, scanner):
        alerts = []
        scanner.register_alert_callback(lambda a: alerts.append(a))

        result = await webhook_handler.handle_webhook(
            {
                "event_type": "vulnerability_discovered",
                "cve_id": "CVE-2024-9999",
                "package_name": "flask",
                "package_version": "2.0.0",
                "severity": "critical",
                "description": "RCE via debug mode",
            }
        )
        assert result["status"] == "processed"
        assert result["alert_id"] == "CVE-2024-9999"
        assert len(alerts) == 1
        assert alerts[0].cve_id == "CVE-2024-9999"

    @pytest.mark.asyncio
    async def test_package_updated(self, webhook_handler, scanner):
        updates = []
        scanner.register_update_callback(lambda u: updates.append(u))

        result = await webhook_handler.handle_webhook(
            {
                "event_type": "package_updated",
                "package_name": "requests",
                "package_manager": "pypi",
                "old_version": "2.30.0",
                "new_version": "2.31.0",
                "vulnerability_count": 0,
                "critical_vulnerability_count": 0,
            }
        )
        assert result["status"] == "processed"
        assert result["package"] == "requests"
        assert len(updates) == 1

    @pytest.mark.asyncio
    async def test_unknown_event(self, webhook_handler):
        result = await webhook_handler.handle_webhook(
            {"event_type": "random_event"}
        )
        assert result["status"] == "unknown_event"

    @pytest.mark.asyncio
    async def test_webhook_callback_error(self, webhook_handler, scanner):
        """Callback error doesn't crash webhook handler."""
        scanner.register_alert_callback(
            lambda a: (_ for _ in ()).throw(ValueError)
        )
        result = await webhook_handler.handle_webhook(
            {
                "event_type": "vulnerability_discovered",
                "cve_id": "CVE-2024-0001",
                "package_name": "x",
                "package_version": "1.0",
                "severity": "high",
                "description": "bug",
            }
        )
        assert result["status"] == "processed"

    @pytest.mark.asyncio
    async def test_webhook_update_callback_error(self, webhook_handler, scanner):
        """Update callback error doesn't crash."""
        scanner.register_update_callback(
            lambda u: (_ for _ in ()).throw(RuntimeError)
        )
        result = await webhook_handler.handle_webhook(
            {
                "event_type": "package_updated",
                "package_name": "x",
                "package_manager": "npm",
                "old_version": "1.0",
                "new_version": "2.0",
            }
        )
        assert result["status"] == "processed"
