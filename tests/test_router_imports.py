"""
Test that all router modules can be imported successfully.

This test ensures that import statements and module-level code
in router modules are covered by the test suite.
"""


def test_import_analytics_router():
    """Test that analytics_router can be imported."""
    from apps.api import analytics_router

    assert analytics_router.router is not None


def test_import_audit_router():
    """Test that audit_router can be imported."""
    from apps.api import audit_router

    assert audit_router.router is not None


def test_import_feeds_router():
    """Test that feeds_router can be imported."""
    from apps.api import feeds_router

    assert feeds_router.router is not None


def test_import_integrations_router():
    """Test that integrations_router can be imported."""
    from apps.api import integrations_router

    assert integrations_router.router is not None


def test_import_inventory_router():
    """Test that inventory_router can be imported."""
    from apps.api import inventory_router

    assert inventory_router.router is not None


def test_import_mpte_router():
    """Test that mpte_router can be imported."""
    from apps.api import mpte_router

    assert mpte_router.router is not None


def test_import_policies_router():
    """Test that policies_router can be imported."""
    from apps.api import policies_router

    assert policies_router.router is not None


def test_import_reports_router():
    """Test that reports_router can be imported."""
    from apps.api import reports_router

    assert reports_router.router is not None


def test_import_teams_router():
    """Test that teams_router can be imported."""
    from apps.api import teams_router

    assert teams_router.router is not None


def test_import_users_router():
    """Test that users_router can be imported."""
    from apps.api import users_router

    assert users_router.router is not None


def test_import_webhooks_router():
    """Test that webhooks_router can be imported."""
    from apps.api import webhooks_router

    assert webhooks_router.router is not None


def test_import_workflows_router():
    """Test that workflows_router can be imported."""
    from apps.api import workflows_router

    assert workflows_router.router is not None


def test_import_dependencies():
    """Test that dependencies module can be imported."""
    from apps.api import dependencies

    assert dependencies.get_org_id is not None
