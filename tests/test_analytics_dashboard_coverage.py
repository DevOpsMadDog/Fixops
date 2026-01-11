"""
Tests for analytics_router.py dashboard endpoints to ensure 100% diff coverage.
"""


def test_dashboard_overview_with_org_id(authenticated_client):
    """Test dashboard overview endpoint with org_id parameter."""
    response = authenticated_client.get(
        "/api/v1/analytics/dashboard/overview?org_id=test-org"
    )
    assert response.status_code == 200
    data = response.json()
    assert data.get("org_id") == "test-org"


def test_dashboard_trends_with_org_id(authenticated_client):
    """Test dashboard trends endpoint with org_id parameter."""
    response = authenticated_client.get(
        "/api/v1/analytics/dashboard/trends?org_id=test-org&days=7"
    )
    assert response.status_code == 200
    data = response.json()
    assert data.get("org_id") == "test-org"
    assert data.get("period_days") == 7


def test_dashboard_top_risks_with_org_id(authenticated_client):
    """Test dashboard top-risks endpoint with org_id parameter."""
    response = authenticated_client.get(
        "/api/v1/analytics/dashboard/top-risks?org_id=test-org&limit=5"
    )
    assert response.status_code == 200
    data = response.json()
    assert data.get("org_id") == "test-org"
