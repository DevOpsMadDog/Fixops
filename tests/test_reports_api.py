"""
Tests for report management API endpoints.
"""
import pytest

from core.report_db import ReportDB
from core.report_models import Report, ReportFormat, ReportStatus, ReportType


@pytest.fixture
def client(authenticated_client):
    """Create test client using shared authenticated_client fixture."""
    return authenticated_client


@pytest.fixture
def db():
    """Create test database using the same path as the API router."""
    # Use the same database path as the API router (data/reports.db)
    return ReportDB(db_path="data/reports.db")


@pytest.fixture(autouse=True)
def cleanup_db():
    """Clean up test database after each test."""
    yield
    import os

    # Clean up the reports database used by both tests and API
    if os.path.exists("data/reports.db"):
        os.remove("data/reports.db")


def test_list_reports_empty(client):
    """Test listing reports when none exist."""
    response = client.get("/api/v1/reports")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert isinstance(data["items"], list)


def test_generate_report(client):
    """Test generating a new report."""
    response = client.post(
        "/api/v1/reports",
        json={
            "name": "Security Summary Report",
            "report_type": "security_summary",
            "format": "pdf",
            "parameters": {"include_charts": True},
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Security Summary Report"
    assert data["report_type"] == "security_summary"
    assert data["format"] == "pdf"
    assert data["status"] == "completed"


def test_get_report(client, db):
    """Test getting report details."""
    report = Report(
        id="",
        name="Test Report",
        report_type=ReportType.COMPLIANCE,
        format=ReportFormat.HTML,
        status=ReportStatus.COMPLETED,
    )
    created = db.create_report(report)

    response = client.get(f"/api/v1/reports/{created.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == created.id
    assert data["name"] == "Test Report"


def test_get_report_not_found(client):
    """Test getting non-existent report."""
    response = client.get("/api/v1/reports/nonexistent")
    assert response.status_code == 404


def test_download_report(client, db):
    """Test downloading a report."""
    report = Report(
        id="",
        name="Test Report",
        report_type=ReportType.COMPLIANCE,
        format=ReportFormat.PDF,
        status=ReportStatus.COMPLETED,
        file_path="/tmp/test.pdf",
        file_size=1024,
    )
    created = db.create_report(report)

    response = client.get(f"/api/v1/reports/{created.id}/download")
    assert response.status_code == 200
    data = response.json()
    assert "download_url" in data
    assert data["format"] == "pdf"


def test_download_report_not_ready(client, db):
    """Test downloading a report that's not ready."""
    report = Report(
        id="",
        name="Test Report",
        report_type=ReportType.COMPLIANCE,
        format=ReportFormat.PDF,
        status=ReportStatus.PENDING,
    )
    created = db.create_report(report)

    response = client.get(f"/api/v1/reports/{created.id}/download")
    assert response.status_code == 400


def test_schedule_report(client):
    """Test scheduling a recurring report."""
    response = client.post(
        "/api/v1/reports/schedule",
        json={
            "report_type": "security_summary",
            "format": "pdf",
            "schedule_cron": "0 0 * * *",
            "parameters": {},
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["report_type"] == "security_summary"
    assert data["schedule_cron"] == "0 0 * * *"


def test_list_schedules(client):
    """Test listing scheduled reports."""
    response = client.get("/api/v1/reports/schedules/list")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data


def test_list_templates(client):
    """Test listing report templates."""
    response = client.get("/api/v1/reports/templates/list")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data


def test_export_sarif(client):
    """Test exporting findings as SARIF."""
    response = client.post("/api/v1/reports/export/sarif")
    assert response.status_code == 200
    data = response.json()
    assert data["format"] == "sarif"
    assert data["version"] == "2.1.0"


def test_export_csv(client):
    """Test exporting findings as CSV."""
    response = client.post("/api/v1/reports/export/csv")
    assert response.status_code == 200
    data = response.json()
    assert data["format"] == "csv"


def test_list_reports_with_filter(client, db):
    """Test listing reports with type filter."""
    report1 = Report(
        id="",
        name="Security Report",
        report_type=ReportType.SECURITY_SUMMARY,
        format=ReportFormat.PDF,
        status=ReportStatus.COMPLETED,
    )
    report2 = Report(
        id="",
        name="Compliance Report",
        report_type=ReportType.COMPLIANCE,
        format=ReportFormat.HTML,
        status=ReportStatus.COMPLETED,
    )
    db.create_report(report1)
    db.create_report(report2)

    response = client.get("/api/v1/reports?report_type=security_summary")
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) >= 1
    assert all(item["report_type"] == "security_summary" for item in data["items"])


def test_list_reports_pagination(client):
    """Test report list pagination."""
    response = client.get("/api/v1/reports?limit=10&offset=0")
    assert response.status_code == 200
    data = response.json()
    assert data["limit"] == 10
    assert data["offset"] == 0
