"""
Tests for apps/api/dependencies.py to ensure 100% diff coverage.
"""
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException


def test_get_org_id_from_query_param():
    """Test get_org_id with query parameter."""
    from apps.api.dependencies import get_org_id

    result = get_org_id(org_id="test-org", x_org_id=None)
    assert result == "test-org"


def test_get_org_id_from_header():
    """Test get_org_id with X-Org-ID header."""
    from apps.api.dependencies import get_org_id

    result = get_org_id(org_id=None, x_org_id="header-org")
    assert result == "header-org"


def test_get_org_id_default():
    """Test get_org_id returns default when no org_id provided."""
    from apps.api.dependencies import get_org_id

    result = get_org_id(org_id=None, x_org_id=None)
    assert result == "default"


def test_get_org_id_query_takes_priority():
    """Test get_org_id query param takes priority over header."""
    from apps.api.dependencies import get_org_id

    result = get_org_id(org_id="query-org", x_org_id="header-org")
    assert result == "query-org"


def test_get_org_id_required_from_query():
    """Test get_org_id_required with query parameter."""
    from apps.api.dependencies import get_org_id_required

    result = get_org_id_required(org_id="test-org", x_org_id=None)
    assert result == "test-org"


def test_get_org_id_required_from_header():
    """Test get_org_id_required with X-Org-ID header."""
    from apps.api.dependencies import get_org_id_required

    result = get_org_id_required(org_id=None, x_org_id="header-org")
    assert result == "header-org"


def test_get_org_id_required_raises_when_missing():
    """Test get_org_id_required raises HTTPException when no org_id provided."""
    from apps.api.dependencies import get_org_id_required

    with pytest.raises(HTTPException) as exc_info:
        get_org_id_required(org_id=None, x_org_id=None)

    assert exc_info.value.status_code == 400
    assert "org_id is required" in exc_info.value.detail


def test_get_correlation_id_from_request():
    """Test get_correlation_id extracts correlation_id from request state."""
    from apps.api.dependencies import get_correlation_id

    mock_request = MagicMock()
    mock_request.state.correlation_id = "test-correlation-id"

    result = get_correlation_id(mock_request)
    assert result == "test-correlation-id"


def test_get_correlation_id_returns_none_when_not_set():
    """Test get_correlation_id returns None when correlation_id not in state."""
    from apps.api.dependencies import get_correlation_id

    mock_request = MagicMock()
    # Remove the correlation_id attribute
    del mock_request.state.correlation_id

    result = get_correlation_id(mock_request)
    assert result is None
