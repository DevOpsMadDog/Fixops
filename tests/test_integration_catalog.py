"""A tenant with nothing connected must still see what it can connect.

``GET /api/v1/integrations`` lists what an org has *registered*, so a fresh install
correctly answers ``[]``. The effect, though, is that the first thing a buyer opens is an
empty screen — for a product whose thesis is that it already speaks their tools. The
empty list is honest and useless at once.

The catalogue answers the other question: what could I connect, and what would I need?

Its important property is that it is **generated from the code that enforces the
requirement**. Each integration declares its needs once, in the ``NotConfigured`` raised
when credentials are absent, and the catalogue harvests those same declarations — so it
cannot drift from runtime behaviour, and an integration nobody wired up never appears in
it.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from apps.api.app import create_app
from tests.conftest import API_TOKEN


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(create_app())


@pytest.fixture(scope="module")
def catalog(client: TestClient) -> dict:
    response = client.get(
        "/api/v1/integrations/catalog",
        headers={"X-API-Key": API_TOKEN, "X-Org-ID": "default"},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_catalogue_is_not_empty(catalog: dict) -> None:
    """The whole point is that a tenant with nothing connected still sees reach."""
    assert catalog["total"] > 0, "catalogue is empty — nothing declares its requirements"
    assert len(catalog["integrations"]) == catalog["total"]


def test_every_entry_states_exactly_what_it_needs(catalog: dict) -> None:
    """'Not configured' is only useful if it says what to configure."""
    for entry in catalog["integrations"]:
        assert entry["service"], "an entry has no service name"
        assert entry["required_env"], (
            f"{entry['service']} says it is unconfigured without naming any variable"
        )
        assert entry["docs_url"], f"{entry['service']} offers nowhere to read more"


def test_counts_are_consistent(catalog: dict) -> None:
    configured = [e for e in catalog["integrations"] if e["configured"]]
    assert catalog["configured"] == len(configured)
    assert catalog["available"] == catalog["total"] - len(configured)


def test_missing_env_is_derived_from_the_environment(
    catalog: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A variable that is set must not be reported as missing."""
    for entry in catalog["integrations"]:
        if entry["configured"]:
            assert entry["missing_env"] == [], (
                f"{entry['service']} is configured but still lists missing variables"
            )
        else:
            assert entry["missing_env"], (
                f"{entry['service']} is unconfigured but names nothing missing"
            )
            assert set(entry["missing_env"]) <= set(entry["required_env"])


def test_catalogue_matches_the_runtime_declarations(catalog: dict) -> None:
    """The catalogue must be generated, never hand-maintained.

    Each entry names the router it came from; importing that router and invoking its
    declaration must reproduce the same requirement. If the two ever disagree, the
    catalogue has become a second source of truth — exactly what this design avoids.
    """
    import importlib

    from apps.api.not_configured import NotConfigured

    for entry in catalog["integrations"]:
        module = importlib.import_module(f"apps.api.{entry['router']}")
        with pytest.raises(NotConfigured) as caught:
            module._raise_unavailable()
        assert caught.value.service == entry["service"]
        assert caught.value.required_env == entry["required_env"]


def test_catalogue_requires_authentication(client: TestClient) -> None:
    assert client.get("/api/v1/integrations/catalog").status_code in (401, 403)
