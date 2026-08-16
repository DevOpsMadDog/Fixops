"""An integration without credentials must look unconfigured, not broken.

Measured 2026-08-16 against the running container: 10 integration domains answered
HTTP 503 purely because the operator had not supplied credentials — `github`, `harbor`,
`hashicorp-vault`, `kong`, `n8n`, `servicenow`, `elasticsearch`, `deployment`,
`guardrails`, `license`. That accounted for roughly half of everything the audit had
counted as "broken".

503 means "the service is unavailable". It trips uptime monitors, colours dashboards
red, and to a prospect evaluating the product it reads as *this is broken* rather than
*I have not connected my Jira yet* — which is exactly backwards, since the integration
surface is what we most want a buyer to notice.

See docs/architecture/adr/007-credential-gated-integrations.md.
"""

from __future__ import annotations

import pytest

from apps.api.not_configured import (
    NotConfigured,
    not_configured_payload,
)


# --------------------------------------------------------------------------
# The payload contract
# --------------------------------------------------------------------------


def test_payload_reports_not_configured_rather_than_failure() -> None:
    payload = not_configured_payload(
        "kong", "KONG_ADMIN_URL environment variable is not configured"
    )
    assert payload["configured"] is False
    assert payload["status"] == "not_configured"
    assert payload["service"] == "kong"
    # An unconfigured integration must never drag overall health down.
    assert payload["healthy"] is True


def test_required_env_is_derived_from_the_existing_message() -> None:
    """Migration must not invent a second source of truth for variable names."""
    payload = not_configured_payload(
        "servicenow",
        "SERVICENOW_URL, SERVICENOW_USER, and SERVICENOW_PASSWORD "
        "environment variables are not configured",
    )
    assert payload["required_env"] == [
        "SERVICENOW_URL",
        "SERVICENOW_USER",
        "SERVICENOW_PASSWORD",
    ]


def test_explicit_required_env_wins_over_derivation() -> None:
    payload = not_configured_payload(
        "harbor", "not configured", required_env=["HARBOR_URL"]
    )
    assert payload["required_env"] == ["HARBOR_URL"]


def test_prose_words_are_not_mistaken_for_variables() -> None:
    """Only SCREAMING_SNAKE_CASE tokens count — 'URL' alone is not a variable."""
    payload = not_configured_payload(
        "x", "Set the URL and API key first. Requires MY_TOKEN to be present."
    )
    assert payload["required_env"] == ["MY_TOKEN"]


def test_docs_url_defaults_to_the_service() -> None:
    assert not_configured_payload("kong", "m")["docs_url"].endswith("/kong")


def test_duplicate_variables_are_not_repeated() -> None:
    payload = not_configured_payload("x", "MY_TOKEN is unset; set MY_TOKEN to continue")
    assert payload["required_env"] == ["MY_TOKEN"]


# --------------------------------------------------------------------------
# The exception carries intent, so rendering cannot drift back to 5xx
# --------------------------------------------------------------------------


def test_not_configured_is_not_an_http_exception() -> None:
    """The raise site declares intent; the status code is decided centrally."""
    from fastapi import HTTPException

    exc = NotConfigured("kong", "KONG_ADMIN_URL is not configured")
    assert not isinstance(exc, HTTPException)
    assert str(exc) == "KONG_ADMIN_URL is not configured"


# --------------------------------------------------------------------------
# Every migrated router actually raises it
# --------------------------------------------------------------------------


MIGRATED = [
    "ansible_tower_router",
    "bitbucket_router",
    "circleci_router",
    "gar_router",
    "github_api_router",
    "gitlab_pipeline_router",
    "harbor_router",
    "jenkins_router",
    "jira_cloud_router",
    "kong_router",
    "mattermost_router",
    "pyrit_router",
    "servicenow_router",
    "workday_router",
]


@pytest.mark.parametrize("module_name", MIGRATED)
def test_router_raises_not_configured_for_absent_credentials(module_name: str) -> None:
    import importlib

    module = importlib.import_module(f"apps.api.{module_name}")
    raiser = getattr(module, "_raise_unavailable", None)
    assert raiser is not None, f"{module_name} lost its _raise_unavailable helper"

    with pytest.raises(NotConfigured) as caught:
        raiser()

    exc = caught.value
    assert exc.service, f"{module_name} raised NotConfigured without a service name"
    assert exc.required_env, (
        f"{module_name} does not tell the operator which variables to set"
    )


@pytest.mark.parametrize("module_name", MIGRATED)
def test_migrated_router_no_longer_promises_503_in_its_docs(module_name: str) -> None:
    """Docstrings are part of the contract; a stale one re-teaches the old behaviour."""
    import importlib

    module = importlib.import_module(f"apps.api.{module_name}")
    assert "HTTP 503" not in (module.__doc__ or ""), (
        f"{module_name} still documents HTTP 503 for absent credentials"
    )
