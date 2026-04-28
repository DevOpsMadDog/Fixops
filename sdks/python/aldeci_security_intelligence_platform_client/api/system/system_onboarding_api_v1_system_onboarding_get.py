from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.system_onboarding_api_v1_system_onboarding_get_response_system_onboarding_api_v1_system_onboarding_get import (
    SystemOnboardingApiV1SystemOnboardingGetResponseSystemOnboardingApiV1SystemOnboardingGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/system/onboarding",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> SystemOnboardingApiV1SystemOnboardingGetResponseSystemOnboardingApiV1SystemOnboardingGet | None:
    if response.status_code == 200:
        response_200 = (
            SystemOnboardingApiV1SystemOnboardingGetResponseSystemOnboardingApiV1SystemOnboardingGet.from_dict(
                response.json()
            )
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[SystemOnboardingApiV1SystemOnboardingGetResponseSystemOnboardingApiV1SystemOnboardingGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[SystemOnboardingApiV1SystemOnboardingGetResponseSystemOnboardingApiV1SystemOnboardingGet]:
    """Guided onboarding wizard

     Step-by-step onboarding wizard for new ALdeci deployments.

    Returns a checklist of setup steps with completion status, progress
    percentage, and next recommended action. Designed for first-time
    customers — deploy, hit this endpoint, follow the steps.

    **No authentication required** — first thing after deploy.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[SystemOnboardingApiV1SystemOnboardingGetResponseSystemOnboardingApiV1SystemOnboardingGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> SystemOnboardingApiV1SystemOnboardingGetResponseSystemOnboardingApiV1SystemOnboardingGet | None:
    """Guided onboarding wizard

     Step-by-step onboarding wizard for new ALdeci deployments.

    Returns a checklist of setup steps with completion status, progress
    percentage, and next recommended action. Designed for first-time
    customers — deploy, hit this endpoint, follow the steps.

    **No authentication required** — first thing after deploy.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        SystemOnboardingApiV1SystemOnboardingGetResponseSystemOnboardingApiV1SystemOnboardingGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[SystemOnboardingApiV1SystemOnboardingGetResponseSystemOnboardingApiV1SystemOnboardingGet]:
    """Guided onboarding wizard

     Step-by-step onboarding wizard for new ALdeci deployments.

    Returns a checklist of setup steps with completion status, progress
    percentage, and next recommended action. Designed for first-time
    customers — deploy, hit this endpoint, follow the steps.

    **No authentication required** — first thing after deploy.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[SystemOnboardingApiV1SystemOnboardingGetResponseSystemOnboardingApiV1SystemOnboardingGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> SystemOnboardingApiV1SystemOnboardingGetResponseSystemOnboardingApiV1SystemOnboardingGet | None:
    """Guided onboarding wizard

     Step-by-step onboarding wizard for new ALdeci deployments.

    Returns a checklist of setup steps with completion status, progress
    percentage, and next recommended action. Designed for first-time
    customers — deploy, hit this endpoint, follow the steps.

    **No authentication required** — first thing after deploy.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        SystemOnboardingApiV1SystemOnboardingGetResponseSystemOnboardingApiV1SystemOnboardingGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
