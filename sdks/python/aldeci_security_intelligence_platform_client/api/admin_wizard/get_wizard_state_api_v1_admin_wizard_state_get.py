from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.wizard_state_response import WizardStateResponse
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/admin/wizard-state",
    }

    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> WizardStateResponse | None:
    if response.status_code == 200:
        response_200 = WizardStateResponse.from_dict(response.json())

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[WizardStateResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[WizardStateResponse]:
    """First-login wizard state (first GET initialises the install)

     Return the wizard-state row, creating it on first call.

    The first GET captures ``first_seen_at`` so the FirstLoginWizard React
    component can render exactly once for the very first admin to log in
    on this install. Subsequent admins on the same install see no wizard
    (because completed=true once any admin finishes it).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[WizardStateResponse]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient | Client,
) -> WizardStateResponse | None:
    """First-login wizard state (first GET initialises the install)

     Return the wizard-state row, creating it on first call.

    The first GET captures ``first_seen_at`` so the FirstLoginWizard React
    component can render exactly once for the very first admin to log in
    on this install. Subsequent admins on the same install see no wizard
    (because completed=true once any admin finishes it).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        WizardStateResponse
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[WizardStateResponse]:
    """First-login wizard state (first GET initialises the install)

     Return the wizard-state row, creating it on first call.

    The first GET captures ``first_seen_at`` so the FirstLoginWizard React
    component can render exactly once for the very first admin to log in
    on this install. Subsequent admins on the same install see no wizard
    (because completed=true once any admin finishes it).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[WizardStateResponse]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient | Client,
) -> WizardStateResponse | None:
    """First-login wizard state (first GET initialises the install)

     Return the wizard-state row, creating it on first call.

    The first GET captures ``first_seen_at`` so the FirstLoginWizard React
    component can render exactly once for the very first admin to log in
    on this install. Subsequent admins on the same install see no wizard
    (because completed=true once any admin finishes it).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        WizardStateResponse
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
