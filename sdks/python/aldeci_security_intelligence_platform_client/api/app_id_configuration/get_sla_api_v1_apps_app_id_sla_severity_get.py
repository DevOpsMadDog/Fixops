from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.sla_response import SLAResponse
from ...types import UNSET, Response, Unset


def _get_kwargs(
    app_id: str,
    severity: str,
    *,
    component: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_component: None | str | Unset
    if isinstance(component, Unset):
        json_component = UNSET
    else:
        json_component = component
    params["component"] = json_component

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/apps/{app_id}/sla/{severity}".format(
            app_id=quote(str(app_id), safe=""),
            severity=quote(str(severity), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | SLAResponse | None:
    if response.status_code == 200:
        response_200 = SLAResponse.from_dict(response.json())

        return response_200

    if response.status_code == 422:
        response_422 = HTTPValidationError.from_dict(response.json())

        return response_422

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[HTTPValidationError | SLAResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    app_id: str,
    severity: str,
    *,
    client: AuthenticatedClient,
    component: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | SLAResponse]:
    """Get SLA deadline for a severity

     Return the SLA configuration and computed deadline UTC timestamp for the given severity.

    Optionally scoped to a specific ``component``.

    Args:
        app_id (str):
        severity (str):
        component (None | str | Unset): Component name for component-specific SLA

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | SLAResponse]
    """

    kwargs = _get_kwargs(
        app_id=app_id,
        severity=severity,
        component=component,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    app_id: str,
    severity: str,
    *,
    client: AuthenticatedClient,
    component: None | str | Unset = UNSET,
) -> HTTPValidationError | SLAResponse | None:
    """Get SLA deadline for a severity

     Return the SLA configuration and computed deadline UTC timestamp for the given severity.

    Optionally scoped to a specific ``component``.

    Args:
        app_id (str):
        severity (str):
        component (None | str | Unset): Component name for component-specific SLA

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | SLAResponse
    """

    return sync_detailed(
        app_id=app_id,
        severity=severity,
        client=client,
        component=component,
    ).parsed


async def asyncio_detailed(
    app_id: str,
    severity: str,
    *,
    client: AuthenticatedClient,
    component: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | SLAResponse]:
    """Get SLA deadline for a severity

     Return the SLA configuration and computed deadline UTC timestamp for the given severity.

    Optionally scoped to a specific ``component``.

    Args:
        app_id (str):
        severity (str):
        component (None | str | Unset): Component name for component-specific SLA

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | SLAResponse]
    """

    kwargs = _get_kwargs(
        app_id=app_id,
        severity=severity,
        component=component,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    app_id: str,
    severity: str,
    *,
    client: AuthenticatedClient,
    component: None | str | Unset = UNSET,
) -> HTTPValidationError | SLAResponse | None:
    """Get SLA deadline for a severity

     Return the SLA configuration and computed deadline UTC timestamp for the given severity.

    Optionally scoped to a specific ``component``.

    Args:
        app_id (str):
        severity (str):
        component (None | str | Unset): Component name for component-specific SLA

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | SLAResponse
    """

    return (
        await asyncio_detailed(
            app_id=app_id,
            severity=severity,
            client=client,
            component=component,
        )
    ).parsed
