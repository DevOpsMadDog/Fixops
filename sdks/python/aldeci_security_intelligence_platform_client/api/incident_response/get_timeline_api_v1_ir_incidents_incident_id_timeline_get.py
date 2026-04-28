from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    incident_id: str,
    *,
    org_id: str | Unset = "default",
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/ir/incidents/{incident_id}/timeline".format(
            incident_id=quote(str(incident_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> HTTPValidationError | None:
    if response.status_code == 422:
        response_422 = HTTPValidationError.from_dict(response.json())

        return response_422

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    incident_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> Response[HTTPValidationError]:
    """Get Incident Timeline

     Return chronological timeline of all events, actions, and communications for the incident.

    Args:
        incident_id (str):
        org_id (str | Unset): Organization ID Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError]
    """

    kwargs = _get_kwargs(
        incident_id=incident_id,
        org_id=org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    incident_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> HTTPValidationError | None:
    """Get Incident Timeline

     Return chronological timeline of all events, actions, and communications for the incident.

    Args:
        incident_id (str):
        org_id (str | Unset): Organization ID Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError
    """

    return sync_detailed(
        incident_id=incident_id,
        client=client,
        org_id=org_id,
    ).parsed


async def asyncio_detailed(
    incident_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> Response[HTTPValidationError]:
    """Get Incident Timeline

     Return chronological timeline of all events, actions, and communications for the incident.

    Args:
        incident_id (str):
        org_id (str | Unset): Organization ID Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError]
    """

    kwargs = _get_kwargs(
        incident_id=incident_id,
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    incident_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> HTTPValidationError | None:
    """Get Incident Timeline

     Return chronological timeline of all events, actions, and communications for the incident.

    Args:
        incident_id (str):
        org_id (str | Unset): Organization ID Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError
    """

    return (
        await asyncio_detailed(
            incident_id=incident_id,
            client=client,
            org_id=org_id,
        )
    ).parsed
