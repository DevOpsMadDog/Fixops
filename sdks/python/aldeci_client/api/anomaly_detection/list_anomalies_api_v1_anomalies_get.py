from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.anomaly import Anomaly
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    org_id: str | Unset = "default",
    severity: None | str | Unset = UNSET,
    limit: int | Unset = 100,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    json_severity: None | str | Unset
    if isinstance(severity, Unset):
        json_severity = UNSET
    else:
        json_severity = severity
    params["severity"] = json_severity

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/anomalies",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[Anomaly] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = Anomaly.from_dict(response_200_item_data)

            response_200.append(response_200_item)

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
) -> Response[HTTPValidationError | list[Anomaly]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    severity: None | str | Unset = UNSET,
    limit: int | Unset = 100,
) -> Response[HTTPValidationError | list[Anomaly]]:
    """List detected anomalies

     Retrieve persisted anomalies for the given org, optionally filtered by severity.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.
        severity (None | str | Unset): Filter by severity (low/medium/high/critical)
        limit (int | Unset): Max results Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[Anomaly]]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        severity=severity,
        limit=limit,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    severity: None | str | Unset = UNSET,
    limit: int | Unset = 100,
) -> HTTPValidationError | list[Anomaly] | None:
    """List detected anomalies

     Retrieve persisted anomalies for the given org, optionally filtered by severity.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.
        severity (None | str | Unset): Filter by severity (low/medium/high/critical)
        limit (int | Unset): Max results Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[Anomaly]
    """

    return sync_detailed(
        client=client,
        org_id=org_id,
        severity=severity,
        limit=limit,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    severity: None | str | Unset = UNSET,
    limit: int | Unset = 100,
) -> Response[HTTPValidationError | list[Anomaly]]:
    """List detected anomalies

     Retrieve persisted anomalies for the given org, optionally filtered by severity.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.
        severity (None | str | Unset): Filter by severity (low/medium/high/critical)
        limit (int | Unset): Max results Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[Anomaly]]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        severity=severity,
        limit=limit,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    severity: None | str | Unset = UNSET,
    limit: int | Unset = 100,
) -> HTTPValidationError | list[Anomaly] | None:
    """List detected anomalies

     Retrieve persisted anomalies for the given org, optionally filtered by severity.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.
        severity (None | str | Unset): Filter by severity (low/medium/high/critical)
        limit (int | Unset): Max results Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[Anomaly]
    """

    return (
        await asyncio_detailed(
            client=client,
            org_id=org_id,
            severity=severity,
            limit=limit,
        )
    ).parsed
