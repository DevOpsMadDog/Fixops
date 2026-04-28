from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.alert_group_response import AlertGroupResponse
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    org_id: str | Unset = "default",
    window_hours: int | Unset = 4,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    params["window_hours"] = window_hours

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/anomaly-ml/groups",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> AlertGroupResponse | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = AlertGroupResponse.from_dict(response.json())

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
) -> Response[AlertGroupResponse | HTTPValidationError]:
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
    window_hours: int | Unset = 4,
) -> Response[AlertGroupResponse | HTTPValidationError]:
    """Get grouped anomaly alerts (alert fatigue reduction)

     Cluster recent anomalies into alert groups to reduce alert fatigue.

    Groups by: same entity, same metric across entities, temporal proximity.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.
        window_hours (int | Unset): Grouping time window Default: 4.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AlertGroupResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        window_hours=window_hours,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    window_hours: int | Unset = 4,
) -> AlertGroupResponse | HTTPValidationError | None:
    """Get grouped anomaly alerts (alert fatigue reduction)

     Cluster recent anomalies into alert groups to reduce alert fatigue.

    Groups by: same entity, same metric across entities, temporal proximity.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.
        window_hours (int | Unset): Grouping time window Default: 4.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AlertGroupResponse | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        org_id=org_id,
        window_hours=window_hours,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    window_hours: int | Unset = 4,
) -> Response[AlertGroupResponse | HTTPValidationError]:
    """Get grouped anomaly alerts (alert fatigue reduction)

     Cluster recent anomalies into alert groups to reduce alert fatigue.

    Groups by: same entity, same metric across entities, temporal proximity.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.
        window_hours (int | Unset): Grouping time window Default: 4.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AlertGroupResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        window_hours=window_hours,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    window_hours: int | Unset = 4,
) -> AlertGroupResponse | HTTPValidationError | None:
    """Get grouped anomaly alerts (alert fatigue reduction)

     Cluster recent anomalies into alert groups to reduce alert fatigue.

    Groups by: same entity, same metric across entities, temporal proximity.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.
        window_hours (int | Unset): Grouping time window Default: 4.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AlertGroupResponse | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            org_id=org_id,
            window_hours=window_hours,
        )
    ).parsed
