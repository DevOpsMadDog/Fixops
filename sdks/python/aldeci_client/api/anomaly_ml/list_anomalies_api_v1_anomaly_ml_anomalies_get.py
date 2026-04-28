from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.anomaly_list_response import AnomalyListResponse
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    org_id: str | Unset = "default",
    entity_id: None | str | Unset = UNSET,
    risk_level: None | str | Unset = UNSET,
    limit: int | Unset = 100,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    json_entity_id: None | str | Unset
    if isinstance(entity_id, Unset):
        json_entity_id = UNSET
    else:
        json_entity_id = entity_id
    params["entity_id"] = json_entity_id

    json_risk_level: None | str | Unset
    if isinstance(risk_level, Unset):
        json_risk_level = UNSET
    else:
        json_risk_level = risk_level
    params["risk_level"] = json_risk_level

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/anomaly-ml/anomalies",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> AnomalyListResponse | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = AnomalyListResponse.from_dict(response.json())

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
) -> Response[AnomalyListResponse | HTTPValidationError]:
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
    entity_id: None | str | Unset = UNSET,
    risk_level: None | str | Unset = UNSET,
    limit: int | Unset = 100,
) -> Response[AnomalyListResponse | HTTPValidationError]:
    """List detected ML anomalies

     Retrieve persisted ML anomalies with optional filters.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.
        entity_id (None | str | Unset): Filter by entity ID
        risk_level (None | str | Unset): Filter by risk level: low/medium/high/critical
        limit (int | Unset): Max results Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AnomalyListResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        entity_id=entity_id,
        risk_level=risk_level,
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
    entity_id: None | str | Unset = UNSET,
    risk_level: None | str | Unset = UNSET,
    limit: int | Unset = 100,
) -> AnomalyListResponse | HTTPValidationError | None:
    """List detected ML anomalies

     Retrieve persisted ML anomalies with optional filters.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.
        entity_id (None | str | Unset): Filter by entity ID
        risk_level (None | str | Unset): Filter by risk level: low/medium/high/critical
        limit (int | Unset): Max results Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AnomalyListResponse | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        org_id=org_id,
        entity_id=entity_id,
        risk_level=risk_level,
        limit=limit,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    entity_id: None | str | Unset = UNSET,
    risk_level: None | str | Unset = UNSET,
    limit: int | Unset = 100,
) -> Response[AnomalyListResponse | HTTPValidationError]:
    """List detected ML anomalies

     Retrieve persisted ML anomalies with optional filters.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.
        entity_id (None | str | Unset): Filter by entity ID
        risk_level (None | str | Unset): Filter by risk level: low/medium/high/critical
        limit (int | Unset): Max results Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AnomalyListResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        entity_id=entity_id,
        risk_level=risk_level,
        limit=limit,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    entity_id: None | str | Unset = UNSET,
    risk_level: None | str | Unset = UNSET,
    limit: int | Unset = 100,
) -> AnomalyListResponse | HTTPValidationError | None:
    """List detected ML anomalies

     Retrieve persisted ML anomalies with optional filters.

    Args:
        org_id (str | Unset): Organisation ID Default: 'default'.
        entity_id (None | str | Unset): Filter by entity ID
        risk_level (None | str | Unset): Filter by risk level: low/medium/high/critical
        limit (int | Unset): Max results Default: 100.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AnomalyListResponse | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            org_id=org_id,
            entity_id=entity_id,
            risk_level=risk_level,
            limit=limit,
        )
    ).parsed
