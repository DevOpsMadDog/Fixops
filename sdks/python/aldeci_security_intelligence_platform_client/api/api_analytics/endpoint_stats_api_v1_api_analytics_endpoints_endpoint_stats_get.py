from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.endpoint_stats_api_v1_api_analytics_endpoints_endpoint_stats_get_response_endpoint_stats_api_v1_api_analytics_endpoints_endpoint_stats_get import (
    EndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGetResponseEndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    endpoint: str,
    *,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/api-analytics/endpoints/{endpoint}/stats".format(
            endpoint=quote(str(endpoint), safe=""),
        ),
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    EndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGetResponseEndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = EndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGetResponseEndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGet.from_dict(
            response.json()
        )

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
) -> Response[
    EndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGetResponseEndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGet
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    endpoint: str,
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    EndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGetResponseEndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGet
    | HTTPValidationError
]:
    """Endpoint Stats

     Return call count, avg/p95 response time, and error rate for one endpoint.

    Args:
        endpoint (str):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGetResponseEndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        endpoint=endpoint,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    endpoint: str,
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    EndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGetResponseEndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGet
    | HTTPValidationError
    | None
):
    """Endpoint Stats

     Return call count, avg/p95 response time, and error rate for one endpoint.

    Args:
        endpoint (str):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGetResponseEndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGet | HTTPValidationError
    """

    return sync_detailed(
        endpoint=endpoint,
        client=client,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    endpoint: str,
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    EndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGetResponseEndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGet
    | HTTPValidationError
]:
    """Endpoint Stats

     Return call count, avg/p95 response time, and error rate for one endpoint.

    Args:
        endpoint (str):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGetResponseEndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        endpoint=endpoint,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    endpoint: str,
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    EndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGetResponseEndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGet
    | HTTPValidationError
    | None
):
    """Endpoint Stats

     Return call count, avg/p95 response time, and error rate for one endpoint.

    Args:
        endpoint (str):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGetResponseEndpointStatsApiV1ApiAnalyticsEndpointsEndpointStatsGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            endpoint=endpoint,
            client=client,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
