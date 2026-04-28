from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.graph_flows_api_v1_graph_flows_service_id_get_response_graph_flows_api_v1_graph_flows_service_id_get import (
    GraphFlowsApiV1GraphFlowsServiceIdGetResponseGraphFlowsApiV1GraphFlowsServiceIdGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    service_id: str,
    *,
    depth: int | Unset = 2,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    params["depth"] = depth

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/graph/flows/{service_id}".format(
            service_id=quote(str(service_id), safe=""),
        ),
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GraphFlowsApiV1GraphFlowsServiceIdGetResponseGraphFlowsApiV1GraphFlowsServiceIdGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = GraphFlowsApiV1GraphFlowsServiceIdGetResponseGraphFlowsApiV1GraphFlowsServiceIdGet.from_dict(
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
) -> Response[GraphFlowsApiV1GraphFlowsServiceIdGetResponseGraphFlowsApiV1GraphFlowsServiceIdGet | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    service_id: str,
    *,
    client: AuthenticatedClient,
    depth: int | Unset = 2,
    x_org_id: None | str | Unset = UNSET,
) -> Response[GraphFlowsApiV1GraphFlowsServiceIdGetResponseGraphFlowsApiV1GraphFlowsServiceIdGet | HTTPValidationError]:
    """Return inbound + outbound data flows for a service

     Return data flows centred on the given service.

    Uses ``core.cloud_graph.CloudGraphEngine`` when available; falls back to a
    deterministic empty-graph response so callers can hook this into UI without
    a 500 when a tenant has no graph yet.

    Args:
        service_id (str):
        depth (int | Unset):  Default: 2.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GraphFlowsApiV1GraphFlowsServiceIdGetResponseGraphFlowsApiV1GraphFlowsServiceIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        service_id=service_id,
        depth=depth,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    service_id: str,
    *,
    client: AuthenticatedClient,
    depth: int | Unset = 2,
    x_org_id: None | str | Unset = UNSET,
) -> GraphFlowsApiV1GraphFlowsServiceIdGetResponseGraphFlowsApiV1GraphFlowsServiceIdGet | HTTPValidationError | None:
    """Return inbound + outbound data flows for a service

     Return data flows centred on the given service.

    Uses ``core.cloud_graph.CloudGraphEngine`` when available; falls back to a
    deterministic empty-graph response so callers can hook this into UI without
    a 500 when a tenant has no graph yet.

    Args:
        service_id (str):
        depth (int | Unset):  Default: 2.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GraphFlowsApiV1GraphFlowsServiceIdGetResponseGraphFlowsApiV1GraphFlowsServiceIdGet | HTTPValidationError
    """

    return sync_detailed(
        service_id=service_id,
        client=client,
        depth=depth,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    service_id: str,
    *,
    client: AuthenticatedClient,
    depth: int | Unset = 2,
    x_org_id: None | str | Unset = UNSET,
) -> Response[GraphFlowsApiV1GraphFlowsServiceIdGetResponseGraphFlowsApiV1GraphFlowsServiceIdGet | HTTPValidationError]:
    """Return inbound + outbound data flows for a service

     Return data flows centred on the given service.

    Uses ``core.cloud_graph.CloudGraphEngine`` when available; falls back to a
    deterministic empty-graph response so callers can hook this into UI without
    a 500 when a tenant has no graph yet.

    Args:
        service_id (str):
        depth (int | Unset):  Default: 2.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GraphFlowsApiV1GraphFlowsServiceIdGetResponseGraphFlowsApiV1GraphFlowsServiceIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        service_id=service_id,
        depth=depth,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    service_id: str,
    *,
    client: AuthenticatedClient,
    depth: int | Unset = 2,
    x_org_id: None | str | Unset = UNSET,
) -> GraphFlowsApiV1GraphFlowsServiceIdGetResponseGraphFlowsApiV1GraphFlowsServiceIdGet | HTTPValidationError | None:
    """Return inbound + outbound data flows for a service

     Return data flows centred on the given service.

    Uses ``core.cloud_graph.CloudGraphEngine`` when available; falls back to a
    deterministic empty-graph response so callers can hook this into UI without
    a 500 when a tenant has no graph yet.

    Args:
        service_id (str):
        depth (int | Unset):  Default: 2.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GraphFlowsApiV1GraphFlowsServiceIdGetResponseGraphFlowsApiV1GraphFlowsServiceIdGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            service_id=service_id,
            client=client,
            depth=depth,
            x_org_id=x_org_id,
        )
    ).parsed
