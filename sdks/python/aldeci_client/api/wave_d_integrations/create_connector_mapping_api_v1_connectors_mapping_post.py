from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.connector_mapping_request import ConnectorMappingRequest
from ...models.create_connector_mapping_api_v1_connectors_mapping_post_response_create_connector_mapping_api_v1_connectors_mapping_post import (
    CreateConnectorMappingApiV1ConnectorsMappingPostResponseCreateConnectorMappingApiV1ConnectorsMappingPost,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: ConnectorMappingRequest,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/connectors/mapping",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    CreateConnectorMappingApiV1ConnectorsMappingPostResponseCreateConnectorMappingApiV1ConnectorsMappingPost
    | HTTPValidationError
    | None
):
    if response.status_code == 201:
        response_201 = CreateConnectorMappingApiV1ConnectorsMappingPostResponseCreateConnectorMappingApiV1ConnectorsMappingPost.from_dict(
            response.json()
        )

        return response_201

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
    CreateConnectorMappingApiV1ConnectorsMappingPostResponseCreateConnectorMappingApiV1ConnectorsMappingPost
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: ConnectorMappingRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    CreateConnectorMappingApiV1ConnectorsMappingPostResponseCreateConnectorMappingApiV1ConnectorsMappingPost
    | HTTPValidationError
]:
    """Create Connector Mapping

     Persist a single field mapping for a connector. (Multica e194a1b1)

    Args:
        x_org_id (None | str | Unset):
        body (ConnectorMappingRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateConnectorMappingApiV1ConnectorsMappingPostResponseCreateConnectorMappingApiV1ConnectorsMappingPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: ConnectorMappingRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    CreateConnectorMappingApiV1ConnectorsMappingPostResponseCreateConnectorMappingApiV1ConnectorsMappingPost
    | HTTPValidationError
    | None
):
    """Create Connector Mapping

     Persist a single field mapping for a connector. (Multica e194a1b1)

    Args:
        x_org_id (None | str | Unset):
        body (ConnectorMappingRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateConnectorMappingApiV1ConnectorsMappingPostResponseCreateConnectorMappingApiV1ConnectorsMappingPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: ConnectorMappingRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    CreateConnectorMappingApiV1ConnectorsMappingPostResponseCreateConnectorMappingApiV1ConnectorsMappingPost
    | HTTPValidationError
]:
    """Create Connector Mapping

     Persist a single field mapping for a connector. (Multica e194a1b1)

    Args:
        x_org_id (None | str | Unset):
        body (ConnectorMappingRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateConnectorMappingApiV1ConnectorsMappingPostResponseCreateConnectorMappingApiV1ConnectorsMappingPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: ConnectorMappingRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    CreateConnectorMappingApiV1ConnectorsMappingPostResponseCreateConnectorMappingApiV1ConnectorsMappingPost
    | HTTPValidationError
    | None
):
    """Create Connector Mapping

     Persist a single field mapping for a connector. (Multica e194a1b1)

    Args:
        x_org_id (None | str | Unset):
        body (ConnectorMappingRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateConnectorMappingApiV1ConnectorsMappingPostResponseCreateConnectorMappingApiV1ConnectorsMappingPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            x_org_id=x_org_id,
        )
    ).parsed
