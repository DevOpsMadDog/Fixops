from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.connector_mapping_dry_run import ConnectorMappingDryRun
from ...models.dry_run_connector_mapping_api_v1_connectors_mapping_dry_run_post_response_dry_run_connector_mapping_api_v1_connectors_mapping_dry_run_post import (
    DryRunConnectorMappingApiV1ConnectorsMappingDryRunPostResponseDryRunConnectorMappingApiV1ConnectorsMappingDryRunPost,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: ConnectorMappingDryRun,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/connectors/mapping/dry-run",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    DryRunConnectorMappingApiV1ConnectorsMappingDryRunPostResponseDryRunConnectorMappingApiV1ConnectorsMappingDryRunPost
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = DryRunConnectorMappingApiV1ConnectorsMappingDryRunPostResponseDryRunConnectorMappingApiV1ConnectorsMappingDryRunPost.from_dict(
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
    DryRunConnectorMappingApiV1ConnectorsMappingDryRunPostResponseDryRunConnectorMappingApiV1ConnectorsMappingDryRunPost
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
    body: ConnectorMappingDryRun,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    DryRunConnectorMappingApiV1ConnectorsMappingDryRunPostResponseDryRunConnectorMappingApiV1ConnectorsMappingDryRunPost
    | HTTPValidationError
]:
    """Dry Run Connector Mapping

     Apply mappings to a sample payload without side effects. (Multica 4e2d5913)

    Args:
        x_org_id (None | str | Unset):
        body (ConnectorMappingDryRun):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DryRunConnectorMappingApiV1ConnectorsMappingDryRunPostResponseDryRunConnectorMappingApiV1ConnectorsMappingDryRunPost | HTTPValidationError]
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
    body: ConnectorMappingDryRun,
    x_org_id: None | str | Unset = UNSET,
) -> (
    DryRunConnectorMappingApiV1ConnectorsMappingDryRunPostResponseDryRunConnectorMappingApiV1ConnectorsMappingDryRunPost
    | HTTPValidationError
    | None
):
    """Dry Run Connector Mapping

     Apply mappings to a sample payload without side effects. (Multica 4e2d5913)

    Args:
        x_org_id (None | str | Unset):
        body (ConnectorMappingDryRun):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DryRunConnectorMappingApiV1ConnectorsMappingDryRunPostResponseDryRunConnectorMappingApiV1ConnectorsMappingDryRunPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: ConnectorMappingDryRun,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    DryRunConnectorMappingApiV1ConnectorsMappingDryRunPostResponseDryRunConnectorMappingApiV1ConnectorsMappingDryRunPost
    | HTTPValidationError
]:
    """Dry Run Connector Mapping

     Apply mappings to a sample payload without side effects. (Multica 4e2d5913)

    Args:
        x_org_id (None | str | Unset):
        body (ConnectorMappingDryRun):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DryRunConnectorMappingApiV1ConnectorsMappingDryRunPostResponseDryRunConnectorMappingApiV1ConnectorsMappingDryRunPost | HTTPValidationError]
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
    body: ConnectorMappingDryRun,
    x_org_id: None | str | Unset = UNSET,
) -> (
    DryRunConnectorMappingApiV1ConnectorsMappingDryRunPostResponseDryRunConnectorMappingApiV1ConnectorsMappingDryRunPost
    | HTTPValidationError
    | None
):
    """Dry Run Connector Mapping

     Apply mappings to a sample payload without side effects. (Multica 4e2d5913)

    Args:
        x_org_id (None | str | Unset):
        body (ConnectorMappingDryRun):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DryRunConnectorMappingApiV1ConnectorsMappingDryRunPostResponseDryRunConnectorMappingApiV1ConnectorsMappingDryRunPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            x_org_id=x_org_id,
        )
    ).parsed
