from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.add_application_dependencies_api_v1_inventory_applications_id_dependencies_post_body_item import (
    AddApplicationDependenciesApiV1InventoryApplicationsIdDependenciesPostBodyItem,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    id: str,
    *,
    body: list[AddApplicationDependenciesApiV1InventoryApplicationsIdDependenciesPostBodyItem],
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/inventory/applications/{id}/dependencies".format(
            id=quote(str(id), safe=""),
        ),
    }

    _kwargs["json"] = []
    for body_item_data in body:
        body_item = body_item_data.to_dict()
        _kwargs["json"].append(body_item)

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = response.json()
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
) -> Response[Any | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    id: str,
    *,
    client: AuthenticatedClient,
    body: list[AddApplicationDependenciesApiV1InventoryApplicationsIdDependenciesPostBodyItem],
) -> Response[Any | HTTPValidationError]:
    """Add Application Dependencies

     Upload dependency manifest for an application.

    Each dependency: {name, version, type, license, ecosystem, transitive}.

    Args:
        id (str):
        body
            (list[AddApplicationDependenciesApiV1InventoryApplicationsIdDependenciesPostBodyItem]):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        id=id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    id: str,
    *,
    client: AuthenticatedClient,
    body: list[AddApplicationDependenciesApiV1InventoryApplicationsIdDependenciesPostBodyItem],
) -> Any | HTTPValidationError | None:
    """Add Application Dependencies

     Upload dependency manifest for an application.

    Each dependency: {name, version, type, license, ecosystem, transitive}.

    Args:
        id (str):
        body
            (list[AddApplicationDependenciesApiV1InventoryApplicationsIdDependenciesPostBodyItem]):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return sync_detailed(
        id=id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    id: str,
    *,
    client: AuthenticatedClient,
    body: list[AddApplicationDependenciesApiV1InventoryApplicationsIdDependenciesPostBodyItem],
) -> Response[Any | HTTPValidationError]:
    """Add Application Dependencies

     Upload dependency manifest for an application.

    Each dependency: {name, version, type, license, ecosystem, transitive}.

    Args:
        id (str):
        body
            (list[AddApplicationDependenciesApiV1InventoryApplicationsIdDependenciesPostBodyItem]):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        id=id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    id: str,
    *,
    client: AuthenticatedClient,
    body: list[AddApplicationDependenciesApiV1InventoryApplicationsIdDependenciesPostBodyItem],
) -> Any | HTTPValidationError | None:
    """Add Application Dependencies

     Upload dependency manifest for an application.

    Each dependency: {name, version, type, license, ecosystem, transitive}.

    Args:
        id (str):
        body
            (list[AddApplicationDependenciesApiV1InventoryApplicationsIdDependenciesPostBodyItem]):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            id=id,
            client=client,
            body=body,
        )
    ).parsed
