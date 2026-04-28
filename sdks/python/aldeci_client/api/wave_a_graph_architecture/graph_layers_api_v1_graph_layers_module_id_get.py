from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.graph_layers_api_v1_graph_layers_module_id_get_response_graph_layers_api_v1_graph_layers_module_id_get import (
    GraphLayersApiV1GraphLayersModuleIdGetResponseGraphLayersApiV1GraphLayersModuleIdGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    module_id: str,
    *,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/graph/layers/{module_id}".format(
            module_id=quote(str(module_id), safe=""),
        ),
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GraphLayersApiV1GraphLayersModuleIdGetResponseGraphLayersApiV1GraphLayersModuleIdGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = GraphLayersApiV1GraphLayersModuleIdGetResponseGraphLayersApiV1GraphLayersModuleIdGet.from_dict(
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
    GraphLayersApiV1GraphLayersModuleIdGetResponseGraphLayersApiV1GraphLayersModuleIdGet | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    module_id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GraphLayersApiV1GraphLayersModuleIdGetResponseGraphLayersApiV1GraphLayersModuleIdGet | HTTPValidationError
]:
    """Return architectural layer assignment for a module

     Return the layer (presentation/application/domain/infra/shared) for a module.

    Searches recent ``architecture_reports`` persisted by /architecture-detect
    and returns the first match. If no report exists, returns 'unclassified'.

    Args:
        module_id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GraphLayersApiV1GraphLayersModuleIdGetResponseGraphLayersApiV1GraphLayersModuleIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        module_id=module_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    module_id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> GraphLayersApiV1GraphLayersModuleIdGetResponseGraphLayersApiV1GraphLayersModuleIdGet | HTTPValidationError | None:
    """Return architectural layer assignment for a module

     Return the layer (presentation/application/domain/infra/shared) for a module.

    Searches recent ``architecture_reports`` persisted by /architecture-detect
    and returns the first match. If no report exists, returns 'unclassified'.

    Args:
        module_id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GraphLayersApiV1GraphLayersModuleIdGetResponseGraphLayersApiV1GraphLayersModuleIdGet | HTTPValidationError
    """

    return sync_detailed(
        module_id=module_id,
        client=client,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    module_id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GraphLayersApiV1GraphLayersModuleIdGetResponseGraphLayersApiV1GraphLayersModuleIdGet | HTTPValidationError
]:
    """Return architectural layer assignment for a module

     Return the layer (presentation/application/domain/infra/shared) for a module.

    Searches recent ``architecture_reports`` persisted by /architecture-detect
    and returns the first match. If no report exists, returns 'unclassified'.

    Args:
        module_id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GraphLayersApiV1GraphLayersModuleIdGetResponseGraphLayersApiV1GraphLayersModuleIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        module_id=module_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    module_id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> GraphLayersApiV1GraphLayersModuleIdGetResponseGraphLayersApiV1GraphLayersModuleIdGet | HTTPValidationError | None:
    """Return architectural layer assignment for a module

     Return the layer (presentation/application/domain/infra/shared) for a module.

    Searches recent ``architecture_reports`` persisted by /architecture-detect
    and returns the first match. If no report exists, returns 'unclassified'.

    Args:
        module_id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GraphLayersApiV1GraphLayersModuleIdGetResponseGraphLayersApiV1GraphLayersModuleIdGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            module_id=module_id,
            client=client,
            x_org_id=x_org_id,
        )
    ).parsed
