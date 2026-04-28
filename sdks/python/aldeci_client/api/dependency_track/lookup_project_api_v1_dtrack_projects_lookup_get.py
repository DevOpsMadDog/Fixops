from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.lookup_project_api_v1_dtrack_projects_lookup_get_response_lookup_project_api_v1_dtrack_projects_lookup_get import (
    LookupProjectApiV1DtrackProjectsLookupGetResponseLookupProjectApiV1DtrackProjectsLookupGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    name: str,
    version: str | Unset = "latest",
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["name"] = name

    params["version"] = version

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/dtrack/projects/lookup",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | LookupProjectApiV1DtrackProjectsLookupGetResponseLookupProjectApiV1DtrackProjectsLookupGet
    | None
):
    if response.status_code == 200:
        response_200 = (
            LookupProjectApiV1DtrackProjectsLookupGetResponseLookupProjectApiV1DtrackProjectsLookupGet.from_dict(
                response.json()
            )
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
    HTTPValidationError | LookupProjectApiV1DtrackProjectsLookupGetResponseLookupProjectApiV1DtrackProjectsLookupGet
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
    name: str,
    version: str | Unset = "latest",
) -> Response[
    HTTPValidationError | LookupProjectApiV1DtrackProjectsLookupGetResponseLookupProjectApiV1DtrackProjectsLookupGet
]:
    """Lookup Project

     Lookup or create a Dependency-Track project by name + version.

    Args:
        name (str):
        version (str | Unset):  Default: 'latest'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | LookupProjectApiV1DtrackProjectsLookupGetResponseLookupProjectApiV1DtrackProjectsLookupGet]
    """

    kwargs = _get_kwargs(
        name=name,
        version=version,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    name: str,
    version: str | Unset = "latest",
) -> (
    HTTPValidationError
    | LookupProjectApiV1DtrackProjectsLookupGetResponseLookupProjectApiV1DtrackProjectsLookupGet
    | None
):
    """Lookup Project

     Lookup or create a Dependency-Track project by name + version.

    Args:
        name (str):
        version (str | Unset):  Default: 'latest'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | LookupProjectApiV1DtrackProjectsLookupGetResponseLookupProjectApiV1DtrackProjectsLookupGet
    """

    return sync_detailed(
        client=client,
        name=name,
        version=version,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    name: str,
    version: str | Unset = "latest",
) -> Response[
    HTTPValidationError | LookupProjectApiV1DtrackProjectsLookupGetResponseLookupProjectApiV1DtrackProjectsLookupGet
]:
    """Lookup Project

     Lookup or create a Dependency-Track project by name + version.

    Args:
        name (str):
        version (str | Unset):  Default: 'latest'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | LookupProjectApiV1DtrackProjectsLookupGetResponseLookupProjectApiV1DtrackProjectsLookupGet]
    """

    kwargs = _get_kwargs(
        name=name,
        version=version,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    name: str,
    version: str | Unset = "latest",
) -> (
    HTTPValidationError
    | LookupProjectApiV1DtrackProjectsLookupGetResponseLookupProjectApiV1DtrackProjectsLookupGet
    | None
):
    """Lookup Project

     Lookup or create a Dependency-Track project by name + version.

    Args:
        name (str):
        version (str | Unset):  Default: 'latest'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | LookupProjectApiV1DtrackProjectsLookupGetResponseLookupProjectApiV1DtrackProjectsLookupGet
    """

    return (
        await asyncio_detailed(
            client=client,
            name=name,
            version=version,
        )
    ).parsed
