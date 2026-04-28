from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.components_match_by_abf_api_v1_components_match_by_abf_get_response_components_match_by_abf_api_v1_components_match_by_abf_get import (
    ComponentsMatchByAbfApiV1ComponentsMatchByAbfGetResponseComponentsMatchByAbfApiV1ComponentsMatchByAbfGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    abf: str,
    org_id: str | Unset = "default",
    limit: int | Unset = 50,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    params["abf"] = abf

    params["org_id"] = org_id

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/components/match-by-abf",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    ComponentsMatchByAbfApiV1ComponentsMatchByAbfGetResponseComponentsMatchByAbfApiV1ComponentsMatchByAbfGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = ComponentsMatchByAbfApiV1ComponentsMatchByAbfGetResponseComponentsMatchByAbfApiV1ComponentsMatchByAbfGet.from_dict(
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
    ComponentsMatchByAbfApiV1ComponentsMatchByAbfGetResponseComponentsMatchByAbfApiV1ComponentsMatchByAbfGet
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
    abf: str,
    org_id: str | Unset = "default",
    limit: int | Unset = 50,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    ComponentsMatchByAbfApiV1ComponentsMatchByAbfGetResponseComponentsMatchByAbfApiV1ComponentsMatchByAbfGet
    | HTTPValidationError
]:
    """Match SBOM components by Application Binary Fingerprint

     Search SBOM component records for a given ABF (binary hash).

    Uses ``SBOMEngine`` storage. Falls back to scanning persistent_store ABF
    entries if the engine has no `list_components_by_hash` API.

    Args:
        abf (str): ABF — usually a sha256 of binary contents
        org_id (str | Unset):  Default: 'default'.
        limit (int | Unset):  Default: 50.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ComponentsMatchByAbfApiV1ComponentsMatchByAbfGetResponseComponentsMatchByAbfApiV1ComponentsMatchByAbfGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        abf=abf,
        org_id=org_id,
        limit=limit,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    abf: str,
    org_id: str | Unset = "default",
    limit: int | Unset = 50,
    x_org_id: None | str | Unset = UNSET,
) -> (
    ComponentsMatchByAbfApiV1ComponentsMatchByAbfGetResponseComponentsMatchByAbfApiV1ComponentsMatchByAbfGet
    | HTTPValidationError
    | None
):
    """Match SBOM components by Application Binary Fingerprint

     Search SBOM component records for a given ABF (binary hash).

    Uses ``SBOMEngine`` storage. Falls back to scanning persistent_store ABF
    entries if the engine has no `list_components_by_hash` API.

    Args:
        abf (str): ABF — usually a sha256 of binary contents
        org_id (str | Unset):  Default: 'default'.
        limit (int | Unset):  Default: 50.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ComponentsMatchByAbfApiV1ComponentsMatchByAbfGetResponseComponentsMatchByAbfApiV1ComponentsMatchByAbfGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        abf=abf,
        org_id=org_id,
        limit=limit,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    abf: str,
    org_id: str | Unset = "default",
    limit: int | Unset = 50,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    ComponentsMatchByAbfApiV1ComponentsMatchByAbfGetResponseComponentsMatchByAbfApiV1ComponentsMatchByAbfGet
    | HTTPValidationError
]:
    """Match SBOM components by Application Binary Fingerprint

     Search SBOM component records for a given ABF (binary hash).

    Uses ``SBOMEngine`` storage. Falls back to scanning persistent_store ABF
    entries if the engine has no `list_components_by_hash` API.

    Args:
        abf (str): ABF — usually a sha256 of binary contents
        org_id (str | Unset):  Default: 'default'.
        limit (int | Unset):  Default: 50.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ComponentsMatchByAbfApiV1ComponentsMatchByAbfGetResponseComponentsMatchByAbfApiV1ComponentsMatchByAbfGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        abf=abf,
        org_id=org_id,
        limit=limit,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    abf: str,
    org_id: str | Unset = "default",
    limit: int | Unset = 50,
    x_org_id: None | str | Unset = UNSET,
) -> (
    ComponentsMatchByAbfApiV1ComponentsMatchByAbfGetResponseComponentsMatchByAbfApiV1ComponentsMatchByAbfGet
    | HTTPValidationError
    | None
):
    """Match SBOM components by Application Binary Fingerprint

     Search SBOM component records for a given ABF (binary hash).

    Uses ``SBOMEngine`` storage. Falls back to scanning persistent_store ABF
    entries if the engine has no `list_components_by_hash` API.

    Args:
        abf (str): ABF — usually a sha256 of binary contents
        org_id (str | Unset):  Default: 'default'.
        limit (int | Unset):  Default: 50.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ComponentsMatchByAbfApiV1ComponentsMatchByAbfGetResponseComponentsMatchByAbfApiV1ComponentsMatchByAbfGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            abf=abf,
            org_id=org_id,
            limit=limit,
            x_org_id=x_org_id,
        )
    ).parsed
