from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    ecosystem: None | str | Unset = UNSET,
    has_vulnerabilities: bool | None | Unset = UNSET,
    license_type: None | str | Unset = UNSET,
    page: int | Unset = 1,
    page_size: int | Unset = 50,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_ecosystem: None | str | Unset
    if isinstance(ecosystem, Unset):
        json_ecosystem = UNSET
    else:
        json_ecosystem = ecosystem
    params["ecosystem"] = json_ecosystem

    json_has_vulnerabilities: bool | None | Unset
    if isinstance(has_vulnerabilities, Unset):
        json_has_vulnerabilities = UNSET
    else:
        json_has_vulnerabilities = has_vulnerabilities
    params["has_vulnerabilities"] = json_has_vulnerabilities

    json_license_type: None | str | Unset
    if isinstance(license_type, Unset):
        json_license_type = UNSET
    else:
        json_license_type = license_type
    params["license_type"] = json_license_type

    params["page"] = page

    params["page_size"] = page_size

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/inventory/sbom/components",
        "params": params,
    }

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
    *,
    client: AuthenticatedClient,
    ecosystem: None | str | Unset = UNSET,
    has_vulnerabilities: bool | None | Unset = UNSET,
    license_type: None | str | Unset = UNSET,
    page: int | Unset = 1,
    page_size: int | Unset = 50,
) -> Response[Any | HTTPValidationError]:
    """List Global Sbom Components

     List all SBOM components across all applications.

    Aggregates components from all ingested SBOMs for enterprise-wide
    supply chain visibility. Supports filtering by ecosystem, vulnerability
    status, and license type.

    Args:
        ecosystem (None | str | Unset):
        has_vulnerabilities (bool | None | Unset):
        license_type (None | str | Unset):
        page (int | Unset):  Default: 1.
        page_size (int | Unset):  Default: 50.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        ecosystem=ecosystem,
        has_vulnerabilities=has_vulnerabilities,
        license_type=license_type,
        page=page,
        page_size=page_size,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    ecosystem: None | str | Unset = UNSET,
    has_vulnerabilities: bool | None | Unset = UNSET,
    license_type: None | str | Unset = UNSET,
    page: int | Unset = 1,
    page_size: int | Unset = 50,
) -> Any | HTTPValidationError | None:
    """List Global Sbom Components

     List all SBOM components across all applications.

    Aggregates components from all ingested SBOMs for enterprise-wide
    supply chain visibility. Supports filtering by ecosystem, vulnerability
    status, and license type.

    Args:
        ecosystem (None | str | Unset):
        has_vulnerabilities (bool | None | Unset):
        license_type (None | str | Unset):
        page (int | Unset):  Default: 1.
        page_size (int | Unset):  Default: 50.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        ecosystem=ecosystem,
        has_vulnerabilities=has_vulnerabilities,
        license_type=license_type,
        page=page,
        page_size=page_size,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    ecosystem: None | str | Unset = UNSET,
    has_vulnerabilities: bool | None | Unset = UNSET,
    license_type: None | str | Unset = UNSET,
    page: int | Unset = 1,
    page_size: int | Unset = 50,
) -> Response[Any | HTTPValidationError]:
    """List Global Sbom Components

     List all SBOM components across all applications.

    Aggregates components from all ingested SBOMs for enterprise-wide
    supply chain visibility. Supports filtering by ecosystem, vulnerability
    status, and license type.

    Args:
        ecosystem (None | str | Unset):
        has_vulnerabilities (bool | None | Unset):
        license_type (None | str | Unset):
        page (int | Unset):  Default: 1.
        page_size (int | Unset):  Default: 50.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        ecosystem=ecosystem,
        has_vulnerabilities=has_vulnerabilities,
        license_type=license_type,
        page=page,
        page_size=page_size,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    ecosystem: None | str | Unset = UNSET,
    has_vulnerabilities: bool | None | Unset = UNSET,
    license_type: None | str | Unset = UNSET,
    page: int | Unset = 1,
    page_size: int | Unset = 50,
) -> Any | HTTPValidationError | None:
    """List Global Sbom Components

     List all SBOM components across all applications.

    Aggregates components from all ingested SBOMs for enterprise-wide
    supply chain visibility. Supports filtering by ecosystem, vulnerability
    status, and license type.

    Args:
        ecosystem (None | str | Unset):
        has_vulnerabilities (bool | None | Unset):
        license_type (None | str | Unset):
        page (int | Unset):  Default: 1.
        page_size (int | Unset):  Default: 50.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            ecosystem=ecosystem,
            has_vulnerabilities=has_vulnerabilities,
            license_type=license_type,
            page=page,
            page_size=page_size,
        )
    ).parsed
