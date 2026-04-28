from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.components_safe_upgrade_api_v1_components_purl_safe_upgrade_get_response_components_safe_upgrade_api_v1_components_purl_safe_upgrade_get import (
    ComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGetResponseComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    purl: str,
    *,
    current_version: None | str | Unset = UNSET,
    cve_ids: None | str | Unset = UNSET,
    org_id: str | Unset = "default",
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_current_version: None | str | Unset
    if isinstance(current_version, Unset):
        json_current_version = UNSET
    else:
        json_current_version = current_version
    params["current_version"] = json_current_version

    json_cve_ids: None | str | Unset
    if isinstance(cve_ids, Unset):
        json_cve_ids = UNSET
    else:
        json_cve_ids = cve_ids
    params["cve_ids"] = json_cve_ids

    params["org_id"] = org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/components/{purl}/safe-upgrade".format(
            purl=quote(str(purl), safe=""),
        ),
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    ComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGetResponseComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = ComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGetResponseComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGet.from_dict(
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
    ComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGetResponseComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGet
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    purl: str,
    *,
    client: AuthenticatedClient,
    current_version: None | str | Unset = UNSET,
    cve_ids: None | str | Unset = UNSET,
    org_id: str | Unset = "default",
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    ComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGetResponseComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGet
    | HTTPValidationError
]:
    """Resolve safe upgrade target for a component PURL

     Resolve the next safe upgrade target for a component.

    Wraps ``UpgradePathResolverEngine.resolve_upgrade(org_id, purl, cve_ids)``.

    The engine signature requires a non-empty ``cve_ids`` list — when no CVEs
    are supplied we attempt to derive them from the engine's per-package vuln
    catalogue, falling back to a 422 if there are none.

    Args:
        purl (str):
        current_version (None | str | Unset):
        cve_ids (None | str | Unset): Comma-separated CVE IDs
        org_id (str | Unset):  Default: 'default'.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGetResponseComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        purl=purl,
        current_version=current_version,
        cve_ids=cve_ids,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    purl: str,
    *,
    client: AuthenticatedClient,
    current_version: None | str | Unset = UNSET,
    cve_ids: None | str | Unset = UNSET,
    org_id: str | Unset = "default",
    x_org_id: None | str | Unset = UNSET,
) -> (
    ComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGetResponseComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGet
    | HTTPValidationError
    | None
):
    """Resolve safe upgrade target for a component PURL

     Resolve the next safe upgrade target for a component.

    Wraps ``UpgradePathResolverEngine.resolve_upgrade(org_id, purl, cve_ids)``.

    The engine signature requires a non-empty ``cve_ids`` list — when no CVEs
    are supplied we attempt to derive them from the engine's per-package vuln
    catalogue, falling back to a 422 if there are none.

    Args:
        purl (str):
        current_version (None | str | Unset):
        cve_ids (None | str | Unset): Comma-separated CVE IDs
        org_id (str | Unset):  Default: 'default'.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGetResponseComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGet | HTTPValidationError
    """

    return sync_detailed(
        purl=purl,
        client=client,
        current_version=current_version,
        cve_ids=cve_ids,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    purl: str,
    *,
    client: AuthenticatedClient,
    current_version: None | str | Unset = UNSET,
    cve_ids: None | str | Unset = UNSET,
    org_id: str | Unset = "default",
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    ComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGetResponseComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGet
    | HTTPValidationError
]:
    """Resolve safe upgrade target for a component PURL

     Resolve the next safe upgrade target for a component.

    Wraps ``UpgradePathResolverEngine.resolve_upgrade(org_id, purl, cve_ids)``.

    The engine signature requires a non-empty ``cve_ids`` list — when no CVEs
    are supplied we attempt to derive them from the engine's per-package vuln
    catalogue, falling back to a 422 if there are none.

    Args:
        purl (str):
        current_version (None | str | Unset):
        cve_ids (None | str | Unset): Comma-separated CVE IDs
        org_id (str | Unset):  Default: 'default'.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGetResponseComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        purl=purl,
        current_version=current_version,
        cve_ids=cve_ids,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    purl: str,
    *,
    client: AuthenticatedClient,
    current_version: None | str | Unset = UNSET,
    cve_ids: None | str | Unset = UNSET,
    org_id: str | Unset = "default",
    x_org_id: None | str | Unset = UNSET,
) -> (
    ComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGetResponseComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGet
    | HTTPValidationError
    | None
):
    """Resolve safe upgrade target for a component PURL

     Resolve the next safe upgrade target for a component.

    Wraps ``UpgradePathResolverEngine.resolve_upgrade(org_id, purl, cve_ids)``.

    The engine signature requires a non-empty ``cve_ids`` list — when no CVEs
    are supplied we attempt to derive them from the engine's per-package vuln
    catalogue, falling back to a 422 if there are none.

    Args:
        purl (str):
        current_version (None | str | Unset):
        cve_ids (None | str | Unset): Comma-separated CVE IDs
        org_id (str | Unset):  Default: 'default'.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGetResponseComponentsSafeUpgradeApiV1ComponentsPurlSafeUpgradeGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            purl=purl,
            client=client,
            current_version=current_version,
            cve_ids=cve_ids,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
