from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.list_iocs_api_v1_threat_intel_iocs_get_response_list_iocs_api_v1_threat_intel_iocs_get import (
    ListIocsApiV1ThreatIntelIocsGetResponseListIocsApiV1ThreatIntelIocsGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    ioc_type: None | str | Unset = UNSET,
    search: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_ioc_type: None | str | Unset
    if isinstance(ioc_type, Unset):
        json_ioc_type = UNSET
    else:
        json_ioc_type = ioc_type
    params["ioc_type"] = json_ioc_type

    json_search: None | str | Unset
    if isinstance(search, Unset):
        json_search = UNSET
    else:
        json_search = search
    params["search"] = json_search

    params["limit"] = limit

    params["offset"] = offset

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/threat-intel/iocs",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | ListIocsApiV1ThreatIntelIocsGetResponseListIocsApiV1ThreatIntelIocsGet | None:
    if response.status_code == 200:
        response_200 = ListIocsApiV1ThreatIntelIocsGetResponseListIocsApiV1ThreatIntelIocsGet.from_dict(response.json())

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
) -> Response[HTTPValidationError | ListIocsApiV1ThreatIntelIocsGetResponseListIocsApiV1ThreatIntelIocsGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    ioc_type: None | str | Unset = UNSET,
    search: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
) -> Response[HTTPValidationError | ListIocsApiV1ThreatIntelIocsGetResponseListIocsApiV1ThreatIntelIocsGet]:
    """List Iocs

     List/search IOCs from local feed caches.

    Currently returns C2 IPs from the Feodo blocklist.
    Supports optional substring search and type filtering.

    Args:
        ioc_type (None | str | Unset): Filter by type: ip|domain|hash|url
        search (None | str | Unset): Substring search on IOC value
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListIocsApiV1ThreatIntelIocsGetResponseListIocsApiV1ThreatIntelIocsGet]
    """

    kwargs = _get_kwargs(
        ioc_type=ioc_type,
        search=search,
        limit=limit,
        offset=offset,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    ioc_type: None | str | Unset = UNSET,
    search: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
) -> HTTPValidationError | ListIocsApiV1ThreatIntelIocsGetResponseListIocsApiV1ThreatIntelIocsGet | None:
    """List Iocs

     List/search IOCs from local feed caches.

    Currently returns C2 IPs from the Feodo blocklist.
    Supports optional substring search and type filtering.

    Args:
        ioc_type (None | str | Unset): Filter by type: ip|domain|hash|url
        search (None | str | Unset): Substring search on IOC value
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListIocsApiV1ThreatIntelIocsGetResponseListIocsApiV1ThreatIntelIocsGet
    """

    return sync_detailed(
        client=client,
        ioc_type=ioc_type,
        search=search,
        limit=limit,
        offset=offset,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    ioc_type: None | str | Unset = UNSET,
    search: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
) -> Response[HTTPValidationError | ListIocsApiV1ThreatIntelIocsGetResponseListIocsApiV1ThreatIntelIocsGet]:
    """List Iocs

     List/search IOCs from local feed caches.

    Currently returns C2 IPs from the Feodo blocklist.
    Supports optional substring search and type filtering.

    Args:
        ioc_type (None | str | Unset): Filter by type: ip|domain|hash|url
        search (None | str | Unset): Substring search on IOC value
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListIocsApiV1ThreatIntelIocsGetResponseListIocsApiV1ThreatIntelIocsGet]
    """

    kwargs = _get_kwargs(
        ioc_type=ioc_type,
        search=search,
        limit=limit,
        offset=offset,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    ioc_type: None | str | Unset = UNSET,
    search: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
) -> HTTPValidationError | ListIocsApiV1ThreatIntelIocsGetResponseListIocsApiV1ThreatIntelIocsGet | None:
    """List Iocs

     List/search IOCs from local feed caches.

    Currently returns C2 IPs from the Feodo blocklist.
    Supports optional substring search and type filtering.

    Args:
        ioc_type (None | str | Unset): Filter by type: ip|domain|hash|url
        search (None | str | Unset): Substring search on IOC value
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListIocsApiV1ThreatIntelIocsGetResponseListIocsApiV1ThreatIntelIocsGet
    """

    return (
        await asyncio_detailed(
            client=client,
            ioc_type=ioc_type,
            search=search,
            limit=limit,
            offset=offset,
        )
    ).parsed
