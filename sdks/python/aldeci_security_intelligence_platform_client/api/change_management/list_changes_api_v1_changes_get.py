from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.list_changes_api_v1_changes_get_response_list_changes_api_v1_changes_get import (
    ListChangesApiV1ChangesGetResponseListChangesApiV1ChangesGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    status: None | str | Unset = UNSET,
    risk_level: None | str | Unset = UNSET,
    requestor_id: None | str | Unset = UNSET,
    limit: int | Unset = 50,
    offset: int | Unset = 0,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_status: None | str | Unset
    if isinstance(status, Unset):
        json_status = UNSET
    else:
        json_status = status
    params["status"] = json_status

    json_risk_level: None | str | Unset
    if isinstance(risk_level, Unset):
        json_risk_level = UNSET
    else:
        json_risk_level = risk_level
    params["risk_level"] = json_risk_level

    json_requestor_id: None | str | Unset
    if isinstance(requestor_id, Unset):
        json_requestor_id = UNSET
    else:
        json_requestor_id = requestor_id
    params["requestor_id"] = json_requestor_id

    params["limit"] = limit

    params["offset"] = offset

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/changes",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | ListChangesApiV1ChangesGetResponseListChangesApiV1ChangesGet | None:
    if response.status_code == 200:
        response_200 = ListChangesApiV1ChangesGetResponseListChangesApiV1ChangesGet.from_dict(response.json())

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
) -> Response[HTTPValidationError | ListChangesApiV1ChangesGetResponseListChangesApiV1ChangesGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    status: None | str | Unset = UNSET,
    risk_level: None | str | Unset = UNSET,
    requestor_id: None | str | Unset = UNSET,
    limit: int | Unset = 50,
    offset: int | Unset = 0,
) -> Response[HTTPValidationError | ListChangesApiV1ChangesGetResponseListChangesApiV1ChangesGet]:
    """List Changes

     List change requests with optional filters.

    Args:
        status (None | str | Unset):
        risk_level (None | str | Unset):
        requestor_id (None | str | Unset):
        limit (int | Unset):  Default: 50.
        offset (int | Unset):  Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListChangesApiV1ChangesGetResponseListChangesApiV1ChangesGet]
    """

    kwargs = _get_kwargs(
        status=status,
        risk_level=risk_level,
        requestor_id=requestor_id,
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
    status: None | str | Unset = UNSET,
    risk_level: None | str | Unset = UNSET,
    requestor_id: None | str | Unset = UNSET,
    limit: int | Unset = 50,
    offset: int | Unset = 0,
) -> HTTPValidationError | ListChangesApiV1ChangesGetResponseListChangesApiV1ChangesGet | None:
    """List Changes

     List change requests with optional filters.

    Args:
        status (None | str | Unset):
        risk_level (None | str | Unset):
        requestor_id (None | str | Unset):
        limit (int | Unset):  Default: 50.
        offset (int | Unset):  Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListChangesApiV1ChangesGetResponseListChangesApiV1ChangesGet
    """

    return sync_detailed(
        client=client,
        status=status,
        risk_level=risk_level,
        requestor_id=requestor_id,
        limit=limit,
        offset=offset,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    status: None | str | Unset = UNSET,
    risk_level: None | str | Unset = UNSET,
    requestor_id: None | str | Unset = UNSET,
    limit: int | Unset = 50,
    offset: int | Unset = 0,
) -> Response[HTTPValidationError | ListChangesApiV1ChangesGetResponseListChangesApiV1ChangesGet]:
    """List Changes

     List change requests with optional filters.

    Args:
        status (None | str | Unset):
        risk_level (None | str | Unset):
        requestor_id (None | str | Unset):
        limit (int | Unset):  Default: 50.
        offset (int | Unset):  Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListChangesApiV1ChangesGetResponseListChangesApiV1ChangesGet]
    """

    kwargs = _get_kwargs(
        status=status,
        risk_level=risk_level,
        requestor_id=requestor_id,
        limit=limit,
        offset=offset,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    status: None | str | Unset = UNSET,
    risk_level: None | str | Unset = UNSET,
    requestor_id: None | str | Unset = UNSET,
    limit: int | Unset = 50,
    offset: int | Unset = 0,
) -> HTTPValidationError | ListChangesApiV1ChangesGetResponseListChangesApiV1ChangesGet | None:
    """List Changes

     List change requests with optional filters.

    Args:
        status (None | str | Unset):
        risk_level (None | str | Unset):
        requestor_id (None | str | Unset):
        limit (int | Unset):  Default: 50.
        offset (int | Unset):  Default: 0.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListChangesApiV1ChangesGetResponseListChangesApiV1ChangesGet
    """

    return (
        await asyncio_detailed(
            client=client,
            status=status,
            risk_level=risk_level,
            requestor_id=requestor_id,
            limit=limit,
            offset=offset,
        )
    ).parsed
