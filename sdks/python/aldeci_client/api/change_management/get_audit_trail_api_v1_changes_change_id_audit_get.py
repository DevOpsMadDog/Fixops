from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_audit_trail_api_v1_changes_change_id_audit_get_response_get_audit_trail_api_v1_changes_change_id_audit_get import (
    GetAuditTrailApiV1ChangesChangeIdAuditGetResponseGetAuditTrailApiV1ChangesChangeIdAuditGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    change_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/changes/{change_id}/audit".format(
            change_id=quote(str(change_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetAuditTrailApiV1ChangesChangeIdAuditGetResponseGetAuditTrailApiV1ChangesChangeIdAuditGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = (
            GetAuditTrailApiV1ChangesChangeIdAuditGetResponseGetAuditTrailApiV1ChangesChangeIdAuditGet.from_dict(
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
    GetAuditTrailApiV1ChangesChangeIdAuditGetResponseGetAuditTrailApiV1ChangesChangeIdAuditGet | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    change_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetAuditTrailApiV1ChangesChangeIdAuditGetResponseGetAuditTrailApiV1ChangesChangeIdAuditGet | HTTPValidationError
]:
    """Get Audit Trail

     Get the full audit trail for a change request.

    Args:
        change_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetAuditTrailApiV1ChangesChangeIdAuditGetResponseGetAuditTrailApiV1ChangesChangeIdAuditGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        change_id=change_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    change_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetAuditTrailApiV1ChangesChangeIdAuditGetResponseGetAuditTrailApiV1ChangesChangeIdAuditGet
    | HTTPValidationError
    | None
):
    """Get Audit Trail

     Get the full audit trail for a change request.

    Args:
        change_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetAuditTrailApiV1ChangesChangeIdAuditGetResponseGetAuditTrailApiV1ChangesChangeIdAuditGet | HTTPValidationError
    """

    return sync_detailed(
        change_id=change_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    change_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetAuditTrailApiV1ChangesChangeIdAuditGetResponseGetAuditTrailApiV1ChangesChangeIdAuditGet | HTTPValidationError
]:
    """Get Audit Trail

     Get the full audit trail for a change request.

    Args:
        change_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetAuditTrailApiV1ChangesChangeIdAuditGetResponseGetAuditTrailApiV1ChangesChangeIdAuditGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        change_id=change_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    change_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetAuditTrailApiV1ChangesChangeIdAuditGetResponseGetAuditTrailApiV1ChangesChangeIdAuditGet
    | HTTPValidationError
    | None
):
    """Get Audit Trail

     Get the full audit trail for a change request.

    Args:
        change_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetAuditTrailApiV1ChangesChangeIdAuditGetResponseGetAuditTrailApiV1ChangesChangeIdAuditGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            change_id=change_id,
            client=client,
        )
    ).parsed
