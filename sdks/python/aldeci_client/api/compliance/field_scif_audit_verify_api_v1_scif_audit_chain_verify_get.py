from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.scif_audit_verify_api_v1_scif_audit_chain_verify_get_response_scif_audit_verify_api_v1_scif_audit_chain_verify_get import (
    ScifAuditVerifyApiV1ScifAuditChainVerifyGetResponseScifAuditVerifyApiV1ScifAuditChainVerifyGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/scif/audit-chain/verify",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ScifAuditVerifyApiV1ScifAuditChainVerifyGetResponseScifAuditVerifyApiV1ScifAuditChainVerifyGet | None:
    if response.status_code == 200:
        response_200 = (
            ScifAuditVerifyApiV1ScifAuditChainVerifyGetResponseScifAuditVerifyApiV1ScifAuditChainVerifyGet.from_dict(
                response.json()
            )
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ScifAuditVerifyApiV1ScifAuditChainVerifyGetResponseScifAuditVerifyApiV1ScifAuditChainVerifyGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[ScifAuditVerifyApiV1ScifAuditChainVerifyGetResponseScifAuditVerifyApiV1ScifAuditChainVerifyGet]:
    """Scif Audit Verify

     Re-verify the tamper-evident audit chain.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ScifAuditVerifyApiV1ScifAuditChainVerifyGetResponseScifAuditVerifyApiV1ScifAuditChainVerifyGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient | Client,
) -> ScifAuditVerifyApiV1ScifAuditChainVerifyGetResponseScifAuditVerifyApiV1ScifAuditChainVerifyGet | None:
    """Scif Audit Verify

     Re-verify the tamper-evident audit chain.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ScifAuditVerifyApiV1ScifAuditChainVerifyGetResponseScifAuditVerifyApiV1ScifAuditChainVerifyGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[ScifAuditVerifyApiV1ScifAuditChainVerifyGetResponseScifAuditVerifyApiV1ScifAuditChainVerifyGet]:
    """Scif Audit Verify

     Re-verify the tamper-evident audit chain.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ScifAuditVerifyApiV1ScifAuditChainVerifyGetResponseScifAuditVerifyApiV1ScifAuditChainVerifyGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient | Client,
) -> ScifAuditVerifyApiV1ScifAuditChainVerifyGetResponseScifAuditVerifyApiV1ScifAuditChainVerifyGet | None:
    """Scif Audit Verify

     Re-verify the tamper-evident audit chain.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ScifAuditVerifyApiV1ScifAuditChainVerifyGetResponseScifAuditVerifyApiV1ScifAuditChainVerifyGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
