from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.verify_integrity_api_v1_evidence_chain_evidence_evidence_id_verify_get_response_verify_integrity_api_v1_evidence_chain_evidence_evidence_id_verify_get import (
    VerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGetResponseVerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    evidence_id: str,
    *,
    org_id: str | Unset = "default",
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/evidence-chain/evidence/{evidence_id}/verify".format(
            evidence_id=quote(str(evidence_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | VerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGetResponseVerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGet
    | None
):
    if response.status_code == 200:
        response_200 = VerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGetResponseVerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGet.from_dict(
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
    HTTPValidationError
    | VerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGetResponseVerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGet
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    evidence_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> Response[
    HTTPValidationError
    | VerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGetResponseVerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGet
]:
    """Verify Integrity

     Verify hash consistency and chain integrity for an evidence item.

    Args:
        evidence_id (str):
        org_id (str | Unset):  Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | VerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGetResponseVerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGet]
    """

    kwargs = _get_kwargs(
        evidence_id=evidence_id,
        org_id=org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    evidence_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> (
    HTTPValidationError
    | VerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGetResponseVerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGet
    | None
):
    """Verify Integrity

     Verify hash consistency and chain integrity for an evidence item.

    Args:
        evidence_id (str):
        org_id (str | Unset):  Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | VerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGetResponseVerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGet
    """

    return sync_detailed(
        evidence_id=evidence_id,
        client=client,
        org_id=org_id,
    ).parsed


async def asyncio_detailed(
    evidence_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> Response[
    HTTPValidationError
    | VerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGetResponseVerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGet
]:
    """Verify Integrity

     Verify hash consistency and chain integrity for an evidence item.

    Args:
        evidence_id (str):
        org_id (str | Unset):  Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | VerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGetResponseVerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGet]
    """

    kwargs = _get_kwargs(
        evidence_id=evidence_id,
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    evidence_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> (
    HTTPValidationError
    | VerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGetResponseVerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGet
    | None
):
    """Verify Integrity

     Verify hash consistency and chain integrity for an evidence item.

    Args:
        evidence_id (str):
        org_id (str | Unset):  Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | VerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGetResponseVerifyIntegrityApiV1EvidenceChainEvidenceEvidenceIdVerifyGet
    """

    return (
        await asyncio_detailed(
            evidence_id=evidence_id,
            client=client,
            org_id=org_id,
        )
    ).parsed
