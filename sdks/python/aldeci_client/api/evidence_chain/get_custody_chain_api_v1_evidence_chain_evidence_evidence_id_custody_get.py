from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_custody_chain_api_v1_evidence_chain_evidence_evidence_id_custody_get_response_get_custody_chain_api_v1_evidence_chain_evidence_evidence_id_custody_get import (
    GetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGetResponseGetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGet,
)
from ...models.http_validation_error import HTTPValidationError
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
        "url": "/api/v1/evidence-chain/evidence/{evidence_id}/custody".format(
            evidence_id=quote(str(evidence_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGetResponseGetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = GetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGetResponseGetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGet.from_dict(
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
    GetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGetResponseGetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGet
    | HTTPValidationError
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
    GetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGetResponseGetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGet
    | HTTPValidationError
]:
    """Get Custody Chain

     Get the complete chain of custody for an evidence item.

    Args:
        evidence_id (str):
        org_id (str | Unset):  Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGetResponseGetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGet | HTTPValidationError]
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
    GetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGetResponseGetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGet
    | HTTPValidationError
    | None
):
    """Get Custody Chain

     Get the complete chain of custody for an evidence item.

    Args:
        evidence_id (str):
        org_id (str | Unset):  Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGetResponseGetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGet | HTTPValidationError
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
    GetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGetResponseGetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGet
    | HTTPValidationError
]:
    """Get Custody Chain

     Get the complete chain of custody for an evidence item.

    Args:
        evidence_id (str):
        org_id (str | Unset):  Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGetResponseGetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGet | HTTPValidationError]
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
    GetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGetResponseGetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGet
    | HTTPValidationError
    | None
):
    """Get Custody Chain

     Get the complete chain of custody for an evidence item.

    Args:
        evidence_id (str):
        org_id (str | Unset):  Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGetResponseGetCustodyChainApiV1EvidenceChainEvidenceEvidenceIdCustodyGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            evidence_id=evidence_id,
            client=client,
            org_id=org_id,
        )
    ).parsed
