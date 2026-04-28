from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.seal_evidence_api_v1_evidence_chain_evidence_evidence_id_seal_post_response_seal_evidence_api_v1_evidence_chain_evidence_evidence_id_seal_post import (
    SealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPostResponseSealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPost,
)
from ...models.seal_in import SealIn
from ...types import UNSET, Response, Unset


def _get_kwargs(
    evidence_id: str,
    *,
    body: SealIn,
    org_id: str | Unset = "default",
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/evidence-chain/evidence/{evidence_id}/seal".format(
            evidence_id=quote(str(evidence_id), safe=""),
        ),
        "params": params,
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | SealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPostResponseSealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPost
    | None
):
    if response.status_code == 200:
        response_200 = SealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPostResponseSealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPost.from_dict(
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
    | SealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPostResponseSealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPost
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
    body: SealIn,
    org_id: str | Unset = "default",
) -> Response[
    HTTPValidationError
    | SealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPostResponseSealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPost
]:
    """Seal Evidence

     Seal evidence to prevent further custody transfers.

    Args:
        evidence_id (str):
        org_id (str | Unset):  Default: 'default'.
        body (SealIn):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | SealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPostResponseSealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPost]
    """

    kwargs = _get_kwargs(
        evidence_id=evidence_id,
        body=body,
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
    body: SealIn,
    org_id: str | Unset = "default",
) -> (
    HTTPValidationError
    | SealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPostResponseSealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPost
    | None
):
    """Seal Evidence

     Seal evidence to prevent further custody transfers.

    Args:
        evidence_id (str):
        org_id (str | Unset):  Default: 'default'.
        body (SealIn):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | SealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPostResponseSealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPost
    """

    return sync_detailed(
        evidence_id=evidence_id,
        client=client,
        body=body,
        org_id=org_id,
    ).parsed


async def asyncio_detailed(
    evidence_id: str,
    *,
    client: AuthenticatedClient,
    body: SealIn,
    org_id: str | Unset = "default",
) -> Response[
    HTTPValidationError
    | SealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPostResponseSealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPost
]:
    """Seal Evidence

     Seal evidence to prevent further custody transfers.

    Args:
        evidence_id (str):
        org_id (str | Unset):  Default: 'default'.
        body (SealIn):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | SealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPostResponseSealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPost]
    """

    kwargs = _get_kwargs(
        evidence_id=evidence_id,
        body=body,
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    evidence_id: str,
    *,
    client: AuthenticatedClient,
    body: SealIn,
    org_id: str | Unset = "default",
) -> (
    HTTPValidationError
    | SealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPostResponseSealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPost
    | None
):
    """Seal Evidence

     Seal evidence to prevent further custody transfers.

    Args:
        evidence_id (str):
        org_id (str | Unset):  Default: 'default'.
        body (SealIn):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | SealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPostResponseSealEvidenceApiV1EvidenceChainEvidenceEvidenceIdSealPost
    """

    return (
        await asyncio_detailed(
            evidence_id=evidence_id,
            client=client,
            body=body,
            org_id=org_id,
        )
    ).parsed
