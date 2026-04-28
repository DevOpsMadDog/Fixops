from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.add_evidence_api_v1_evidence_chain_cases_case_id_evidence_post_response_add_evidence_api_v1_evidence_chain_cases_case_id_evidence_post import (
    AddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePostResponseAddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePost,
)
from ...models.evidence_in import EvidenceIn
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    case_id: str,
    *,
    body: EvidenceIn,
    org_id: str | Unset = "default",
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/evidence-chain/cases/{case_id}/evidence".format(
            case_id=quote(str(case_id), safe=""),
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
    AddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePostResponseAddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePost
    | HTTPValidationError
    | None
):
    if response.status_code == 201:
        response_201 = AddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePostResponseAddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePost.from_dict(
            response.json()
        )

        return response_201

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
    AddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePostResponseAddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePost
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    case_id: str,
    *,
    client: AuthenticatedClient,
    body: EvidenceIn,
    org_id: str | Unset = "default",
) -> Response[
    AddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePostResponseAddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePost
    | HTTPValidationError
]:
    """Add Evidence

     Add an evidence item to a case.

    Args:
        case_id (str):
        org_id (str | Unset):  Default: 'default'.
        body (EvidenceIn):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePostResponseAddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        case_id=case_id,
        body=body,
        org_id=org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    case_id: str,
    *,
    client: AuthenticatedClient,
    body: EvidenceIn,
    org_id: str | Unset = "default",
) -> (
    AddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePostResponseAddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePost
    | HTTPValidationError
    | None
):
    """Add Evidence

     Add an evidence item to a case.

    Args:
        case_id (str):
        org_id (str | Unset):  Default: 'default'.
        body (EvidenceIn):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePostResponseAddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePost | HTTPValidationError
    """

    return sync_detailed(
        case_id=case_id,
        client=client,
        body=body,
        org_id=org_id,
    ).parsed


async def asyncio_detailed(
    case_id: str,
    *,
    client: AuthenticatedClient,
    body: EvidenceIn,
    org_id: str | Unset = "default",
) -> Response[
    AddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePostResponseAddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePost
    | HTTPValidationError
]:
    """Add Evidence

     Add an evidence item to a case.

    Args:
        case_id (str):
        org_id (str | Unset):  Default: 'default'.
        body (EvidenceIn):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePostResponseAddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        case_id=case_id,
        body=body,
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    case_id: str,
    *,
    client: AuthenticatedClient,
    body: EvidenceIn,
    org_id: str | Unset = "default",
) -> (
    AddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePostResponseAddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePost
    | HTTPValidationError
    | None
):
    """Add Evidence

     Add an evidence item to a case.

    Args:
        case_id (str):
        org_id (str | Unset):  Default: 'default'.
        body (EvidenceIn):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePostResponseAddEvidenceApiV1EvidenceChainCasesCaseIdEvidencePost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            case_id=case_id,
            client=client,
            body=body,
            org_id=org_id,
        )
    ).parsed
