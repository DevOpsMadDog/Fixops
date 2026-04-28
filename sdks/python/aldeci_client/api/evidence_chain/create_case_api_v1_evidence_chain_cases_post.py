from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.case_in import CaseIn
from ...models.create_case_api_v1_evidence_chain_cases_post_response_create_case_api_v1_evidence_chain_cases_post import (
    CreateCaseApiV1EvidenceChainCasesPostResponseCreateCaseApiV1EvidenceChainCasesPost,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: CaseIn,
    org_id: str | Unset = "default",
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/evidence-chain/cases",
        "params": params,
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> CreateCaseApiV1EvidenceChainCasesPostResponseCreateCaseApiV1EvidenceChainCasesPost | HTTPValidationError | None:
    if response.status_code == 201:
        response_201 = CreateCaseApiV1EvidenceChainCasesPostResponseCreateCaseApiV1EvidenceChainCasesPost.from_dict(
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
) -> Response[CreateCaseApiV1EvidenceChainCasesPostResponseCreateCaseApiV1EvidenceChainCasesPost | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: CaseIn,
    org_id: str | Unset = "default",
) -> Response[CreateCaseApiV1EvidenceChainCasesPostResponseCreateCaseApiV1EvidenceChainCasesPost | HTTPValidationError]:
    """Create Case

     Create a new investigation case.

    Args:
        org_id (str | Unset):  Default: 'default'.
        body (CaseIn):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateCaseApiV1EvidenceChainCasesPostResponseCreateCaseApiV1EvidenceChainCasesPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
        org_id=org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: CaseIn,
    org_id: str | Unset = "default",
) -> CreateCaseApiV1EvidenceChainCasesPostResponseCreateCaseApiV1EvidenceChainCasesPost | HTTPValidationError | None:
    """Create Case

     Create a new investigation case.

    Args:
        org_id (str | Unset):  Default: 'default'.
        body (CaseIn):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateCaseApiV1EvidenceChainCasesPostResponseCreateCaseApiV1EvidenceChainCasesPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
        org_id=org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: CaseIn,
    org_id: str | Unset = "default",
) -> Response[CreateCaseApiV1EvidenceChainCasesPostResponseCreateCaseApiV1EvidenceChainCasesPost | HTTPValidationError]:
    """Create Case

     Create a new investigation case.

    Args:
        org_id (str | Unset):  Default: 'default'.
        body (CaseIn):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateCaseApiV1EvidenceChainCasesPostResponseCreateCaseApiV1EvidenceChainCasesPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: CaseIn,
    org_id: str | Unset = "default",
) -> CreateCaseApiV1EvidenceChainCasesPostResponseCreateCaseApiV1EvidenceChainCasesPost | HTTPValidationError | None:
    """Create Case

     Create a new investigation case.

    Args:
        org_id (str | Unset):  Default: 'default'.
        body (CaseIn):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateCaseApiV1EvidenceChainCasesPostResponseCreateCaseApiV1EvidenceChainCasesPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            org_id=org_id,
        )
    ).parsed
