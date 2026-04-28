from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.close_case_api_v1_evidence_chain_cases_case_id_close_post_response_close_case_api_v1_evidence_chain_cases_case_id_close_post import (
    CloseCaseApiV1EvidenceChainCasesCaseIdClosePostResponseCloseCaseApiV1EvidenceChainCasesCaseIdClosePost,
)
from ...models.close_in import CloseIn
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    case_id: str,
    *,
    body: CloseIn,
    org_id: str | Unset = "default",
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/evidence-chain/cases/{case_id}/close".format(
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
    CloseCaseApiV1EvidenceChainCasesCaseIdClosePostResponseCloseCaseApiV1EvidenceChainCasesCaseIdClosePost
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = CloseCaseApiV1EvidenceChainCasesCaseIdClosePostResponseCloseCaseApiV1EvidenceChainCasesCaseIdClosePost.from_dict(
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
    CloseCaseApiV1EvidenceChainCasesCaseIdClosePostResponseCloseCaseApiV1EvidenceChainCasesCaseIdClosePost
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
    body: CloseIn,
    org_id: str | Unset = "default",
) -> Response[
    CloseCaseApiV1EvidenceChainCasesCaseIdClosePostResponseCloseCaseApiV1EvidenceChainCasesCaseIdClosePost
    | HTTPValidationError
]:
    """Close Case

     Close a case with outcome.

    Args:
        case_id (str):
        org_id (str | Unset):  Default: 'default'.
        body (CloseIn):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CloseCaseApiV1EvidenceChainCasesCaseIdClosePostResponseCloseCaseApiV1EvidenceChainCasesCaseIdClosePost | HTTPValidationError]
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
    body: CloseIn,
    org_id: str | Unset = "default",
) -> (
    CloseCaseApiV1EvidenceChainCasesCaseIdClosePostResponseCloseCaseApiV1EvidenceChainCasesCaseIdClosePost
    | HTTPValidationError
    | None
):
    """Close Case

     Close a case with outcome.

    Args:
        case_id (str):
        org_id (str | Unset):  Default: 'default'.
        body (CloseIn):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CloseCaseApiV1EvidenceChainCasesCaseIdClosePostResponseCloseCaseApiV1EvidenceChainCasesCaseIdClosePost | HTTPValidationError
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
    body: CloseIn,
    org_id: str | Unset = "default",
) -> Response[
    CloseCaseApiV1EvidenceChainCasesCaseIdClosePostResponseCloseCaseApiV1EvidenceChainCasesCaseIdClosePost
    | HTTPValidationError
]:
    """Close Case

     Close a case with outcome.

    Args:
        case_id (str):
        org_id (str | Unset):  Default: 'default'.
        body (CloseIn):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CloseCaseApiV1EvidenceChainCasesCaseIdClosePostResponseCloseCaseApiV1EvidenceChainCasesCaseIdClosePost | HTTPValidationError]
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
    body: CloseIn,
    org_id: str | Unset = "default",
) -> (
    CloseCaseApiV1EvidenceChainCasesCaseIdClosePostResponseCloseCaseApiV1EvidenceChainCasesCaseIdClosePost
    | HTTPValidationError
    | None
):
    """Close Case

     Close a case with outcome.

    Args:
        case_id (str):
        org_id (str | Unset):  Default: 'default'.
        body (CloseIn):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CloseCaseApiV1EvidenceChainCasesCaseIdClosePostResponseCloseCaseApiV1EvidenceChainCasesCaseIdClosePost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            case_id=case_id,
            client=client,
            body=body,
            org_id=org_id,
        )
    ).parsed
