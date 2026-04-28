from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.list_evidence_api_v1_evidence_chain_cases_case_id_evidence_get_response_200_item import (
    ListEvidenceApiV1EvidenceChainCasesCaseIdEvidenceGetResponse200Item,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    case_id: str,
    *,
    org_id: str | Unset = "default",
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/evidence-chain/cases/{case_id}/evidence".format(
            case_id=quote(str(case_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[ListEvidenceApiV1EvidenceChainCasesCaseIdEvidenceGetResponse200Item] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = ListEvidenceApiV1EvidenceChainCasesCaseIdEvidenceGetResponse200Item.from_dict(
                response_200_item_data
            )

            response_200.append(response_200_item)

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
) -> Response[HTTPValidationError | list[ListEvidenceApiV1EvidenceChainCasesCaseIdEvidenceGetResponse200Item]]:
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
    org_id: str | Unset = "default",
) -> Response[HTTPValidationError | list[ListEvidenceApiV1EvidenceChainCasesCaseIdEvidenceGetResponse200Item]]:
    """List Evidence

     List all evidence items for a case.

    Args:
        case_id (str):
        org_id (str | Unset):  Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[ListEvidenceApiV1EvidenceChainCasesCaseIdEvidenceGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        case_id=case_id,
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
    org_id: str | Unset = "default",
) -> HTTPValidationError | list[ListEvidenceApiV1EvidenceChainCasesCaseIdEvidenceGetResponse200Item] | None:
    """List Evidence

     List all evidence items for a case.

    Args:
        case_id (str):
        org_id (str | Unset):  Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[ListEvidenceApiV1EvidenceChainCasesCaseIdEvidenceGetResponse200Item]
    """

    return sync_detailed(
        case_id=case_id,
        client=client,
        org_id=org_id,
    ).parsed


async def asyncio_detailed(
    case_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> Response[HTTPValidationError | list[ListEvidenceApiV1EvidenceChainCasesCaseIdEvidenceGetResponse200Item]]:
    """List Evidence

     List all evidence items for a case.

    Args:
        case_id (str):
        org_id (str | Unset):  Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[ListEvidenceApiV1EvidenceChainCasesCaseIdEvidenceGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        case_id=case_id,
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    case_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> HTTPValidationError | list[ListEvidenceApiV1EvidenceChainCasesCaseIdEvidenceGetResponse200Item] | None:
    """List Evidence

     List all evidence items for a case.

    Args:
        case_id (str):
        org_id (str | Unset):  Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[ListEvidenceApiV1EvidenceChainCasesCaseIdEvidenceGetResponse200Item]
    """

    return (
        await asyncio_detailed(
            case_id=case_id,
            client=client,
            org_id=org_id,
        )
    ).parsed
