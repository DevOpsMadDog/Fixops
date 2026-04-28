from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.list_cases_api_v1_evidence_chain_cases_get_response_200_item import (
    ListCasesApiV1EvidenceChainCasesGetResponse200Item,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    org_id: str | Unset = "default",
    status: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    json_status: None | str | Unset
    if isinstance(status, Unset):
        json_status = UNSET
    else:
        json_status = status
    params["status"] = json_status

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/evidence-chain/cases",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[ListCasesApiV1EvidenceChainCasesGetResponse200Item] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = ListCasesApiV1EvidenceChainCasesGetResponse200Item.from_dict(response_200_item_data)

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
) -> Response[HTTPValidationError | list[ListCasesApiV1EvidenceChainCasesGetResponse200Item]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    status: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[ListCasesApiV1EvidenceChainCasesGetResponse200Item]]:
    """List Cases

     List all investigation cases for an org.

    Args:
        org_id (str | Unset):  Default: 'default'.
        status (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[ListCasesApiV1EvidenceChainCasesGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        status=status,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    status: None | str | Unset = UNSET,
) -> HTTPValidationError | list[ListCasesApiV1EvidenceChainCasesGetResponse200Item] | None:
    """List Cases

     List all investigation cases for an org.

    Args:
        org_id (str | Unset):  Default: 'default'.
        status (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[ListCasesApiV1EvidenceChainCasesGetResponse200Item]
    """

    return sync_detailed(
        client=client,
        org_id=org_id,
        status=status,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    status: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[ListCasesApiV1EvidenceChainCasesGetResponse200Item]]:
    """List Cases

     List all investigation cases for an org.

    Args:
        org_id (str | Unset):  Default: 'default'.
        status (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[ListCasesApiV1EvidenceChainCasesGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        status=status,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    status: None | str | Unset = UNSET,
) -> HTTPValidationError | list[ListCasesApiV1EvidenceChainCasesGetResponse200Item] | None:
    """List Cases

     List all investigation cases for an org.

    Args:
        org_id (str | Unset):  Default: 'default'.
        status (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[ListCasesApiV1EvidenceChainCasesGetResponse200Item]
    """

    return (
        await asyncio_detailed(
            client=client,
            org_id=org_id,
            status=status,
        )
    ).parsed
