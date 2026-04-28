from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.list_risks_api_v1_risks_get_response_200_item import ListRisksApiV1RisksGetResponse200Item
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    org_id: str | Unset = "default",
    category: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    min_score: float | None | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    json_category: None | str | Unset
    if isinstance(category, Unset):
        json_category = UNSET
    else:
        json_category = category
    params["category"] = json_category

    json_status: None | str | Unset
    if isinstance(status, Unset):
        json_status = UNSET
    else:
        json_status = status
    params["status"] = json_status

    json_min_score: float | None | Unset
    if isinstance(min_score, Unset):
        json_min_score = UNSET
    else:
        json_min_score = min_score
    params["min_score"] = json_min_score

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/risks",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[ListRisksApiV1RisksGetResponse200Item] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = ListRisksApiV1RisksGetResponse200Item.from_dict(response_200_item_data)

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
) -> Response[HTTPValidationError | list[ListRisksApiV1RisksGetResponse200Item]]:
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
    category: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    min_score: float | None | Unset = UNSET,
) -> Response[HTTPValidationError | list[ListRisksApiV1RisksGetResponse200Item]]:
    """List risks

    Args:
        org_id (str | Unset):  Default: 'default'.
        category (None | str | Unset):
        status (None | str | Unset):
        min_score (float | None | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[ListRisksApiV1RisksGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        category=category,
        status=status,
        min_score=min_score,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    category: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    min_score: float | None | Unset = UNSET,
) -> HTTPValidationError | list[ListRisksApiV1RisksGetResponse200Item] | None:
    """List risks

    Args:
        org_id (str | Unset):  Default: 'default'.
        category (None | str | Unset):
        status (None | str | Unset):
        min_score (float | None | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[ListRisksApiV1RisksGetResponse200Item]
    """

    return sync_detailed(
        client=client,
        org_id=org_id,
        category=category,
        status=status,
        min_score=min_score,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    category: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    min_score: float | None | Unset = UNSET,
) -> Response[HTTPValidationError | list[ListRisksApiV1RisksGetResponse200Item]]:
    """List risks

    Args:
        org_id (str | Unset):  Default: 'default'.
        category (None | str | Unset):
        status (None | str | Unset):
        min_score (float | None | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[ListRisksApiV1RisksGetResponse200Item]]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        category=category,
        status=status,
        min_score=min_score,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    category: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
    min_score: float | None | Unset = UNSET,
) -> HTTPValidationError | list[ListRisksApiV1RisksGetResponse200Item] | None:
    """List risks

    Args:
        org_id (str | Unset):  Default: 'default'.
        category (None | str | Unset):
        status (None | str | Unset):
        min_score (float | None | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[ListRisksApiV1RisksGetResponse200Item]
    """

    return (
        await asyncio_detailed(
            client=client,
            org_id=org_id,
            category=category,
            status=status,
            min_score=min_score,
        )
    ).parsed
