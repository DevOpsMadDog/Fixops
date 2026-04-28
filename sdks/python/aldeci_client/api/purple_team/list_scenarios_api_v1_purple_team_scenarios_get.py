from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.scenario_list_response import ScenarioListResponse
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    category: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_category: None | str | Unset
    if isinstance(category, Unset):
        json_category = UNSET
    else:
        json_category = category
    params["category"] = json_category

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/purple-team/scenarios",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[ScenarioListResponse] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = ScenarioListResponse.from_dict(response_200_item_data)

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
) -> Response[HTTPValidationError | list[ScenarioListResponse]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    category: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[ScenarioListResponse]]:
    """List pre-built attack scenarios

     Returns the built-in scenario library (30+ scenarios).
    Each scenario has pre-mapped MITRE ATT&CK techniques and estimated duration.

    Args:
        category (None | str | Unset): Filter by category (e.g. ransomware, cloud_breach)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[ScenarioListResponse]]
    """

    kwargs = _get_kwargs(
        category=category,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    category: None | str | Unset = UNSET,
) -> HTTPValidationError | list[ScenarioListResponse] | None:
    """List pre-built attack scenarios

     Returns the built-in scenario library (30+ scenarios).
    Each scenario has pre-mapped MITRE ATT&CK techniques and estimated duration.

    Args:
        category (None | str | Unset): Filter by category (e.g. ransomware, cloud_breach)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[ScenarioListResponse]
    """

    return sync_detailed(
        client=client,
        category=category,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    category: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | list[ScenarioListResponse]]:
    """List pre-built attack scenarios

     Returns the built-in scenario library (30+ scenarios).
    Each scenario has pre-mapped MITRE ATT&CK techniques and estimated duration.

    Args:
        category (None | str | Unset): Filter by category (e.g. ransomware, cloud_breach)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[ScenarioListResponse]]
    """

    kwargs = _get_kwargs(
        category=category,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    category: None | str | Unset = UNSET,
) -> HTTPValidationError | list[ScenarioListResponse] | None:
    """List pre-built attack scenarios

     Returns the built-in scenario library (30+ scenarios).
    Each scenario has pre-mapped MITRE ATT&CK techniques and estimated duration.

    Args:
        category (None | str | Unset): Filter by category (e.g. ransomware, cloud_breach)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[ScenarioListResponse]
    """

    return (
        await asyncio_detailed(
            client=client,
            category=category,
        )
    ).parsed
