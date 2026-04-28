from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    limit: int | Unset = 20,
    repository: None | str | Unset = UNSET,
    verdict: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["limit"] = limit

    json_repository: None | str | Unset
    if isinstance(repository, Unset):
        json_repository = UNSET
    else:
        json_repository = repository
    params["repository"] = json_repository

    json_verdict: None | str | Unset
    if isinstance(verdict, Unset):
        json_verdict = UNSET
    else:
        json_verdict = verdict
    params["verdict"] = json_verdict

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/gate/history",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = response.json()
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
) -> Response[Any | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 20,
    repository: None | str | Unset = UNSET,
    verdict: None | str | Unset = UNSET,
) -> Response[Any | HTTPValidationError]:
    """Gate History

     Get recent gate evaluations with optional filtering.

    Args:
        limit (int | Unset):  Default: 20.
        repository (None | str | Unset):
        verdict (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        limit=limit,
        repository=repository,
        verdict=verdict,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 20,
    repository: None | str | Unset = UNSET,
    verdict: None | str | Unset = UNSET,
) -> Any | HTTPValidationError | None:
    """Gate History

     Get recent gate evaluations with optional filtering.

    Args:
        limit (int | Unset):  Default: 20.
        repository (None | str | Unset):
        verdict (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        limit=limit,
        repository=repository,
        verdict=verdict,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 20,
    repository: None | str | Unset = UNSET,
    verdict: None | str | Unset = UNSET,
) -> Response[Any | HTTPValidationError]:
    """Gate History

     Get recent gate evaluations with optional filtering.

    Args:
        limit (int | Unset):  Default: 20.
        repository (None | str | Unset):
        verdict (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        limit=limit,
        repository=repository,
        verdict=verdict,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 20,
    repository: None | str | Unset = UNSET,
    verdict: None | str | Unset = UNSET,
) -> Any | HTTPValidationError | None:
    """Gate History

     Get recent gate evaluations with optional filtering.

    Args:
        limit (int | Unset):  Default: 20.
        repository (None | str | Unset):
        verdict (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            limit=limit,
            repository=repository,
            verdict=verdict,
        )
    ).parsed
