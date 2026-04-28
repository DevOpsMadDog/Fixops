from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.runtime_traffic_api_v1_runtime_traffic_api_get_response_runtime_traffic_api_v1_runtime_traffic_api_get import (
    RuntimeTrafficApiV1RuntimeTrafficApiGetResponseRuntimeTrafficApiV1RuntimeTrafficApiGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    api: str,
    *,
    window_minutes: int | Unset = 60,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    params["window_minutes"] = window_minutes

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/runtime/traffic/{api}".format(
            api=quote(str(api), safe=""),
        ),
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError | RuntimeTrafficApiV1RuntimeTrafficApiGetResponseRuntimeTrafficApiV1RuntimeTrafficApiGet | None
):
    if response.status_code == 200:
        response_200 = RuntimeTrafficApiV1RuntimeTrafficApiGetResponseRuntimeTrafficApiV1RuntimeTrafficApiGet.from_dict(
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
    HTTPValidationError | RuntimeTrafficApiV1RuntimeTrafficApiGetResponseRuntimeTrafficApiV1RuntimeTrafficApiGet
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    api: str,
    *,
    client: AuthenticatedClient,
    window_minutes: int | Unset = 60,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError | RuntimeTrafficApiV1RuntimeTrafficApiGetResponseRuntimeTrafficApiV1RuntimeTrafficApiGet
]:
    """Return runtime traffic stats for an API path

     Return aggregate runtime traffic for an API path.

    Uses ``CodeToRuntimeMatcherEngine.list_events`` filtered by api_path.

    Args:
        api (str):
        window_minutes (int | Unset):  Default: 60.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RuntimeTrafficApiV1RuntimeTrafficApiGetResponseRuntimeTrafficApiV1RuntimeTrafficApiGet]
    """

    kwargs = _get_kwargs(
        api=api,
        window_minutes=window_minutes,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    api: str,
    *,
    client: AuthenticatedClient,
    window_minutes: int | Unset = 60,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError | RuntimeTrafficApiV1RuntimeTrafficApiGetResponseRuntimeTrafficApiV1RuntimeTrafficApiGet | None
):
    """Return runtime traffic stats for an API path

     Return aggregate runtime traffic for an API path.

    Uses ``CodeToRuntimeMatcherEngine.list_events`` filtered by api_path.

    Args:
        api (str):
        window_minutes (int | Unset):  Default: 60.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RuntimeTrafficApiV1RuntimeTrafficApiGetResponseRuntimeTrafficApiV1RuntimeTrafficApiGet
    """

    return sync_detailed(
        api=api,
        client=client,
        window_minutes=window_minutes,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    api: str,
    *,
    client: AuthenticatedClient,
    window_minutes: int | Unset = 60,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError | RuntimeTrafficApiV1RuntimeTrafficApiGetResponseRuntimeTrafficApiV1RuntimeTrafficApiGet
]:
    """Return runtime traffic stats for an API path

     Return aggregate runtime traffic for an API path.

    Uses ``CodeToRuntimeMatcherEngine.list_events`` filtered by api_path.

    Args:
        api (str):
        window_minutes (int | Unset):  Default: 60.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RuntimeTrafficApiV1RuntimeTrafficApiGetResponseRuntimeTrafficApiV1RuntimeTrafficApiGet]
    """

    kwargs = _get_kwargs(
        api=api,
        window_minutes=window_minutes,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    api: str,
    *,
    client: AuthenticatedClient,
    window_minutes: int | Unset = 60,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError | RuntimeTrafficApiV1RuntimeTrafficApiGetResponseRuntimeTrafficApiV1RuntimeTrafficApiGet | None
):
    """Return runtime traffic stats for an API path

     Return aggregate runtime traffic for an API path.

    Uses ``CodeToRuntimeMatcherEngine.list_events`` filtered by api_path.

    Args:
        api (str):
        window_minutes (int | Unset):  Default: 60.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RuntimeTrafficApiV1RuntimeTrafficApiGetResponseRuntimeTrafficApiV1RuntimeTrafficApiGet
    """

    return (
        await asyncio_detailed(
            api=api,
            client=client,
            window_minutes=window_minutes,
            x_org_id=x_org_id,
        )
    ).parsed
