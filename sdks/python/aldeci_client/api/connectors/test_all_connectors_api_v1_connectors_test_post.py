from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.test_all_connectors_api_v1_connectors_test_post_response_test_all_connectors_api_v1_connectors_test_post import (
    TestAllConnectorsApiV1ConnectorsTestPostResponseTestAllConnectorsApiV1ConnectorsTestPost,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/connectors/test",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> TestAllConnectorsApiV1ConnectorsTestPostResponseTestAllConnectorsApiV1ConnectorsTestPost | None:
    if response.status_code == 200:
        response_200 = (
            TestAllConnectorsApiV1ConnectorsTestPostResponseTestAllConnectorsApiV1ConnectorsTestPost.from_dict(
                response.json()
            )
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[TestAllConnectorsApiV1ConnectorsTestPostResponseTestAllConnectorsApiV1ConnectorsTestPost]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[TestAllConnectorsApiV1ConnectorsTestPostResponseTestAllConnectorsApiV1ConnectorsTestPost]:
    """Test all connectors

     Test connectivity to all registered connectors.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[TestAllConnectorsApiV1ConnectorsTestPostResponseTestAllConnectorsApiV1ConnectorsTestPost]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> TestAllConnectorsApiV1ConnectorsTestPostResponseTestAllConnectorsApiV1ConnectorsTestPost | None:
    """Test all connectors

     Test connectivity to all registered connectors.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        TestAllConnectorsApiV1ConnectorsTestPostResponseTestAllConnectorsApiV1ConnectorsTestPost
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[TestAllConnectorsApiV1ConnectorsTestPostResponseTestAllConnectorsApiV1ConnectorsTestPost]:
    """Test all connectors

     Test connectivity to all registered connectors.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[TestAllConnectorsApiV1ConnectorsTestPostResponseTestAllConnectorsApiV1ConnectorsTestPost]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> TestAllConnectorsApiV1ConnectorsTestPostResponseTestAllConnectorsApiV1ConnectorsTestPost | None:
    """Test all connectors

     Test connectivity to all registered connectors.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        TestAllConnectorsApiV1ConnectorsTestPostResponseTestAllConnectorsApiV1ConnectorsTestPost
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
