from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.test_connector_api_v1_connectors_name_test_post_response_test_connector_api_v1_connectors_name_test_post import (
    TestConnectorApiV1ConnectorsNameTestPostResponseTestConnectorApiV1ConnectorsNameTestPost,
)
from ...types import Response


def _get_kwargs(
    name: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/connectors/{name}/test".format(
            name=quote(str(name), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | TestConnectorApiV1ConnectorsNameTestPostResponseTestConnectorApiV1ConnectorsNameTestPost
    | None
):
    if response.status_code == 200:
        response_200 = (
            TestConnectorApiV1ConnectorsNameTestPostResponseTestConnectorApiV1ConnectorsNameTestPost.from_dict(
                response.json()
            )
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
    HTTPValidationError | TestConnectorApiV1ConnectorsNameTestPostResponseTestConnectorApiV1ConnectorsNameTestPost
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    name: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    HTTPValidationError | TestConnectorApiV1ConnectorsNameTestPostResponseTestConnectorApiV1ConnectorsNameTestPost
]:
    """Test a specific connector

     Test connectivity to a specific registered connector.

    Args:
        name (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | TestConnectorApiV1ConnectorsNameTestPostResponseTestConnectorApiV1ConnectorsNameTestPost]
    """

    kwargs = _get_kwargs(
        name=name,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    name: str,
    *,
    client: AuthenticatedClient,
) -> (
    HTTPValidationError
    | TestConnectorApiV1ConnectorsNameTestPostResponseTestConnectorApiV1ConnectorsNameTestPost
    | None
):
    """Test a specific connector

     Test connectivity to a specific registered connector.

    Args:
        name (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | TestConnectorApiV1ConnectorsNameTestPostResponseTestConnectorApiV1ConnectorsNameTestPost
    """

    return sync_detailed(
        name=name,
        client=client,
    ).parsed


async def asyncio_detailed(
    name: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    HTTPValidationError | TestConnectorApiV1ConnectorsNameTestPostResponseTestConnectorApiV1ConnectorsNameTestPost
]:
    """Test a specific connector

     Test connectivity to a specific registered connector.

    Args:
        name (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | TestConnectorApiV1ConnectorsNameTestPostResponseTestConnectorApiV1ConnectorsNameTestPost]
    """

    kwargs = _get_kwargs(
        name=name,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    name: str,
    *,
    client: AuthenticatedClient,
) -> (
    HTTPValidationError
    | TestConnectorApiV1ConnectorsNameTestPostResponseTestConnectorApiV1ConnectorsNameTestPost
    | None
):
    """Test a specific connector

     Test connectivity to a specific registered connector.

    Args:
        name (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | TestConnectorApiV1ConnectorsNameTestPostResponseTestConnectorApiV1ConnectorsNameTestPost
    """

    return (
        await asyncio_detailed(
            name=name,
            client=client,
        )
    ).parsed
