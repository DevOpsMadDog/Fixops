from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.aws_status_response import AWSStatusResponse
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/scan/aws-security-hub/status",
    }

    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> AWSStatusResponse | None:
    if response.status_code == 200:
        response_200 = AWSStatusResponse.from_dict(response.json())

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[AWSStatusResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[AWSStatusResponse]:
    """Check AWS Security Hub configuration

     Return whether AWS credentials are configured.

    When unconfigured all endpoints return mock data so the pipeline
    can be exercised without real AWS credentials.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AWSStatusResponse]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> AWSStatusResponse | None:
    """Check AWS Security Hub configuration

     Return whether AWS credentials are configured.

    When unconfigured all endpoints return mock data so the pipeline
    can be exercised without real AWS credentials.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AWSStatusResponse
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[AWSStatusResponse]:
    """Check AWS Security Hub configuration

     Return whether AWS credentials are configured.

    When unconfigured all endpoints return mock data so the pipeline
    can be exercised without real AWS credentials.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AWSStatusResponse]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> AWSStatusResponse | None:
    """Check AWS Security Hub configuration

     Return whether AWS credentials are configured.

    When unconfigured all endpoints return mock data so the pipeline
    can be exercised without real AWS credentials.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AWSStatusResponse
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
