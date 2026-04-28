from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.register_connector_api_v1_connectors_register_post_response_register_connector_api_v1_connectors_register_post import (
    RegisterConnectorApiV1ConnectorsRegisterPostResponseRegisterConnectorApiV1ConnectorsRegisterPost,
)
from ...models.register_connector_request import RegisterConnectorRequest
from ...types import Response


def _get_kwargs(
    *,
    body: RegisterConnectorRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/connectors/register",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | RegisterConnectorApiV1ConnectorsRegisterPostResponseRegisterConnectorApiV1ConnectorsRegisterPost
    | None
):
    if response.status_code == 200:
        response_200 = (
            RegisterConnectorApiV1ConnectorsRegisterPostResponseRegisterConnectorApiV1ConnectorsRegisterPost.from_dict(
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
    HTTPValidationError
    | RegisterConnectorApiV1ConnectorsRegisterPostResponseRegisterConnectorApiV1ConnectorsRegisterPost
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: RegisterConnectorRequest,
) -> Response[
    HTTPValidationError
    | RegisterConnectorApiV1ConnectorsRegisterPostResponseRegisterConnectorApiV1ConnectorsRegisterPost
]:
    """Register a new connector

     Register a Jira, GitHub, or Slack connector.

    Credentials are validated for format but not tested against the
    remote API. Use POST /test after registration to verify connectivity.

    Args:
        body (RegisterConnectorRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RegisterConnectorApiV1ConnectorsRegisterPostResponseRegisterConnectorApiV1ConnectorsRegisterPost]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: RegisterConnectorRequest,
) -> (
    HTTPValidationError
    | RegisterConnectorApiV1ConnectorsRegisterPostResponseRegisterConnectorApiV1ConnectorsRegisterPost
    | None
):
    """Register a new connector

     Register a Jira, GitHub, or Slack connector.

    Credentials are validated for format but not tested against the
    remote API. Use POST /test after registration to verify connectivity.

    Args:
        body (RegisterConnectorRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RegisterConnectorApiV1ConnectorsRegisterPostResponseRegisterConnectorApiV1ConnectorsRegisterPost
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: RegisterConnectorRequest,
) -> Response[
    HTTPValidationError
    | RegisterConnectorApiV1ConnectorsRegisterPostResponseRegisterConnectorApiV1ConnectorsRegisterPost
]:
    """Register a new connector

     Register a Jira, GitHub, or Slack connector.

    Credentials are validated for format but not tested against the
    remote API. Use POST /test after registration to verify connectivity.

    Args:
        body (RegisterConnectorRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RegisterConnectorApiV1ConnectorsRegisterPostResponseRegisterConnectorApiV1ConnectorsRegisterPost]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: RegisterConnectorRequest,
) -> (
    HTTPValidationError
    | RegisterConnectorApiV1ConnectorsRegisterPostResponseRegisterConnectorApiV1ConnectorsRegisterPost
    | None
):
    """Register a new connector

     Register a Jira, GitHub, or Slack connector.

    Credentials are validated for format but not tested against the
    remote API. Use POST /test after registration to verify connectivity.

    Args:
        body (RegisterConnectorRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RegisterConnectorApiV1ConnectorsRegisterPostResponseRegisterConnectorApiV1ConnectorsRegisterPost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
