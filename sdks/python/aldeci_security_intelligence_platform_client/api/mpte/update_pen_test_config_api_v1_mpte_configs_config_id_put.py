from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.update_pen_test_config_model import UpdatePenTestConfigModel
from ...types import Response


def _get_kwargs(
    config_id: str,
    *,
    body: UpdatePenTestConfigModel,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/mpte/configs/{config_id}".format(
            config_id=quote(str(config_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
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
    config_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdatePenTestConfigModel,
) -> Response[Any | HTTPValidationError]:
    """Update Pen Test Config

     Update MPTE configuration.

    Args:
        config_id (str):
        body (UpdatePenTestConfigModel): Model for updating MPTE configuration.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        config_id=config_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    config_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdatePenTestConfigModel,
) -> Any | HTTPValidationError | None:
    """Update Pen Test Config

     Update MPTE configuration.

    Args:
        config_id (str):
        body (UpdatePenTestConfigModel): Model for updating MPTE configuration.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return sync_detailed(
        config_id=config_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    config_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdatePenTestConfigModel,
) -> Response[Any | HTTPValidationError]:
    """Update Pen Test Config

     Update MPTE configuration.

    Args:
        config_id (str):
        body (UpdatePenTestConfigModel): Model for updating MPTE configuration.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        config_id=config_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    config_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdatePenTestConfigModel,
) -> Any | HTTPValidationError | None:
    """Update Pen Test Config

     Update MPTE configuration.

    Args:
        config_id (str):
        body (UpdatePenTestConfigModel): Model for updating MPTE configuration.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            config_id=config_id,
            client=client,
            body=body,
        )
    ).parsed
