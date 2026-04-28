from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    org_id: str | Unset = "default",
    trigger_type: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    json_trigger_type: None | str | Unset
    if isinstance(trigger_type, Unset):
        json_trigger_type = UNSET
    else:
        json_trigger_type = trigger_type
    params["trigger_type"] = json_trigger_type

    json_status: None | str | Unset
    if isinstance(status, Unset):
        json_status = UNSET
    else:
        json_status = status
    params["status"] = json_status

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/workflows",
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
    org_id: str | Unset = "default",
    trigger_type: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
) -> Response[Any | HTTPValidationError]:
    """List Workflows

     List workflows, optionally filtered by org_id and trigger type.

    Args:
        org_id (str | Unset):  Default: 'default'.
        trigger_type (None | str | Unset):
        status (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        trigger_type=trigger_type,
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
    trigger_type: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
) -> Any | HTTPValidationError | None:
    """List Workflows

     List workflows, optionally filtered by org_id and trigger type.

    Args:
        org_id (str | Unset):  Default: 'default'.
        trigger_type (None | str | Unset):
        status (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        org_id=org_id,
        trigger_type=trigger_type,
        status=status,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    trigger_type: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
) -> Response[Any | HTTPValidationError]:
    """List Workflows

     List workflows, optionally filtered by org_id and trigger type.

    Args:
        org_id (str | Unset):  Default: 'default'.
        trigger_type (None | str | Unset):
        status (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        trigger_type=trigger_type,
        status=status,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    trigger_type: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
) -> Any | HTTPValidationError | None:
    """List Workflows

     List workflows, optionally filtered by org_id and trigger type.

    Args:
        org_id (str | Unset):  Default: 'default'.
        trigger_type (None | str | Unset):
        status (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            org_id=org_id,
            trigger_type=trigger_type,
            status=status,
        )
    ).parsed
