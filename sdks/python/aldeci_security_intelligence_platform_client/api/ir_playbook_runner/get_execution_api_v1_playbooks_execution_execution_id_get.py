from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.execution_response import ExecutionResponse
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    execution_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/playbooks/execution/{execution_id}".format(
            execution_id=quote(str(execution_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ExecutionResponse | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = ExecutionResponse.from_dict(response.json())

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
) -> Response[ExecutionResponse | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    execution_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[ExecutionResponse | HTTPValidationError]:
    """Get Execution Status

     Get the current status and step results for a specific playbook execution.

    Args:
        execution_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ExecutionResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        execution_id=execution_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    execution_id: str,
    *,
    client: AuthenticatedClient,
) -> ExecutionResponse | HTTPValidationError | None:
    """Get Execution Status

     Get the current status and step results for a specific playbook execution.

    Args:
        execution_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ExecutionResponse | HTTPValidationError
    """

    return sync_detailed(
        execution_id=execution_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    execution_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[ExecutionResponse | HTTPValidationError]:
    """Get Execution Status

     Get the current status and step results for a specific playbook execution.

    Args:
        execution_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ExecutionResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        execution_id=execution_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    execution_id: str,
    *,
    client: AuthenticatedClient,
) -> ExecutionResponse | HTTPValidationError | None:
    """Get Execution Status

     Get the current status and step results for a specific playbook execution.

    Args:
        execution_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ExecutionResponse | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            execution_id=execution_id,
            client=client,
        )
    ).parsed
