from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.execution_response import ExecutionResponse
from ...models.http_validation_error import HTTPValidationError
from ...models.step_override_request import StepOverrideRequest
from ...types import Response


def _get_kwargs(
    execution_id: str,
    step_id: str,
    *,
    body: StepOverrideRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/playbooks/execution/{execution_id}/step/{step_id}/override".format(
            execution_id=quote(str(execution_id), safe=""),
            step_id=quote(str(step_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
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
    step_id: str,
    *,
    client: AuthenticatedClient,
    body: StepOverrideRequest,
) -> Response[ExecutionResponse | HTTPValidationError]:
    """Manual Step Override

     Analyst manually marks a step as overridden (completed or skipped). Useful when automated action
    fails but analyst completed it manually.

    Args:
        execution_id (str):
        step_id (str):
        body (StepOverrideRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ExecutionResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        execution_id=execution_id,
        step_id=step_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    execution_id: str,
    step_id: str,
    *,
    client: AuthenticatedClient,
    body: StepOverrideRequest,
) -> ExecutionResponse | HTTPValidationError | None:
    """Manual Step Override

     Analyst manually marks a step as overridden (completed or skipped). Useful when automated action
    fails but analyst completed it manually.

    Args:
        execution_id (str):
        step_id (str):
        body (StepOverrideRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ExecutionResponse | HTTPValidationError
    """

    return sync_detailed(
        execution_id=execution_id,
        step_id=step_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    execution_id: str,
    step_id: str,
    *,
    client: AuthenticatedClient,
    body: StepOverrideRequest,
) -> Response[ExecutionResponse | HTTPValidationError]:
    """Manual Step Override

     Analyst manually marks a step as overridden (completed or skipped). Useful when automated action
    fails but analyst completed it manually.

    Args:
        execution_id (str):
        step_id (str):
        body (StepOverrideRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ExecutionResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        execution_id=execution_id,
        step_id=step_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    execution_id: str,
    step_id: str,
    *,
    client: AuthenticatedClient,
    body: StepOverrideRequest,
) -> ExecutionResponse | HTTPValidationError | None:
    """Manual Step Override

     Analyst manually marks a step as overridden (completed or skipped). Useful when automated action
    fails but analyst completed it manually.

    Args:
        execution_id (str):
        step_id (str):
        body (StepOverrideRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ExecutionResponse | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            execution_id=execution_id,
            step_id=step_id,
            client=client,
            body=body,
        )
    ).parsed
