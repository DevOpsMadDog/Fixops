from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.execute_workflow_api_v1_workflows_id_execute_post_body_type_0 import (
    ExecuteWorkflowApiV1WorkflowsIdExecutePostBodyType0,
)
from ...models.http_validation_error import HTTPValidationError
from ...models.workflow_execution_response import WorkflowExecutionResponse
from ...types import UNSET, Response, Unset


def _get_kwargs(
    id: str,
    *,
    body: ExecuteWorkflowApiV1WorkflowsIdExecutePostBodyType0 | None | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/workflows/{id}/execute".format(
            id=quote(str(id), safe=""),
        ),
    }

    if isinstance(body, ExecuteWorkflowApiV1WorkflowsIdExecutePostBodyType0):
        _kwargs["json"] = body.to_dict()
    else:
        _kwargs["json"] = body

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | WorkflowExecutionResponse | None:
    if response.status_code == 200:
        response_200 = WorkflowExecutionResponse.from_dict(response.json())

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
) -> Response[HTTPValidationError | WorkflowExecutionResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    id: str,
    *,
    client: AuthenticatedClient,
    body: ExecuteWorkflowApiV1WorkflowsIdExecutePostBodyType0 | None | Unset = UNSET,
) -> Response[HTTPValidationError | WorkflowExecutionResponse]:
    """Execute Workflow

     Execute a workflow with real step-by-step processing.

    Supports conditional branching, retries with exponential back-off,
    parallel step groups, and SLA deadline checking.

    Args:
        id (str):
        body (ExecuteWorkflowApiV1WorkflowsIdExecutePostBodyType0 | None | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | WorkflowExecutionResponse]
    """

    kwargs = _get_kwargs(
        id=id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    id: str,
    *,
    client: AuthenticatedClient,
    body: ExecuteWorkflowApiV1WorkflowsIdExecutePostBodyType0 | None | Unset = UNSET,
) -> HTTPValidationError | WorkflowExecutionResponse | None:
    """Execute Workflow

     Execute a workflow with real step-by-step processing.

    Supports conditional branching, retries with exponential back-off,
    parallel step groups, and SLA deadline checking.

    Args:
        id (str):
        body (ExecuteWorkflowApiV1WorkflowsIdExecutePostBodyType0 | None | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | WorkflowExecutionResponse
    """

    return sync_detailed(
        id=id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    id: str,
    *,
    client: AuthenticatedClient,
    body: ExecuteWorkflowApiV1WorkflowsIdExecutePostBodyType0 | None | Unset = UNSET,
) -> Response[HTTPValidationError | WorkflowExecutionResponse]:
    """Execute Workflow

     Execute a workflow with real step-by-step processing.

    Supports conditional branching, retries with exponential back-off,
    parallel step groups, and SLA deadline checking.

    Args:
        id (str):
        body (ExecuteWorkflowApiV1WorkflowsIdExecutePostBodyType0 | None | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | WorkflowExecutionResponse]
    """

    kwargs = _get_kwargs(
        id=id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    id: str,
    *,
    client: AuthenticatedClient,
    body: ExecuteWorkflowApiV1WorkflowsIdExecutePostBodyType0 | None | Unset = UNSET,
) -> HTTPValidationError | WorkflowExecutionResponse | None:
    """Execute Workflow

     Execute a workflow with real step-by-step processing.

    Supports conditional branching, retries with exponential back-off,
    parallel step groups, and SLA deadline checking.

    Args:
        id (str):
        body (ExecuteWorkflowApiV1WorkflowsIdExecutePostBodyType0 | None | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | WorkflowExecutionResponse
    """

    return (
        await asyncio_detailed(
            id=id,
            client=client,
            body=body,
        )
    ).parsed
