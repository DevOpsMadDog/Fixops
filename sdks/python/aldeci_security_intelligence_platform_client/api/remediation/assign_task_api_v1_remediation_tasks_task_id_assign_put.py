from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.assign_task_api_v1_remediation_tasks_task_id_assign_put_response_assign_task_api_v1_remediation_tasks_task_id_assign_put import (
    AssignTaskApiV1RemediationTasksTaskIdAssignPutResponseAssignTaskApiV1RemediationTasksTaskIdAssignPut,
)
from ...models.assign_task_request import AssignTaskRequest
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    task_id: str,
    *,
    body: AssignTaskRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/remediation/tasks/{task_id}/assign".format(
            task_id=quote(str(task_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    AssignTaskApiV1RemediationTasksTaskIdAssignPutResponseAssignTaskApiV1RemediationTasksTaskIdAssignPut
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = AssignTaskApiV1RemediationTasksTaskIdAssignPutResponseAssignTaskApiV1RemediationTasksTaskIdAssignPut.from_dict(
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
    AssignTaskApiV1RemediationTasksTaskIdAssignPutResponseAssignTaskApiV1RemediationTasksTaskIdAssignPut
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    task_id: str,
    *,
    client: AuthenticatedClient,
    body: AssignTaskRequest,
) -> Response[
    AssignTaskApiV1RemediationTasksTaskIdAssignPutResponseAssignTaskApiV1RemediationTasksTaskIdAssignPut
    | HTTPValidationError
]:
    """Assign Task

     Assign task to a user.

    Args:
        task_id (str):
        body (AssignTaskRequest): Request to assign task.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AssignTaskApiV1RemediationTasksTaskIdAssignPutResponseAssignTaskApiV1RemediationTasksTaskIdAssignPut | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        task_id=task_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    task_id: str,
    *,
    client: AuthenticatedClient,
    body: AssignTaskRequest,
) -> (
    AssignTaskApiV1RemediationTasksTaskIdAssignPutResponseAssignTaskApiV1RemediationTasksTaskIdAssignPut
    | HTTPValidationError
    | None
):
    """Assign Task

     Assign task to a user.

    Args:
        task_id (str):
        body (AssignTaskRequest): Request to assign task.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AssignTaskApiV1RemediationTasksTaskIdAssignPutResponseAssignTaskApiV1RemediationTasksTaskIdAssignPut | HTTPValidationError
    """

    return sync_detailed(
        task_id=task_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    task_id: str,
    *,
    client: AuthenticatedClient,
    body: AssignTaskRequest,
) -> Response[
    AssignTaskApiV1RemediationTasksTaskIdAssignPutResponseAssignTaskApiV1RemediationTasksTaskIdAssignPut
    | HTTPValidationError
]:
    """Assign Task

     Assign task to a user.

    Args:
        task_id (str):
        body (AssignTaskRequest): Request to assign task.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AssignTaskApiV1RemediationTasksTaskIdAssignPutResponseAssignTaskApiV1RemediationTasksTaskIdAssignPut | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        task_id=task_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    task_id: str,
    *,
    client: AuthenticatedClient,
    body: AssignTaskRequest,
) -> (
    AssignTaskApiV1RemediationTasksTaskIdAssignPutResponseAssignTaskApiV1RemediationTasksTaskIdAssignPut
    | HTTPValidationError
    | None
):
    """Assign Task

     Assign task to a user.

    Args:
        task_id (str):
        body (AssignTaskRequest): Request to assign task.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AssignTaskApiV1RemediationTasksTaskIdAssignPutResponseAssignTaskApiV1RemediationTasksTaskIdAssignPut | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            task_id=task_id,
            client=client,
            body=body,
        )
    ).parsed
