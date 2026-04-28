from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_task_timeline_api_v1_remediation_tasks_task_id_timeline_get_response_get_task_timeline_api_v1_remediation_tasks_task_id_timeline_get import (
    GetTaskTimelineApiV1RemediationTasksTaskIdTimelineGetResponseGetTaskTimelineApiV1RemediationTasksTaskIdTimelineGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    task_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/remediation/tasks/{task_id}/timeline".format(
            task_id=quote(str(task_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetTaskTimelineApiV1RemediationTasksTaskIdTimelineGetResponseGetTaskTimelineApiV1RemediationTasksTaskIdTimelineGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = GetTaskTimelineApiV1RemediationTasksTaskIdTimelineGetResponseGetTaskTimelineApiV1RemediationTasksTaskIdTimelineGet.from_dict(
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
    GetTaskTimelineApiV1RemediationTasksTaskIdTimelineGetResponseGetTaskTimelineApiV1RemediationTasksTaskIdTimelineGet
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
) -> Response[
    GetTaskTimelineApiV1RemediationTasksTaskIdTimelineGetResponseGetTaskTimelineApiV1RemediationTasksTaskIdTimelineGet
    | HTTPValidationError
]:
    """Get Task Timeline

     Full remediation lifecycle timeline for a task.

    Returns every phase of the finding lifecycle:
    discovery → triage → ticket → fix → verification → evidence,
    assembled from task_history, task metadata, and linked evidence.

    Args:
        task_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetTaskTimelineApiV1RemediationTasksTaskIdTimelineGetResponseGetTaskTimelineApiV1RemediationTasksTaskIdTimelineGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        task_id=task_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    task_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetTaskTimelineApiV1RemediationTasksTaskIdTimelineGetResponseGetTaskTimelineApiV1RemediationTasksTaskIdTimelineGet
    | HTTPValidationError
    | None
):
    """Get Task Timeline

     Full remediation lifecycle timeline for a task.

    Returns every phase of the finding lifecycle:
    discovery → triage → ticket → fix → verification → evidence,
    assembled from task_history, task metadata, and linked evidence.

    Args:
        task_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetTaskTimelineApiV1RemediationTasksTaskIdTimelineGetResponseGetTaskTimelineApiV1RemediationTasksTaskIdTimelineGet | HTTPValidationError
    """

    return sync_detailed(
        task_id=task_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    task_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetTaskTimelineApiV1RemediationTasksTaskIdTimelineGetResponseGetTaskTimelineApiV1RemediationTasksTaskIdTimelineGet
    | HTTPValidationError
]:
    """Get Task Timeline

     Full remediation lifecycle timeline for a task.

    Returns every phase of the finding lifecycle:
    discovery → triage → ticket → fix → verification → evidence,
    assembled from task_history, task metadata, and linked evidence.

    Args:
        task_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetTaskTimelineApiV1RemediationTasksTaskIdTimelineGetResponseGetTaskTimelineApiV1RemediationTasksTaskIdTimelineGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        task_id=task_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    task_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetTaskTimelineApiV1RemediationTasksTaskIdTimelineGetResponseGetTaskTimelineApiV1RemediationTasksTaskIdTimelineGet
    | HTTPValidationError
    | None
):
    """Get Task Timeline

     Full remediation lifecycle timeline for a task.

    Returns every phase of the finding lifecycle:
    discovery → triage → ticket → fix → verification → evidence,
    assembled from task_history, task metadata, and linked evidence.

    Args:
        task_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetTaskTimelineApiV1RemediationTasksTaskIdTimelineGetResponseGetTaskTimelineApiV1RemediationTasksTaskIdTimelineGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            task_id=task_id,
            client=client,
        )
    ).parsed
