from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_task_autofix_suggestions_api_v1_remediation_tasks_task_id_autofix_suggestions_get_response_get_task_autofix_suggestions_api_v1_remediation_tasks_task_id_autofix_suggestions_get import (
    GetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGetResponseGetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    task_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/remediation/tasks/{task_id}/autofix/suggestions".format(
            task_id=quote(str(task_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGetResponseGetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = GetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGetResponseGetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGet.from_dict(
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
    GetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGetResponseGetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGet
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
    GetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGetResponseGetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGet
    | HTTPValidationError
]:
    """Get Task Autofix Suggestions

     Get existing autofix suggestions for a remediation task.

    Args:
        task_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGetResponseGetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGet | HTTPValidationError]
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
    GetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGetResponseGetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGet
    | HTTPValidationError
    | None
):
    """Get Task Autofix Suggestions

     Get existing autofix suggestions for a remediation task.

    Args:
        task_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGetResponseGetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGet | HTTPValidationError
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
    GetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGetResponseGetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGet
    | HTTPValidationError
]:
    """Get Task Autofix Suggestions

     Get existing autofix suggestions for a remediation task.

    Args:
        task_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGetResponseGetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGet | HTTPValidationError]
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
    GetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGetResponseGetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGet
    | HTTPValidationError
    | None
):
    """Get Task Autofix Suggestions

     Get existing autofix suggestions for a remediation task.

    Args:
        task_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGetResponseGetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            task_id=task_id,
            client=client,
        )
    ).parsed
