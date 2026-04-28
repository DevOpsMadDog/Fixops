from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.submit_verification_request import SubmitVerificationRequest
from ...models.verify_task_api_v1_remediation_tasks_task_id_verify_post_response_verify_task_api_v1_remediation_tasks_task_id_verify_post import (
    VerifyTaskApiV1RemediationTasksTaskIdVerifyPostResponseVerifyTaskApiV1RemediationTasksTaskIdVerifyPost,
)
from ...types import Response


def _get_kwargs(
    task_id: str,
    *,
    body: SubmitVerificationRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/remediation/tasks/{task_id}/verify".format(
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
    HTTPValidationError
    | VerifyTaskApiV1RemediationTasksTaskIdVerifyPostResponseVerifyTaskApiV1RemediationTasksTaskIdVerifyPost
    | None
):
    if response.status_code == 200:
        response_200 = VerifyTaskApiV1RemediationTasksTaskIdVerifyPostResponseVerifyTaskApiV1RemediationTasksTaskIdVerifyPost.from_dict(
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
    HTTPValidationError
    | VerifyTaskApiV1RemediationTasksTaskIdVerifyPostResponseVerifyTaskApiV1RemediationTasksTaskIdVerifyPost
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
    body: SubmitVerificationRequest,
) -> Response[
    HTTPValidationError
    | VerifyTaskApiV1RemediationTasksTaskIdVerifyPostResponseVerifyTaskApiV1RemediationTasksTaskIdVerifyPost
]:
    """Verify Task

     Verify task (CLI-compatible alias for /tasks/{task_id}/verification).

    Args:
        task_id (str):
        body (SubmitVerificationRequest): Request to submit verification evidence.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | VerifyTaskApiV1RemediationTasksTaskIdVerifyPostResponseVerifyTaskApiV1RemediationTasksTaskIdVerifyPost]
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
    body: SubmitVerificationRequest,
) -> (
    HTTPValidationError
    | VerifyTaskApiV1RemediationTasksTaskIdVerifyPostResponseVerifyTaskApiV1RemediationTasksTaskIdVerifyPost
    | None
):
    """Verify Task

     Verify task (CLI-compatible alias for /tasks/{task_id}/verification).

    Args:
        task_id (str):
        body (SubmitVerificationRequest): Request to submit verification evidence.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | VerifyTaskApiV1RemediationTasksTaskIdVerifyPostResponseVerifyTaskApiV1RemediationTasksTaskIdVerifyPost
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
    body: SubmitVerificationRequest,
) -> Response[
    HTTPValidationError
    | VerifyTaskApiV1RemediationTasksTaskIdVerifyPostResponseVerifyTaskApiV1RemediationTasksTaskIdVerifyPost
]:
    """Verify Task

     Verify task (CLI-compatible alias for /tasks/{task_id}/verification).

    Args:
        task_id (str):
        body (SubmitVerificationRequest): Request to submit verification evidence.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | VerifyTaskApiV1RemediationTasksTaskIdVerifyPostResponseVerifyTaskApiV1RemediationTasksTaskIdVerifyPost]
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
    body: SubmitVerificationRequest,
) -> (
    HTTPValidationError
    | VerifyTaskApiV1RemediationTasksTaskIdVerifyPostResponseVerifyTaskApiV1RemediationTasksTaskIdVerifyPost
    | None
):
    """Verify Task

     Verify task (CLI-compatible alias for /tasks/{task_id}/verification).

    Args:
        task_id (str):
        body (SubmitVerificationRequest): Request to submit verification evidence.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | VerifyTaskApiV1RemediationTasksTaskIdVerifyPostResponseVerifyTaskApiV1RemediationTasksTaskIdVerifyPost
    """

    return (
        await asyncio_detailed(
            task_id=task_id,
            client=client,
            body=body,
        )
    ).parsed
