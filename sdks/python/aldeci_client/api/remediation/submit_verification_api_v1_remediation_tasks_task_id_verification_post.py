from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.submit_verification_api_v1_remediation_tasks_task_id_verification_post_response_submit_verification_api_v1_remediation_tasks_task_id_verification_post import (
    SubmitVerificationApiV1RemediationTasksTaskIdVerificationPostResponseSubmitVerificationApiV1RemediationTasksTaskIdVerificationPost,
)
from ...models.submit_verification_request import SubmitVerificationRequest
from ...types import Response


def _get_kwargs(
    task_id: str,
    *,
    body: SubmitVerificationRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/remediation/tasks/{task_id}/verification".format(
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
    | SubmitVerificationApiV1RemediationTasksTaskIdVerificationPostResponseSubmitVerificationApiV1RemediationTasksTaskIdVerificationPost
    | None
):
    if response.status_code == 200:
        response_200 = SubmitVerificationApiV1RemediationTasksTaskIdVerificationPostResponseSubmitVerificationApiV1RemediationTasksTaskIdVerificationPost.from_dict(
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
    | SubmitVerificationApiV1RemediationTasksTaskIdVerificationPostResponseSubmitVerificationApiV1RemediationTasksTaskIdVerificationPost
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
    | SubmitVerificationApiV1RemediationTasksTaskIdVerificationPostResponseSubmitVerificationApiV1RemediationTasksTaskIdVerificationPost
]:
    """Submit Verification

     Submit verification evidence for a task.

    Args:
        task_id (str):
        body (SubmitVerificationRequest): Request to submit verification evidence.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | SubmitVerificationApiV1RemediationTasksTaskIdVerificationPostResponseSubmitVerificationApiV1RemediationTasksTaskIdVerificationPost]
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
    | SubmitVerificationApiV1RemediationTasksTaskIdVerificationPostResponseSubmitVerificationApiV1RemediationTasksTaskIdVerificationPost
    | None
):
    """Submit Verification

     Submit verification evidence for a task.

    Args:
        task_id (str):
        body (SubmitVerificationRequest): Request to submit verification evidence.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | SubmitVerificationApiV1RemediationTasksTaskIdVerificationPostResponseSubmitVerificationApiV1RemediationTasksTaskIdVerificationPost
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
    | SubmitVerificationApiV1RemediationTasksTaskIdVerificationPostResponseSubmitVerificationApiV1RemediationTasksTaskIdVerificationPost
]:
    """Submit Verification

     Submit verification evidence for a task.

    Args:
        task_id (str):
        body (SubmitVerificationRequest): Request to submit verification evidence.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | SubmitVerificationApiV1RemediationTasksTaskIdVerificationPostResponseSubmitVerificationApiV1RemediationTasksTaskIdVerificationPost]
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
    | SubmitVerificationApiV1RemediationTasksTaskIdVerificationPostResponseSubmitVerificationApiV1RemediationTasksTaskIdVerificationPost
    | None
):
    """Submit Verification

     Submit verification evidence for a task.

    Args:
        task_id (str):
        body (SubmitVerificationRequest): Request to submit verification evidence.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | SubmitVerificationApiV1RemediationTasksTaskIdVerificationPostResponseSubmitVerificationApiV1RemediationTasksTaskIdVerificationPost
    """

    return (
        await asyncio_detailed(
            task_id=task_id,
            client=client,
            body=body,
        )
    ).parsed
