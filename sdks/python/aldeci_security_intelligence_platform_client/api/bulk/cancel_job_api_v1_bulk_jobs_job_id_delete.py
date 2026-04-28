from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.cancel_job_api_v1_bulk_jobs_job_id_delete_response_cancel_job_api_v1_bulk_jobs_job_id_delete import (
    CancelJobApiV1BulkJobsJobIdDeleteResponseCancelJobApiV1BulkJobsJobIdDelete,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    job_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/api/v1/bulk/jobs/{job_id}".format(
            job_id=quote(str(job_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> CancelJobApiV1BulkJobsJobIdDeleteResponseCancelJobApiV1BulkJobsJobIdDelete | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = CancelJobApiV1BulkJobsJobIdDeleteResponseCancelJobApiV1BulkJobsJobIdDelete.from_dict(
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
) -> Response[CancelJobApiV1BulkJobsJobIdDeleteResponseCancelJobApiV1BulkJobsJobIdDelete | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    job_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[CancelJobApiV1BulkJobsJobIdDeleteResponseCancelJobApiV1BulkJobsJobIdDelete | HTTPValidationError]:
    """Cancel Job

     Cancel a pending or in-progress job.

    Args:
        job_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CancelJobApiV1BulkJobsJobIdDeleteResponseCancelJobApiV1BulkJobsJobIdDelete | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        job_id=job_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    job_id: str,
    *,
    client: AuthenticatedClient,
) -> CancelJobApiV1BulkJobsJobIdDeleteResponseCancelJobApiV1BulkJobsJobIdDelete | HTTPValidationError | None:
    """Cancel Job

     Cancel a pending or in-progress job.

    Args:
        job_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CancelJobApiV1BulkJobsJobIdDeleteResponseCancelJobApiV1BulkJobsJobIdDelete | HTTPValidationError
    """

    return sync_detailed(
        job_id=job_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    job_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[CancelJobApiV1BulkJobsJobIdDeleteResponseCancelJobApiV1BulkJobsJobIdDelete | HTTPValidationError]:
    """Cancel Job

     Cancel a pending or in-progress job.

    Args:
        job_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CancelJobApiV1BulkJobsJobIdDeleteResponseCancelJobApiV1BulkJobsJobIdDelete | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        job_id=job_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    job_id: str,
    *,
    client: AuthenticatedClient,
) -> CancelJobApiV1BulkJobsJobIdDeleteResponseCancelJobApiV1BulkJobsJobIdDelete | HTTPValidationError | None:
    """Cancel Job

     Cancel a pending or in-progress job.

    Args:
        job_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CancelJobApiV1BulkJobsJobIdDeleteResponseCancelJobApiV1BulkJobsJobIdDelete | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            job_id=job_id,
            client=client,
        )
    ).parsed
