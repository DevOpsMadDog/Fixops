from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.mark_triaged_api_v1_fail_drills_drill_id_triage_post_response_mark_triaged_api_v1_fail_drills_drill_id_triage_post import (
    MarkTriagedApiV1FailDrillsDrillIdTriagePostResponseMarkTriagedApiV1FailDrillsDrillIdTriagePost,
)
from ...models.triage_request import TriageRequest
from ...types import Response


def _get_kwargs(
    drill_id: str,
    *,
    body: TriageRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/fail/drills/{drill_id}/triage".format(
            drill_id=quote(str(drill_id), safe=""),
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
    | MarkTriagedApiV1FailDrillsDrillIdTriagePostResponseMarkTriagedApiV1FailDrillsDrillIdTriagePost
    | None
):
    if response.status_code == 200:
        response_200 = (
            MarkTriagedApiV1FailDrillsDrillIdTriagePostResponseMarkTriagedApiV1FailDrillsDrillIdTriagePost.from_dict(
                response.json()
            )
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
    HTTPValidationError | MarkTriagedApiV1FailDrillsDrillIdTriagePostResponseMarkTriagedApiV1FailDrillsDrillIdTriagePost
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    drill_id: str,
    *,
    client: AuthenticatedClient,
    body: TriageRequest,
) -> Response[
    HTTPValidationError | MarkTriagedApiV1FailDrillsDrillIdTriagePostResponseMarkTriagedApiV1FailDrillsDrillIdTriagePost
]:
    """Mark drill finding as triaged

     Record the triage outcome: classification, escalation, and teams notified.
    This is used by the scorer to assess triage accuracy and communication quality.

    Args:
        drill_id (str):
        body (TriageRequest): Request to mark a drill finding as triaged.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | MarkTriagedApiV1FailDrillsDrillIdTriagePostResponseMarkTriagedApiV1FailDrillsDrillIdTriagePost]
    """

    kwargs = _get_kwargs(
        drill_id=drill_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    drill_id: str,
    *,
    client: AuthenticatedClient,
    body: TriageRequest,
) -> (
    HTTPValidationError
    | MarkTriagedApiV1FailDrillsDrillIdTriagePostResponseMarkTriagedApiV1FailDrillsDrillIdTriagePost
    | None
):
    """Mark drill finding as triaged

     Record the triage outcome: classification, escalation, and teams notified.
    This is used by the scorer to assess triage accuracy and communication quality.

    Args:
        drill_id (str):
        body (TriageRequest): Request to mark a drill finding as triaged.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | MarkTriagedApiV1FailDrillsDrillIdTriagePostResponseMarkTriagedApiV1FailDrillsDrillIdTriagePost
    """

    return sync_detailed(
        drill_id=drill_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    drill_id: str,
    *,
    client: AuthenticatedClient,
    body: TriageRequest,
) -> Response[
    HTTPValidationError | MarkTriagedApiV1FailDrillsDrillIdTriagePostResponseMarkTriagedApiV1FailDrillsDrillIdTriagePost
]:
    """Mark drill finding as triaged

     Record the triage outcome: classification, escalation, and teams notified.
    This is used by the scorer to assess triage accuracy and communication quality.

    Args:
        drill_id (str):
        body (TriageRequest): Request to mark a drill finding as triaged.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | MarkTriagedApiV1FailDrillsDrillIdTriagePostResponseMarkTriagedApiV1FailDrillsDrillIdTriagePost]
    """

    kwargs = _get_kwargs(
        drill_id=drill_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    drill_id: str,
    *,
    client: AuthenticatedClient,
    body: TriageRequest,
) -> (
    HTTPValidationError
    | MarkTriagedApiV1FailDrillsDrillIdTriagePostResponseMarkTriagedApiV1FailDrillsDrillIdTriagePost
    | None
):
    """Mark drill finding as triaged

     Record the triage outcome: classification, escalation, and teams notified.
    This is used by the scorer to assess triage accuracy and communication quality.

    Args:
        drill_id (str):
        body (TriageRequest): Request to mark a drill finding as triaged.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | MarkTriagedApiV1FailDrillsDrillIdTriagePostResponseMarkTriagedApiV1FailDrillsDrillIdTriagePost
    """

    return (
        await asyncio_detailed(
            drill_id=drill_id,
            client=client,
            body=body,
        )
    ).parsed
