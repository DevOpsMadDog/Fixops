from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.log_activity_api_v1_fail_activity_post_response_log_activity_api_v1_fail_activity_post import (
    LogActivityApiV1FailActivityPostResponseLogActivityApiV1FailActivityPost,
)
from ...models.log_activity_request import LogActivityRequest
from ...types import Response


def _get_kwargs(
    *,
    body: LogActivityRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/fail/activity",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | LogActivityApiV1FailActivityPostResponseLogActivityApiV1FailActivityPost | None:
    if response.status_code == 201:
        response_201 = LogActivityApiV1FailActivityPostResponseLogActivityApiV1FailActivityPost.from_dict(
            response.json()
        )

        return response_201

    if response.status_code == 422:
        response_422 = HTTPValidationError.from_dict(response.json())

        return response_422

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[HTTPValidationError | LogActivityApiV1FailActivityPostResponseLogActivityApiV1FailActivityPost]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: LogActivityRequest,
) -> Response[HTTPValidationError | LogActivityApiV1FailActivityPostResponseLogActivityApiV1FailActivityPost]:
    """Log a security activity for neglect zone tracking

     Log a security activity event for a component.

    This is used to track when components have been scanned, reviewed, or
    drilled, so the neglect zone detector can accurately identify blind spots.

    Activity types: scan, review, drill, pentest, audit

    Args:
        body (LogActivityRequest): Request to log a security activity for neglect zone tracking.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | LogActivityApiV1FailActivityPostResponseLogActivityApiV1FailActivityPost]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: LogActivityRequest,
) -> HTTPValidationError | LogActivityApiV1FailActivityPostResponseLogActivityApiV1FailActivityPost | None:
    """Log a security activity for neglect zone tracking

     Log a security activity event for a component.

    This is used to track when components have been scanned, reviewed, or
    drilled, so the neglect zone detector can accurately identify blind spots.

    Activity types: scan, review, drill, pentest, audit

    Args:
        body (LogActivityRequest): Request to log a security activity for neglect zone tracking.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | LogActivityApiV1FailActivityPostResponseLogActivityApiV1FailActivityPost
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: LogActivityRequest,
) -> Response[HTTPValidationError | LogActivityApiV1FailActivityPostResponseLogActivityApiV1FailActivityPost]:
    """Log a security activity for neglect zone tracking

     Log a security activity event for a component.

    This is used to track when components have been scanned, reviewed, or
    drilled, so the neglect zone detector can accurately identify blind spots.

    Activity types: scan, review, drill, pentest, audit

    Args:
        body (LogActivityRequest): Request to log a security activity for neglect zone tracking.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | LogActivityApiV1FailActivityPostResponseLogActivityApiV1FailActivityPost]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: LogActivityRequest,
) -> HTTPValidationError | LogActivityApiV1FailActivityPostResponseLogActivityApiV1FailActivityPost | None:
    """Log a security activity for neglect zone tracking

     Log a security activity event for a component.

    This is used to track when components have been scanned, reviewed, or
    drilled, so the neglect zone detector can accurately identify blind spots.

    Activity types: scan, review, drill, pentest, audit

    Args:
        body (LogActivityRequest): Request to log a security activity for neglect zone tracking.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | LogActivityApiV1FailActivityPostResponseLogActivityApiV1FailActivityPost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
