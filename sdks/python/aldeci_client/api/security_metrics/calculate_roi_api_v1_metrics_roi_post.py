from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.calculate_roi_api_v1_metrics_roi_post_response_calculate_roi_api_v1_metrics_roi_post import (
    CalculateRoiApiV1MetricsRoiPostResponseCalculateRoiApiV1MetricsRoiPost,
)
from ...models.http_validation_error import HTTPValidationError
from ...models.roi_request import ROIRequest
from ...types import Response


def _get_kwargs(
    *,
    body: ROIRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/metrics/roi",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> CalculateRoiApiV1MetricsRoiPostResponseCalculateRoiApiV1MetricsRoiPost | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = CalculateRoiApiV1MetricsRoiPostResponseCalculateRoiApiV1MetricsRoiPost.from_dict(response.json())

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
) -> Response[CalculateRoiApiV1MetricsRoiPostResponseCalculateRoiApiV1MetricsRoiPost | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: ROIRequest,
) -> Response[CalculateRoiApiV1MetricsRoiPostResponseCalculateRoiApiV1MetricsRoiPost | HTTPValidationError]:
    """Security program ROI calculation

     Calculate security program ROI: cost vs avoided losses using Ponemon/IBM 2024 breach cost data.
    Returns net benefit and payback period.

    Args:
        body (ROIRequest): Request body for ROI calculation.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CalculateRoiApiV1MetricsRoiPostResponseCalculateRoiApiV1MetricsRoiPost | HTTPValidationError]
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
    body: ROIRequest,
) -> CalculateRoiApiV1MetricsRoiPostResponseCalculateRoiApiV1MetricsRoiPost | HTTPValidationError | None:
    """Security program ROI calculation

     Calculate security program ROI: cost vs avoided losses using Ponemon/IBM 2024 breach cost data.
    Returns net benefit and payback period.

    Args:
        body (ROIRequest): Request body for ROI calculation.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CalculateRoiApiV1MetricsRoiPostResponseCalculateRoiApiV1MetricsRoiPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: ROIRequest,
) -> Response[CalculateRoiApiV1MetricsRoiPostResponseCalculateRoiApiV1MetricsRoiPost | HTTPValidationError]:
    """Security program ROI calculation

     Calculate security program ROI: cost vs avoided losses using Ponemon/IBM 2024 breach cost data.
    Returns net benefit and payback period.

    Args:
        body (ROIRequest): Request body for ROI calculation.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CalculateRoiApiV1MetricsRoiPostResponseCalculateRoiApiV1MetricsRoiPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: ROIRequest,
) -> CalculateRoiApiV1MetricsRoiPostResponseCalculateRoiApiV1MetricsRoiPost | HTTPValidationError | None:
    """Security program ROI calculation

     Calculate security program ROI: cost vs avoided losses using Ponemon/IBM 2024 breach cost data.
    Returns net benefit and payback period.

    Args:
        body (ROIRequest): Request body for ROI calculation.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CalculateRoiApiV1MetricsRoiPostResponseCalculateRoiApiV1MetricsRoiPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
