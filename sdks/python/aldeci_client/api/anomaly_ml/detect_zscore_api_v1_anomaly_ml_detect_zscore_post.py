from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.z_score_request import ZScoreRequest
from ...models.z_score_response import ZScoreResponse
from ...types import Response


def _get_kwargs(
    *,
    body: ZScoreRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/anomaly-ml/detect/zscore",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | ZScoreResponse | None:
    if response.status_code == 200:
        response_200 = ZScoreResponse.from_dict(response.json())

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
) -> Response[HTTPValidationError | ZScoreResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: ZScoreRequest,
) -> Response[HTTPValidationError | ZScoreResponse]:
    """Z-score anomaly detection against behavioral baseline

     Compute z-score for an observed value against the entity's historical baseline.

    Returns an anomaly if |z| > z_threshold (default 3.0 sigma).
    The baseline is computed from events in the lookback window.

    Args:
        body (ZScoreRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ZScoreResponse]
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
    body: ZScoreRequest,
) -> HTTPValidationError | ZScoreResponse | None:
    """Z-score anomaly detection against behavioral baseline

     Compute z-score for an observed value against the entity's historical baseline.

    Returns an anomaly if |z| > z_threshold (default 3.0 sigma).
    The baseline is computed from events in the lookback window.

    Args:
        body (ZScoreRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ZScoreResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: ZScoreRequest,
) -> Response[HTTPValidationError | ZScoreResponse]:
    """Z-score anomaly detection against behavioral baseline

     Compute z-score for an observed value against the entity's historical baseline.

    Returns an anomaly if |z| > z_threshold (default 3.0 sigma).
    The baseline is computed from events in the lookback window.

    Args:
        body (ZScoreRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ZScoreResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: ZScoreRequest,
) -> HTTPValidationError | ZScoreResponse | None:
    """Z-score anomaly detection against behavioral baseline

     Compute z-score for an observed value against the entity's historical baseline.

    Returns an anomaly if |z| > z_threshold (default 3.0 sigma).
    The baseline is computed from events in the lookback window.

    Args:
        body (ZScoreRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ZScoreResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
