from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.isolation_request import IsolationRequest
from ...models.isolation_response import IsolationResponse
from ...types import Response


def _get_kwargs(
    *,
    body: IsolationRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/anomaly-ml/detect/isolation",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | IsolationResponse | None:
    if response.status_code == 200:
        response_200 = IsolationResponse.from_dict(response.json())

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
) -> Response[HTTPValidationError | IsolationResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: IsolationRequest,
) -> Response[HTTPValidationError | IsolationResponse]:
    """Isolation Forest multi-dimensional anomaly scoring

     Score a multi-metric feature vector using a lightweight Isolation Forest.

    Trains on historical data (window_days) and scores the current observation.
    Score > 0.6 is flagged as anomalous. No sklearn required.

    Args:
        body (IsolationRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | IsolationResponse]
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
    body: IsolationRequest,
) -> HTTPValidationError | IsolationResponse | None:
    """Isolation Forest multi-dimensional anomaly scoring

     Score a multi-metric feature vector using a lightweight Isolation Forest.

    Trains on historical data (window_days) and scores the current observation.
    Score > 0.6 is flagged as anomalous. No sklearn required.

    Args:
        body (IsolationRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | IsolationResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: IsolationRequest,
) -> Response[HTTPValidationError | IsolationResponse]:
    """Isolation Forest multi-dimensional anomaly scoring

     Score a multi-metric feature vector using a lightweight Isolation Forest.

    Trains on historical data (window_days) and scores the current observation.
    Score > 0.6 is flagged as anomalous. No sklearn required.

    Args:
        body (IsolationRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | IsolationResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: IsolationRequest,
) -> HTTPValidationError | IsolationResponse | None:
    """Isolation Forest multi-dimensional anomaly scoring

     Score a multi-metric feature vector using a lightweight Isolation Forest.

    Trains on historical data (window_days) and scores the current observation.
    Score > 0.6 is flagged as anomalous. No sklearn required.

    Args:
        body (IsolationRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | IsolationResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
