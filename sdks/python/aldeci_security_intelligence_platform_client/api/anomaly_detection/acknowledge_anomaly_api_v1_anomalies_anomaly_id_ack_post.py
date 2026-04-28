from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.ack_response import AckResponse
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    anomaly_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/anomalies/{anomaly_id}/ack".format(
            anomaly_id=quote(str(anomaly_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> AckResponse | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = AckResponse.from_dict(response.json())

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
) -> Response[AckResponse | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    anomaly_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[AckResponse | HTTPValidationError]:
    """Acknowledge an anomaly

     Mark an anomaly as reviewed.

    Returns 404 if the anomaly does not exist or was already acknowledged.

    Args:
        anomaly_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AckResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        anomaly_id=anomaly_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    anomaly_id: str,
    *,
    client: AuthenticatedClient,
) -> AckResponse | HTTPValidationError | None:
    """Acknowledge an anomaly

     Mark an anomaly as reviewed.

    Returns 404 if the anomaly does not exist or was already acknowledged.

    Args:
        anomaly_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AckResponse | HTTPValidationError
    """

    return sync_detailed(
        anomaly_id=anomaly_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    anomaly_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[AckResponse | HTTPValidationError]:
    """Acknowledge an anomaly

     Mark an anomaly as reviewed.

    Returns 404 if the anomaly does not exist or was already acknowledged.

    Args:
        anomaly_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AckResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        anomaly_id=anomaly_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    anomaly_id: str,
    *,
    client: AuthenticatedClient,
) -> AckResponse | HTTPValidationError | None:
    """Acknowledge an anomaly

     Mark an anomaly as reviewed.

    Returns 404 if the anomaly does not exist or was already acknowledged.

    Args:
        anomaly_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AckResponse | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            anomaly_id=anomaly_id,
            client=client,
        )
    ).parsed
