from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.ueba_risk_response import UEBARiskResponse
from ...types import UNSET, Response, Unset


def _get_kwargs(
    user_id: str,
    *,
    org_id: str | Unset = "default",
    window_days: int | Unset = 7,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    params["window_days"] = window_days

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/anomaly-ml/ueba/{user_id}".format(
            user_id=quote(str(user_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | UEBARiskResponse | None:
    if response.status_code == 200:
        response_200 = UEBARiskResponse.from_dict(response.json())

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
) -> Response[HTTPValidationError | UEBARiskResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    user_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    window_days: int | Unset = 7,
) -> Response[HTTPValidationError | UEBARiskResponse]:
    """UEBA composite risk score for a user

     Compute User Entity Behavior Analytics (UEBA) composite risk score (0-100).

    Sub-scores:
    - login_anomaly_score (0-25): login frequency vs baseline
    - access_pattern_score (0-25): API call patterns vs baseline
    - data_volume_score (0-25): data egress vs baseline
    - travel_anomaly_score (0-25): distinct geo_region count (impossible travel)

    Args:
        user_id (str):
        org_id (str | Unset): Organisation ID Default: 'default'.
        window_days (int | Unset): Lookback window Default: 7.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UEBARiskResponse]
    """

    kwargs = _get_kwargs(
        user_id=user_id,
        org_id=org_id,
        window_days=window_days,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    user_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    window_days: int | Unset = 7,
) -> HTTPValidationError | UEBARiskResponse | None:
    """UEBA composite risk score for a user

     Compute User Entity Behavior Analytics (UEBA) composite risk score (0-100).

    Sub-scores:
    - login_anomaly_score (0-25): login frequency vs baseline
    - access_pattern_score (0-25): API call patterns vs baseline
    - data_volume_score (0-25): data egress vs baseline
    - travel_anomaly_score (0-25): distinct geo_region count (impossible travel)

    Args:
        user_id (str):
        org_id (str | Unset): Organisation ID Default: 'default'.
        window_days (int | Unset): Lookback window Default: 7.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UEBARiskResponse
    """

    return sync_detailed(
        user_id=user_id,
        client=client,
        org_id=org_id,
        window_days=window_days,
    ).parsed


async def asyncio_detailed(
    user_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    window_days: int | Unset = 7,
) -> Response[HTTPValidationError | UEBARiskResponse]:
    """UEBA composite risk score for a user

     Compute User Entity Behavior Analytics (UEBA) composite risk score (0-100).

    Sub-scores:
    - login_anomaly_score (0-25): login frequency vs baseline
    - access_pattern_score (0-25): API call patterns vs baseline
    - data_volume_score (0-25): data egress vs baseline
    - travel_anomaly_score (0-25): distinct geo_region count (impossible travel)

    Args:
        user_id (str):
        org_id (str | Unset): Organisation ID Default: 'default'.
        window_days (int | Unset): Lookback window Default: 7.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UEBARiskResponse]
    """

    kwargs = _get_kwargs(
        user_id=user_id,
        org_id=org_id,
        window_days=window_days,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    user_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
    window_days: int | Unset = 7,
) -> HTTPValidationError | UEBARiskResponse | None:
    """UEBA composite risk score for a user

     Compute User Entity Behavior Analytics (UEBA) composite risk score (0-100).

    Sub-scores:
    - login_anomaly_score (0-25): login frequency vs baseline
    - access_pattern_score (0-25): API call patterns vs baseline
    - data_volume_score (0-25): data egress vs baseline
    - travel_anomaly_score (0-25): distinct geo_region count (impossible travel)

    Args:
        user_id (str):
        org_id (str | Unset): Organisation ID Default: 'default'.
        window_days (int | Unset): Lookback window Default: 7.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UEBARiskResponse
    """

    return (
        await asyncio_detailed(
            user_id=user_id,
            client=client,
            org_id=org_id,
            window_days=window_days,
        )
    ).parsed
