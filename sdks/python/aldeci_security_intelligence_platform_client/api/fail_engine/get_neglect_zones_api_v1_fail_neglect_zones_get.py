from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_neglect_zones_api_v1_fail_neglect_zones_get_response_get_neglect_zones_api_v1_fail_neglect_zones_get import (
    GetNeglectZonesApiV1FailNeglectZonesGetResponseGetNeglectZonesApiV1FailNeglectZonesGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    threshold_days: int | Unset = 90,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    params["threshold_days"] = threshold_days

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/fail/neglect-zones",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetNeglectZonesApiV1FailNeglectZonesGetResponseGetNeglectZonesApiV1FailNeglectZonesGet | HTTPValidationError | None
):
    if response.status_code == 200:
        response_200 = GetNeglectZonesApiV1FailNeglectZonesGetResponseGetNeglectZonesApiV1FailNeglectZonesGet.from_dict(
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
    GetNeglectZonesApiV1FailNeglectZonesGetResponseGetNeglectZonesApiV1FailNeglectZonesGet | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    threshold_days: int | Unset = 90,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GetNeglectZonesApiV1FailNeglectZonesGetResponseGetNeglectZonesApiV1FailNeglectZonesGet | HTTPValidationError
]:
    """Components with no recent security activity

     Return all components that have had no security activity (scan, review, drill)
    within the threshold period.

    Risk amplification rules:
    - Component inactive 90+ days → flagged
    - Component inactive + holds critical data → **urgent**
    - Each neglect zone includes a suggested drill scenario

    Use this to proactively target under-tested components for FAIL drills.

    Args:
        threshold_days (int | Unset): Days of inactivity to flag as neglected Default: 90.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetNeglectZonesApiV1FailNeglectZonesGetResponseGetNeglectZonesApiV1FailNeglectZonesGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        threshold_days=threshold_days,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    threshold_days: int | Unset = 90,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GetNeglectZonesApiV1FailNeglectZonesGetResponseGetNeglectZonesApiV1FailNeglectZonesGet | HTTPValidationError | None
):
    """Components with no recent security activity

     Return all components that have had no security activity (scan, review, drill)
    within the threshold period.

    Risk amplification rules:
    - Component inactive 90+ days → flagged
    - Component inactive + holds critical data → **urgent**
    - Each neglect zone includes a suggested drill scenario

    Use this to proactively target under-tested components for FAIL drills.

    Args:
        threshold_days (int | Unset): Days of inactivity to flag as neglected Default: 90.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetNeglectZonesApiV1FailNeglectZonesGetResponseGetNeglectZonesApiV1FailNeglectZonesGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        threshold_days=threshold_days,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    threshold_days: int | Unset = 90,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GetNeglectZonesApiV1FailNeglectZonesGetResponseGetNeglectZonesApiV1FailNeglectZonesGet | HTTPValidationError
]:
    """Components with no recent security activity

     Return all components that have had no security activity (scan, review, drill)
    within the threshold period.

    Risk amplification rules:
    - Component inactive 90+ days → flagged
    - Component inactive + holds critical data → **urgent**
    - Each neglect zone includes a suggested drill scenario

    Use this to proactively target under-tested components for FAIL drills.

    Args:
        threshold_days (int | Unset): Days of inactivity to flag as neglected Default: 90.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetNeglectZonesApiV1FailNeglectZonesGetResponseGetNeglectZonesApiV1FailNeglectZonesGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        threshold_days=threshold_days,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    threshold_days: int | Unset = 90,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GetNeglectZonesApiV1FailNeglectZonesGetResponseGetNeglectZonesApiV1FailNeglectZonesGet | HTTPValidationError | None
):
    """Components with no recent security activity

     Return all components that have had no security activity (scan, review, drill)
    within the threshold period.

    Risk amplification rules:
    - Component inactive 90+ days → flagged
    - Component inactive + holds critical data → **urgent**
    - Each neglect zone includes a suggested drill scenario

    Use this to proactively target under-tested components for FAIL drills.

    Args:
        threshold_days (int | Unset): Days of inactivity to flag as neglected Default: 90.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetNeglectZonesApiV1FailNeglectZonesGetResponseGetNeglectZonesApiV1FailNeglectZonesGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            threshold_days=threshold_days,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
