from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.easm_exposures_api_v1_easm_exposures_get_response_easm_exposures_api_v1_easm_exposures_get import (
    EasmExposuresApiV1EasmExposuresGetResponseEasmExposuresApiV1EasmExposuresGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    confidence: float | Unset = 0.0,
    limit: int | Unset = 100,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    params["confidence"] = confidence

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/easm/exposures",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> EasmExposuresApiV1EasmExposuresGetResponseEasmExposuresApiV1EasmExposuresGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = EasmExposuresApiV1EasmExposuresGetResponseEasmExposuresApiV1EasmExposuresGet.from_dict(
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
) -> Response[EasmExposuresApiV1EasmExposuresGetResponseEasmExposuresApiV1EasmExposuresGet | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    confidence: float | Unset = 0.0,
    limit: int | Unset = 100,
    x_org_id: None | str | Unset = UNSET,
) -> Response[EasmExposuresApiV1EasmExposuresGetResponseEasmExposuresApiV1EasmExposuresGet | HTTPValidationError]:
    """Easm Exposures

     Return exposures filtered by confidence. (Multica 0476b668)

    Args:
        confidence (float | Unset):  Default: 0.0.
        limit (int | Unset):  Default: 100.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EasmExposuresApiV1EasmExposuresGetResponseEasmExposuresApiV1EasmExposuresGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        confidence=confidence,
        limit=limit,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    confidence: float | Unset = 0.0,
    limit: int | Unset = 100,
    x_org_id: None | str | Unset = UNSET,
) -> EasmExposuresApiV1EasmExposuresGetResponseEasmExposuresApiV1EasmExposuresGet | HTTPValidationError | None:
    """Easm Exposures

     Return exposures filtered by confidence. (Multica 0476b668)

    Args:
        confidence (float | Unset):  Default: 0.0.
        limit (int | Unset):  Default: 100.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EasmExposuresApiV1EasmExposuresGetResponseEasmExposuresApiV1EasmExposuresGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        confidence=confidence,
        limit=limit,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    confidence: float | Unset = 0.0,
    limit: int | Unset = 100,
    x_org_id: None | str | Unset = UNSET,
) -> Response[EasmExposuresApiV1EasmExposuresGetResponseEasmExposuresApiV1EasmExposuresGet | HTTPValidationError]:
    """Easm Exposures

     Return exposures filtered by confidence. (Multica 0476b668)

    Args:
        confidence (float | Unset):  Default: 0.0.
        limit (int | Unset):  Default: 100.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EasmExposuresApiV1EasmExposuresGetResponseEasmExposuresApiV1EasmExposuresGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        confidence=confidence,
        limit=limit,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    confidence: float | Unset = 0.0,
    limit: int | Unset = 100,
    x_org_id: None | str | Unset = UNSET,
) -> EasmExposuresApiV1EasmExposuresGetResponseEasmExposuresApiV1EasmExposuresGet | HTTPValidationError | None:
    """Easm Exposures

     Return exposures filtered by confidence. (Multica 0476b668)

    Args:
        confidence (float | Unset):  Default: 0.0.
        limit (int | Unset):  Default: 100.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EasmExposuresApiV1EasmExposuresGetResponseEasmExposuresApiV1EasmExposuresGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            confidence=confidence,
            limit=limit,
            x_org_id=x_org_id,
        )
    ).parsed
