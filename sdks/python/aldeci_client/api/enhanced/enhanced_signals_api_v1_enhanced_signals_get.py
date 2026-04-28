from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enhanced_signals_api_v1_enhanced_signals_get_response_enhanced_signals_api_v1_enhanced_signals_get import (
    EnhancedSignalsApiV1EnhancedSignalsGetResponseEnhancedSignalsApiV1EnhancedSignalsGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    verdict: str | Unset = "allow",
    confidence: float | Unset = 0.9,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["verdict"] = verdict

    params["confidence"] = confidence

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/enhanced/signals",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> EnhancedSignalsApiV1EnhancedSignalsGetResponseEnhancedSignalsApiV1EnhancedSignalsGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = EnhancedSignalsApiV1EnhancedSignalsGetResponseEnhancedSignalsApiV1EnhancedSignalsGet.from_dict(
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
    EnhancedSignalsApiV1EnhancedSignalsGetResponseEnhancedSignalsApiV1EnhancedSignalsGet | HTTPValidationError
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
    verdict: str | Unset = "allow",
    confidence: float | Unset = 0.9,
) -> Response[
    EnhancedSignalsApiV1EnhancedSignalsGetResponseEnhancedSignalsApiV1EnhancedSignalsGet | HTTPValidationError
]:
    """Enhanced Signals

     Return the latest feed badges and SSVC label for the enhanced engine.

    Args:
        verdict (str | Unset):  Default: 'allow'.
        confidence (float | Unset):  Default: 0.9.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EnhancedSignalsApiV1EnhancedSignalsGetResponseEnhancedSignalsApiV1EnhancedSignalsGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        verdict=verdict,
        confidence=confidence,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    verdict: str | Unset = "allow",
    confidence: float | Unset = 0.9,
) -> EnhancedSignalsApiV1EnhancedSignalsGetResponseEnhancedSignalsApiV1EnhancedSignalsGet | HTTPValidationError | None:
    """Enhanced Signals

     Return the latest feed badges and SSVC label for the enhanced engine.

    Args:
        verdict (str | Unset):  Default: 'allow'.
        confidence (float | Unset):  Default: 0.9.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EnhancedSignalsApiV1EnhancedSignalsGetResponseEnhancedSignalsApiV1EnhancedSignalsGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        verdict=verdict,
        confidence=confidence,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    verdict: str | Unset = "allow",
    confidence: float | Unset = 0.9,
) -> Response[
    EnhancedSignalsApiV1EnhancedSignalsGetResponseEnhancedSignalsApiV1EnhancedSignalsGet | HTTPValidationError
]:
    """Enhanced Signals

     Return the latest feed badges and SSVC label for the enhanced engine.

    Args:
        verdict (str | Unset):  Default: 'allow'.
        confidence (float | Unset):  Default: 0.9.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EnhancedSignalsApiV1EnhancedSignalsGetResponseEnhancedSignalsApiV1EnhancedSignalsGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        verdict=verdict,
        confidence=confidence,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    verdict: str | Unset = "allow",
    confidence: float | Unset = 0.9,
) -> EnhancedSignalsApiV1EnhancedSignalsGetResponseEnhancedSignalsApiV1EnhancedSignalsGet | HTTPValidationError | None:
    """Enhanced Signals

     Return the latest feed badges and SSVC label for the enhanced engine.

    Args:
        verdict (str | Unset):  Default: 'allow'.
        confidence (float | Unset):  Default: 0.9.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EnhancedSignalsApiV1EnhancedSignalsGetResponseEnhancedSignalsApiV1EnhancedSignalsGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            verdict=verdict,
            confidence=confidence,
        )
    ).parsed
