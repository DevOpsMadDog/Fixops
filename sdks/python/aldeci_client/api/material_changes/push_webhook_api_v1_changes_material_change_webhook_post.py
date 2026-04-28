from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.material_change_response import MaterialChangeResponse
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    x_github_event: None | str | Unset = UNSET,
    x_hub_signature_256: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_github_event, Unset):
        headers["x-github-event"] = x_github_event

    if not isinstance(x_hub_signature_256, Unset):
        headers["x-hub-signature-256"] = x_hub_signature_256

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/changes/material-change/webhook",
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | MaterialChangeResponse | None:
    if response.status_code == 200:
        response_200 = MaterialChangeResponse.from_dict(response.json())

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
) -> Response[HTTPValidationError | MaterialChangeResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    x_github_event: None | str | Unset = UNSET,
    x_hub_signature_256: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | MaterialChangeResponse]:
    """Receive GitHub push webhook → SAST → LLM Council → incident

     Accept a GitHub push webhook, run SAST on changed files, assess materiality,
    and open an incident if the change is security-material.

    Security:
    - HMAC-SHA256 verified when GITHUB_WEBHOOK_SECRET is set
    - Rate-limited: 10 requests/minute per IP
    - Payload capped at 1 MB

    Args:
        x_github_event (None | str | Unset):
        x_hub_signature_256 (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | MaterialChangeResponse]
    """

    kwargs = _get_kwargs(
        x_github_event=x_github_event,
        x_hub_signature_256=x_hub_signature_256,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    x_github_event: None | str | Unset = UNSET,
    x_hub_signature_256: None | str | Unset = UNSET,
) -> HTTPValidationError | MaterialChangeResponse | None:
    """Receive GitHub push webhook → SAST → LLM Council → incident

     Accept a GitHub push webhook, run SAST on changed files, assess materiality,
    and open an incident if the change is security-material.

    Security:
    - HMAC-SHA256 verified when GITHUB_WEBHOOK_SECRET is set
    - Rate-limited: 10 requests/minute per IP
    - Payload capped at 1 MB

    Args:
        x_github_event (None | str | Unset):
        x_hub_signature_256 (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | MaterialChangeResponse
    """

    return sync_detailed(
        client=client,
        x_github_event=x_github_event,
        x_hub_signature_256=x_hub_signature_256,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    x_github_event: None | str | Unset = UNSET,
    x_hub_signature_256: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | MaterialChangeResponse]:
    """Receive GitHub push webhook → SAST → LLM Council → incident

     Accept a GitHub push webhook, run SAST on changed files, assess materiality,
    and open an incident if the change is security-material.

    Security:
    - HMAC-SHA256 verified when GITHUB_WEBHOOK_SECRET is set
    - Rate-limited: 10 requests/minute per IP
    - Payload capped at 1 MB

    Args:
        x_github_event (None | str | Unset):
        x_hub_signature_256 (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | MaterialChangeResponse]
    """

    kwargs = _get_kwargs(
        x_github_event=x_github_event,
        x_hub_signature_256=x_hub_signature_256,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    x_github_event: None | str | Unset = UNSET,
    x_hub_signature_256: None | str | Unset = UNSET,
) -> HTTPValidationError | MaterialChangeResponse | None:
    """Receive GitHub push webhook → SAST → LLM Council → incident

     Accept a GitHub push webhook, run SAST on changed files, assess materiality,
    and open an incident if the change is security-material.

    Security:
    - HMAC-SHA256 verified when GITHUB_WEBHOOK_SECRET is set
    - Rate-limited: 10 requests/minute per IP
    - Payload capped at 1 MB

    Args:
        x_github_event (None | str | Unset):
        x_hub_signature_256 (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | MaterialChangeResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            x_github_event=x_github_event,
            x_hub_signature_256=x_hub_signature_256,
        )
    ).parsed
