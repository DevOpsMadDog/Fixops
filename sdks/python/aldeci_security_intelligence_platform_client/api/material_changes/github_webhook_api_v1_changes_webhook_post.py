from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.webhook_response import WebhookResponse
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
        "url": "/api/v1/changes/webhook",
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | WebhookResponse | None:
    if response.status_code == 200:
        response_200 = WebhookResponse.from_dict(response.json())

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
) -> Response[HTTPValidationError | WebhookResponse]:
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
) -> Response[HTTPValidationError | WebhookResponse]:
    """Github Webhook

     Handle GitHub push-event webhooks.

    Validates the HMAC signature (if GITHUB_WEBHOOK_SECRET is set), then
    analyses the diff for the head commit and returns the classification.

    GitHub sends a ``push`` event with a JSON payload containing ``commits``
    and ``head_commit`` fields.

    Security hardening applied:
    - Rate limiting: 10 requests/minute per IP
    - Payload size limit: 1 MB
    - SSRF validation on any URLs in the payload

    Args:
        x_github_event (None | str | Unset):
        x_hub_signature_256 (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | WebhookResponse]
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
) -> HTTPValidationError | WebhookResponse | None:
    """Github Webhook

     Handle GitHub push-event webhooks.

    Validates the HMAC signature (if GITHUB_WEBHOOK_SECRET is set), then
    analyses the diff for the head commit and returns the classification.

    GitHub sends a ``push`` event with a JSON payload containing ``commits``
    and ``head_commit`` fields.

    Security hardening applied:
    - Rate limiting: 10 requests/minute per IP
    - Payload size limit: 1 MB
    - SSRF validation on any URLs in the payload

    Args:
        x_github_event (None | str | Unset):
        x_hub_signature_256 (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | WebhookResponse
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
) -> Response[HTTPValidationError | WebhookResponse]:
    """Github Webhook

     Handle GitHub push-event webhooks.

    Validates the HMAC signature (if GITHUB_WEBHOOK_SECRET is set), then
    analyses the diff for the head commit and returns the classification.

    GitHub sends a ``push`` event with a JSON payload containing ``commits``
    and ``head_commit`` fields.

    Security hardening applied:
    - Rate limiting: 10 requests/minute per IP
    - Payload size limit: 1 MB
    - SSRF validation on any URLs in the payload

    Args:
        x_github_event (None | str | Unset):
        x_hub_signature_256 (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | WebhookResponse]
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
) -> HTTPValidationError | WebhookResponse | None:
    """Github Webhook

     Handle GitHub push-event webhooks.

    Validates the HMAC signature (if GITHUB_WEBHOOK_SECRET is set), then
    analyses the diff for the head commit and returns the classification.

    GitHub sends a ``push`` event with a JSON payload containing ``commits``
    and ``head_commit`` fields.

    Security hardening applied:
    - Rate limiting: 10 requests/minute per IP
    - Payload size limit: 1 MB
    - SSRF validation on any URLs in the payload

    Args:
        x_github_event (None | str | Unset):
        x_hub_signature_256 (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | WebhookResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            x_github_event=x_github_event,
            x_hub_signature_256=x_hub_signature_256,
        )
    ).parsed
