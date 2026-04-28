from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.body_sso_callback_api_v1_auth_sso_provider_callback_get import (
    BodySsoCallbackApiV1AuthSsoProviderCallbackGet,
)
from ...models.callback_response import CallbackResponse
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    provider: str,
    *,
    body: BodySsoCallbackApiV1AuthSsoProviderCallbackGet | Unset = UNSET,
    code: None | str | Unset = UNSET,
    state: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    params: dict[str, Any] = {}

    json_code: None | str | Unset
    if isinstance(code, Unset):
        json_code = UNSET
    else:
        json_code = code
    params["code"] = json_code

    json_state: None | str | Unset
    if isinstance(state, Unset):
        json_state = UNSET
    else:
        json_state = state
    params["state"] = json_state

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/auth/sso/{provider}/callback".format(
            provider=quote(str(provider), safe=""),
        ),
        "params": params,
    }

    if not isinstance(body, Unset):
        _kwargs["data"] = body.to_dict()

    headers["Content-Type"] = "application/x-www-form-urlencoded"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> CallbackResponse | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = CallbackResponse.from_dict(response.json())

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
) -> Response[CallbackResponse | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    provider: str,
    *,
    client: AuthenticatedClient | Client,
    body: BodySsoCallbackApiV1AuthSsoProviderCallbackGet | Unset = UNSET,
    code: None | str | Unset = UNSET,
    state: None | str | Unset = UNSET,
) -> Response[CallbackResponse | HTTPValidationError]:
    """Sso Callback

     Handle IdP callback. Issues an ALDECI JWT on success.

    Args:
        provider (str):
        code (None | str | Unset):
        state (None | str | Unset):
        body (BodySsoCallbackApiV1AuthSsoProviderCallbackGet | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CallbackResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        provider=provider,
        body=body,
        code=code,
        state=state,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    provider: str,
    *,
    client: AuthenticatedClient | Client,
    body: BodySsoCallbackApiV1AuthSsoProviderCallbackGet | Unset = UNSET,
    code: None | str | Unset = UNSET,
    state: None | str | Unset = UNSET,
) -> CallbackResponse | HTTPValidationError | None:
    """Sso Callback

     Handle IdP callback. Issues an ALDECI JWT on success.

    Args:
        provider (str):
        code (None | str | Unset):
        state (None | str | Unset):
        body (BodySsoCallbackApiV1AuthSsoProviderCallbackGet | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CallbackResponse | HTTPValidationError
    """

    return sync_detailed(
        provider=provider,
        client=client,
        body=body,
        code=code,
        state=state,
    ).parsed


async def asyncio_detailed(
    provider: str,
    *,
    client: AuthenticatedClient | Client,
    body: BodySsoCallbackApiV1AuthSsoProviderCallbackGet | Unset = UNSET,
    code: None | str | Unset = UNSET,
    state: None | str | Unset = UNSET,
) -> Response[CallbackResponse | HTTPValidationError]:
    """Sso Callback

     Handle IdP callback. Issues an ALDECI JWT on success.

    Args:
        provider (str):
        code (None | str | Unset):
        state (None | str | Unset):
        body (BodySsoCallbackApiV1AuthSsoProviderCallbackGet | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CallbackResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        provider=provider,
        body=body,
        code=code,
        state=state,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    provider: str,
    *,
    client: AuthenticatedClient | Client,
    body: BodySsoCallbackApiV1AuthSsoProviderCallbackGet | Unset = UNSET,
    code: None | str | Unset = UNSET,
    state: None | str | Unset = UNSET,
) -> CallbackResponse | HTTPValidationError | None:
    """Sso Callback

     Handle IdP callback. Issues an ALDECI JWT on success.

    Args:
        provider (str):
        code (None | str | Unset):
        state (None | str | Unset):
        body (BodySsoCallbackApiV1AuthSsoProviderCallbackGet | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CallbackResponse | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            provider=provider,
            client=client,
            body=body,
            code=code,
            state=state,
        )
    ).parsed
