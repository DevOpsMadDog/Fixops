from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.ai_exposure_shadow_api_v1_ai_exposure_shadow_get_response_ai_exposure_shadow_api_v1_ai_exposure_shadow_get import (
    AiExposureShadowApiV1AiExposureShadowGetResponseAiExposureShadowApiV1AiExposureShadowGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    flag_unregistered: bool | Unset = True,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    params["flag_unregistered"] = flag_unregistered

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/ai-exposure/shadow",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    AiExposureShadowApiV1AiExposureShadowGetResponseAiExposureShadowApiV1AiExposureShadowGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = (
            AiExposureShadowApiV1AiExposureShadowGetResponseAiExposureShadowApiV1AiExposureShadowGet.from_dict(
                response.json()
            )
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
    AiExposureShadowApiV1AiExposureShadowGetResponseAiExposureShadowApiV1AiExposureShadowGet | HTTPValidationError
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
    flag_unregistered: bool | Unset = True,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    AiExposureShadowApiV1AiExposureShadowGetResponseAiExposureShadowApiV1AiExposureShadowGet | HTTPValidationError
]:
    """Ai Exposure Shadow

     List discovered shadow AI services. (Multica 3e63ac8d)

    Args:
        flag_unregistered (bool | Unset):  Default: True.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AiExposureShadowApiV1AiExposureShadowGetResponseAiExposureShadowApiV1AiExposureShadowGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        flag_unregistered=flag_unregistered,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    flag_unregistered: bool | Unset = True,
    x_org_id: None | str | Unset = UNSET,
) -> (
    AiExposureShadowApiV1AiExposureShadowGetResponseAiExposureShadowApiV1AiExposureShadowGet
    | HTTPValidationError
    | None
):
    """Ai Exposure Shadow

     List discovered shadow AI services. (Multica 3e63ac8d)

    Args:
        flag_unregistered (bool | Unset):  Default: True.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AiExposureShadowApiV1AiExposureShadowGetResponseAiExposureShadowApiV1AiExposureShadowGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        flag_unregistered=flag_unregistered,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    flag_unregistered: bool | Unset = True,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    AiExposureShadowApiV1AiExposureShadowGetResponseAiExposureShadowApiV1AiExposureShadowGet | HTTPValidationError
]:
    """Ai Exposure Shadow

     List discovered shadow AI services. (Multica 3e63ac8d)

    Args:
        flag_unregistered (bool | Unset):  Default: True.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AiExposureShadowApiV1AiExposureShadowGetResponseAiExposureShadowApiV1AiExposureShadowGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        flag_unregistered=flag_unregistered,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    flag_unregistered: bool | Unset = True,
    x_org_id: None | str | Unset = UNSET,
) -> (
    AiExposureShadowApiV1AiExposureShadowGetResponseAiExposureShadowApiV1AiExposureShadowGet
    | HTTPValidationError
    | None
):
    """Ai Exposure Shadow

     List discovered shadow AI services. (Multica 3e63ac8d)

    Args:
        flag_unregistered (bool | Unset):  Default: True.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AiExposureShadowApiV1AiExposureShadowGetResponseAiExposureShadowApiV1AiExposureShadowGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            flag_unregistered=flag_unregistered,
            x_org_id=x_org_id,
        )
    ).parsed
