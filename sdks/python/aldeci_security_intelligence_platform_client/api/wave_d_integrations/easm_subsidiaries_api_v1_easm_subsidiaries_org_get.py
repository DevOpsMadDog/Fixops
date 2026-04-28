from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.easm_subsidiaries_api_v1_easm_subsidiaries_org_get_response_easm_subsidiaries_api_v1_easm_subsidiaries_org_get import (
    EasmSubsidiariesApiV1EasmSubsidiariesOrgGetResponseEasmSubsidiariesApiV1EasmSubsidiariesOrgGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    org: str,
    *,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/easm/subsidiaries/{org}".format(
            org=quote(str(org), safe=""),
        ),
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    EasmSubsidiariesApiV1EasmSubsidiariesOrgGetResponseEasmSubsidiariesApiV1EasmSubsidiariesOrgGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = (
            EasmSubsidiariesApiV1EasmSubsidiariesOrgGetResponseEasmSubsidiariesApiV1EasmSubsidiariesOrgGet.from_dict(
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
    EasmSubsidiariesApiV1EasmSubsidiariesOrgGetResponseEasmSubsidiariesApiV1EasmSubsidiariesOrgGet | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    org: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    EasmSubsidiariesApiV1EasmSubsidiariesOrgGetResponseEasmSubsidiariesApiV1EasmSubsidiariesOrgGet | HTTPValidationError
]:
    """Easm Subsidiaries

     List discovered subsidiaries for an org. (Multica 828b955d)

    Args:
        org (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EasmSubsidiariesApiV1EasmSubsidiariesOrgGetResponseEasmSubsidiariesApiV1EasmSubsidiariesOrgGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org=org,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    org: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> (
    EasmSubsidiariesApiV1EasmSubsidiariesOrgGetResponseEasmSubsidiariesApiV1EasmSubsidiariesOrgGet
    | HTTPValidationError
    | None
):
    """Easm Subsidiaries

     List discovered subsidiaries for an org. (Multica 828b955d)

    Args:
        org (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EasmSubsidiariesApiV1EasmSubsidiariesOrgGetResponseEasmSubsidiariesApiV1EasmSubsidiariesOrgGet | HTTPValidationError
    """

    return sync_detailed(
        org=org,
        client=client,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    org: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    EasmSubsidiariesApiV1EasmSubsidiariesOrgGetResponseEasmSubsidiariesApiV1EasmSubsidiariesOrgGet | HTTPValidationError
]:
    """Easm Subsidiaries

     List discovered subsidiaries for an org. (Multica 828b955d)

    Args:
        org (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[EasmSubsidiariesApiV1EasmSubsidiariesOrgGetResponseEasmSubsidiariesApiV1EasmSubsidiariesOrgGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org=org,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    org: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> (
    EasmSubsidiariesApiV1EasmSubsidiariesOrgGetResponseEasmSubsidiariesApiV1EasmSubsidiariesOrgGet
    | HTTPValidationError
    | None
):
    """Easm Subsidiaries

     List discovered subsidiaries for an org. (Multica 828b955d)

    Args:
        org (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        EasmSubsidiariesApiV1EasmSubsidiariesOrgGetResponseEasmSubsidiariesApiV1EasmSubsidiariesOrgGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            org=org,
            client=client,
            x_org_id=x_org_id,
        )
    ).parsed
