from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.list_exposure_cases_api_v1_correlations_exposure_cases_get_response_list_exposure_cases_api_v1_correlations_exposure_cases_get import (
    ListExposureCasesApiV1CorrelationsExposureCasesGetResponseListExposureCasesApiV1CorrelationsExposureCasesGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    org_id: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    json_status: None | str | Unset
    if isinstance(status, Unset):
        json_status = UNSET
    else:
        json_status = status
    params["status"] = json_status

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/correlations/exposure-cases",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | ListExposureCasesApiV1CorrelationsExposureCasesGetResponseListExposureCasesApiV1CorrelationsExposureCasesGet
    | None
):
    if response.status_code == 200:
        response_200 = ListExposureCasesApiV1CorrelationsExposureCasesGetResponseListExposureCasesApiV1CorrelationsExposureCasesGet.from_dict(
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
    HTTPValidationError
    | ListExposureCasesApiV1CorrelationsExposureCasesGetResponseListExposureCasesApiV1CorrelationsExposureCasesGet
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
    org_id: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError
    | ListExposureCasesApiV1CorrelationsExposureCasesGetResponseListExposureCasesApiV1CorrelationsExposureCasesGet
]:
    """List Exposure Cases

     List persisted Exposure Cases with optional filters.

    Args:
        org_id (None | str | Unset): Filter by org
        status (None | str | Unset): Filter by status: open | investigating | resolved

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListExposureCasesApiV1CorrelationsExposureCasesGetResponseListExposureCasesApiV1CorrelationsExposureCasesGet]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        status=status,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | ListExposureCasesApiV1CorrelationsExposureCasesGetResponseListExposureCasesApiV1CorrelationsExposureCasesGet
    | None
):
    """List Exposure Cases

     List persisted Exposure Cases with optional filters.

    Args:
        org_id (None | str | Unset): Filter by org
        status (None | str | Unset): Filter by status: open | investigating | resolved

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListExposureCasesApiV1CorrelationsExposureCasesGetResponseListExposureCasesApiV1CorrelationsExposureCasesGet
    """

    return sync_detailed(
        client=client,
        org_id=org_id,
        status=status,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError
    | ListExposureCasesApiV1CorrelationsExposureCasesGetResponseListExposureCasesApiV1CorrelationsExposureCasesGet
]:
    """List Exposure Cases

     List persisted Exposure Cases with optional filters.

    Args:
        org_id (None | str | Unset): Filter by org
        status (None | str | Unset): Filter by status: open | investigating | resolved

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListExposureCasesApiV1CorrelationsExposureCasesGetResponseListExposureCasesApiV1CorrelationsExposureCasesGet]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        status=status,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    status: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | ListExposureCasesApiV1CorrelationsExposureCasesGetResponseListExposureCasesApiV1CorrelationsExposureCasesGet
    | None
):
    """List Exposure Cases

     List persisted Exposure Cases with optional filters.

    Args:
        org_id (None | str | Unset): Filter by org
        status (None | str | Unset): Filter by status: open | investigating | resolved

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListExposureCasesApiV1CorrelationsExposureCasesGetResponseListExposureCasesApiV1CorrelationsExposureCasesGet
    """

    return (
        await asyncio_detailed(
            client=client,
            org_id=org_id,
            status=status,
        )
    ).parsed
