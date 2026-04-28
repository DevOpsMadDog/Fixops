from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_exposure_case_api_v1_correlations_exposure_cases_case_id_get_response_get_exposure_case_api_v1_correlations_exposure_cases_case_id_get import (
    GetExposureCaseApiV1CorrelationsExposureCasesCaseIdGetResponseGetExposureCaseApiV1CorrelationsExposureCasesCaseIdGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    case_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/correlations/exposure-cases/{case_id}".format(
            case_id=quote(str(case_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetExposureCaseApiV1CorrelationsExposureCasesCaseIdGetResponseGetExposureCaseApiV1CorrelationsExposureCasesCaseIdGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = GetExposureCaseApiV1CorrelationsExposureCasesCaseIdGetResponseGetExposureCaseApiV1CorrelationsExposureCasesCaseIdGet.from_dict(
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
    GetExposureCaseApiV1CorrelationsExposureCasesCaseIdGetResponseGetExposureCaseApiV1CorrelationsExposureCasesCaseIdGet
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    case_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetExposureCaseApiV1CorrelationsExposureCasesCaseIdGetResponseGetExposureCaseApiV1CorrelationsExposureCasesCaseIdGet
    | HTTPValidationError
]:
    """Get Exposure Case detail

     Retrieve a single Exposure Case by ID.

    Args:
        case_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetExposureCaseApiV1CorrelationsExposureCasesCaseIdGetResponseGetExposureCaseApiV1CorrelationsExposureCasesCaseIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        case_id=case_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    case_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetExposureCaseApiV1CorrelationsExposureCasesCaseIdGetResponseGetExposureCaseApiV1CorrelationsExposureCasesCaseIdGet
    | HTTPValidationError
    | None
):
    """Get Exposure Case detail

     Retrieve a single Exposure Case by ID.

    Args:
        case_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetExposureCaseApiV1CorrelationsExposureCasesCaseIdGetResponseGetExposureCaseApiV1CorrelationsExposureCasesCaseIdGet | HTTPValidationError
    """

    return sync_detailed(
        case_id=case_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    case_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetExposureCaseApiV1CorrelationsExposureCasesCaseIdGetResponseGetExposureCaseApiV1CorrelationsExposureCasesCaseIdGet
    | HTTPValidationError
]:
    """Get Exposure Case detail

     Retrieve a single Exposure Case by ID.

    Args:
        case_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetExposureCaseApiV1CorrelationsExposureCasesCaseIdGetResponseGetExposureCaseApiV1CorrelationsExposureCasesCaseIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        case_id=case_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    case_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetExposureCaseApiV1CorrelationsExposureCasesCaseIdGetResponseGetExposureCaseApiV1CorrelationsExposureCasesCaseIdGet
    | HTTPValidationError
    | None
):
    """Get Exposure Case detail

     Retrieve a single Exposure Case by ID.

    Args:
        case_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetExposureCaseApiV1CorrelationsExposureCasesCaseIdGetResponseGetExposureCaseApiV1CorrelationsExposureCasesCaseIdGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            case_id=case_id,
            client=client,
        )
    ).parsed
