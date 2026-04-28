from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.status_update_request import StatusUpdateRequest
from ...models.update_case_status_api_v1_correlations_exposure_cases_case_id_status_put_response_update_case_status_api_v1_correlations_exposure_cases_case_id_status_put import (
    UpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPutResponseUpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPut,
)
from ...types import Response


def _get_kwargs(
    case_id: str,
    *,
    body: StatusUpdateRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/correlations/exposure-cases/{case_id}/status".format(
            case_id=quote(str(case_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | UpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPutResponseUpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPut
    | None
):
    if response.status_code == 200:
        response_200 = UpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPutResponseUpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPut.from_dict(
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
    | UpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPutResponseUpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPut
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
    body: StatusUpdateRequest,
) -> Response[
    HTTPValidationError
    | UpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPutResponseUpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPut
]:
    """Update Exposure Case investigation status

     Change the investigation status of an Exposure Case.

    Args:
        case_id (str):
        body (StatusUpdateRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPutResponseUpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPut]
    """

    kwargs = _get_kwargs(
        case_id=case_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    case_id: str,
    *,
    client: AuthenticatedClient,
    body: StatusUpdateRequest,
) -> (
    HTTPValidationError
    | UpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPutResponseUpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPut
    | None
):
    """Update Exposure Case investigation status

     Change the investigation status of an Exposure Case.

    Args:
        case_id (str):
        body (StatusUpdateRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPutResponseUpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPut
    """

    return sync_detailed(
        case_id=case_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    case_id: str,
    *,
    client: AuthenticatedClient,
    body: StatusUpdateRequest,
) -> Response[
    HTTPValidationError
    | UpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPutResponseUpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPut
]:
    """Update Exposure Case investigation status

     Change the investigation status of an Exposure Case.

    Args:
        case_id (str):
        body (StatusUpdateRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPutResponseUpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPut]
    """

    kwargs = _get_kwargs(
        case_id=case_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    case_id: str,
    *,
    client: AuthenticatedClient,
    body: StatusUpdateRequest,
) -> (
    HTTPValidationError
    | UpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPutResponseUpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPut
    | None
):
    """Update Exposure Case investigation status

     Change the investigation status of an Exposure Case.

    Args:
        case_id (str):
        body (StatusUpdateRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPutResponseUpdateCaseStatusApiV1CorrelationsExposureCasesCaseIdStatusPut
    """

    return (
        await asyncio_detailed(
            case_id=case_id,
            client=client,
            body=body,
        )
    ).parsed
