from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.assess_impact_api_v1_changes_change_id_impact_post_response_assess_impact_api_v1_changes_change_id_impact_post import (
    AssessImpactApiV1ChangesChangeIdImpactPostResponseAssessImpactApiV1ChangesChangeIdImpactPost,
)
from ...models.http_validation_error import HTTPValidationError
from ...models.impact_assess_request import ImpactAssessRequest
from ...types import Response


def _get_kwargs(
    change_id: str,
    *,
    body: ImpactAssessRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/changes/{change_id}/impact".format(
            change_id=quote(str(change_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    AssessImpactApiV1ChangesChangeIdImpactPostResponseAssessImpactApiV1ChangesChangeIdImpactPost
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = (
            AssessImpactApiV1ChangesChangeIdImpactPostResponseAssessImpactApiV1ChangesChangeIdImpactPost.from_dict(
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
    AssessImpactApiV1ChangesChangeIdImpactPostResponseAssessImpactApiV1ChangesChangeIdImpactPost | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    change_id: str,
    *,
    client: AuthenticatedClient,
    body: ImpactAssessRequest,
) -> Response[
    AssessImpactApiV1ChangesChangeIdImpactPostResponseAssessImpactApiV1ChangesChangeIdImpactPost | HTTPValidationError
]:
    """Assess Impact

     Attach or update impact analysis for a change request.

    Args:
        change_id (str):
        body (ImpactAssessRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AssessImpactApiV1ChangesChangeIdImpactPostResponseAssessImpactApiV1ChangesChangeIdImpactPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        change_id=change_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    change_id: str,
    *,
    client: AuthenticatedClient,
    body: ImpactAssessRequest,
) -> (
    AssessImpactApiV1ChangesChangeIdImpactPostResponseAssessImpactApiV1ChangesChangeIdImpactPost
    | HTTPValidationError
    | None
):
    """Assess Impact

     Attach or update impact analysis for a change request.

    Args:
        change_id (str):
        body (ImpactAssessRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AssessImpactApiV1ChangesChangeIdImpactPostResponseAssessImpactApiV1ChangesChangeIdImpactPost | HTTPValidationError
    """

    return sync_detailed(
        change_id=change_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    change_id: str,
    *,
    client: AuthenticatedClient,
    body: ImpactAssessRequest,
) -> Response[
    AssessImpactApiV1ChangesChangeIdImpactPostResponseAssessImpactApiV1ChangesChangeIdImpactPost | HTTPValidationError
]:
    """Assess Impact

     Attach or update impact analysis for a change request.

    Args:
        change_id (str):
        body (ImpactAssessRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AssessImpactApiV1ChangesChangeIdImpactPostResponseAssessImpactApiV1ChangesChangeIdImpactPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        change_id=change_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    change_id: str,
    *,
    client: AuthenticatedClient,
    body: ImpactAssessRequest,
) -> (
    AssessImpactApiV1ChangesChangeIdImpactPostResponseAssessImpactApiV1ChangesChangeIdImpactPost
    | HTTPValidationError
    | None
):
    """Assess Impact

     Attach or update impact analysis for a change request.

    Args:
        change_id (str):
        body (ImpactAssessRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AssessImpactApiV1ChangesChangeIdImpactPostResponseAssessImpactApiV1ChangesChangeIdImpactPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            change_id=change_id,
            client=client,
            body=body,
        )
    ).parsed
