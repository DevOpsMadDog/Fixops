from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.assign_finding_api_v1_findings_finding_id_assign_put_response_assign_finding_api_v1_findings_finding_id_assign_put import (
    AssignFindingApiV1FindingsFindingIdAssignPutResponseAssignFindingApiV1FindingsFindingIdAssignPut,
)
from ...models.assignment_request import AssignmentRequest
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    finding_id: str,
    *,
    body: AssignmentRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "put",
        "url": "/api/v1/findings/{finding_id}/assign".format(
            finding_id=quote(str(finding_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    AssignFindingApiV1FindingsFindingIdAssignPutResponseAssignFindingApiV1FindingsFindingIdAssignPut
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = (
            AssignFindingApiV1FindingsFindingIdAssignPutResponseAssignFindingApiV1FindingsFindingIdAssignPut.from_dict(
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
    AssignFindingApiV1FindingsFindingIdAssignPutResponseAssignFindingApiV1FindingsFindingIdAssignPut
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    finding_id: str,
    *,
    client: AuthenticatedClient,
    body: AssignmentRequest,
) -> Response[
    AssignFindingApiV1FindingsFindingIdAssignPutResponseAssignFindingApiV1FindingsFindingIdAssignPut
    | HTTPValidationError
]:
    """Assign Finding

     Assign finding to user or team.

    Args:
        finding_id: Finding identifier
        assignment: AssignmentRequest with user or team

    Returns:
        Updated assignment info

    Raises:
        HTTPException: 404 if finding not found, 400 if assignment invalid

    Args:
        finding_id (str):
        body (AssignmentRequest): Request to assign finding.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AssignFindingApiV1FindingsFindingIdAssignPutResponseAssignFindingApiV1FindingsFindingIdAssignPut | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        finding_id=finding_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    finding_id: str,
    *,
    client: AuthenticatedClient,
    body: AssignmentRequest,
) -> (
    AssignFindingApiV1FindingsFindingIdAssignPutResponseAssignFindingApiV1FindingsFindingIdAssignPut
    | HTTPValidationError
    | None
):
    """Assign Finding

     Assign finding to user or team.

    Args:
        finding_id: Finding identifier
        assignment: AssignmentRequest with user or team

    Returns:
        Updated assignment info

    Raises:
        HTTPException: 404 if finding not found, 400 if assignment invalid

    Args:
        finding_id (str):
        body (AssignmentRequest): Request to assign finding.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AssignFindingApiV1FindingsFindingIdAssignPutResponseAssignFindingApiV1FindingsFindingIdAssignPut | HTTPValidationError
    """

    return sync_detailed(
        finding_id=finding_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    finding_id: str,
    *,
    client: AuthenticatedClient,
    body: AssignmentRequest,
) -> Response[
    AssignFindingApiV1FindingsFindingIdAssignPutResponseAssignFindingApiV1FindingsFindingIdAssignPut
    | HTTPValidationError
]:
    """Assign Finding

     Assign finding to user or team.

    Args:
        finding_id: Finding identifier
        assignment: AssignmentRequest with user or team

    Returns:
        Updated assignment info

    Raises:
        HTTPException: 404 if finding not found, 400 if assignment invalid

    Args:
        finding_id (str):
        body (AssignmentRequest): Request to assign finding.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AssignFindingApiV1FindingsFindingIdAssignPutResponseAssignFindingApiV1FindingsFindingIdAssignPut | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        finding_id=finding_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    finding_id: str,
    *,
    client: AuthenticatedClient,
    body: AssignmentRequest,
) -> (
    AssignFindingApiV1FindingsFindingIdAssignPutResponseAssignFindingApiV1FindingsFindingIdAssignPut
    | HTTPValidationError
    | None
):
    """Assign Finding

     Assign finding to user or team.

    Args:
        finding_id: Finding identifier
        assignment: AssignmentRequest with user or team

    Returns:
        Updated assignment info

    Raises:
        HTTPException: 404 if finding not found, 400 if assignment invalid

    Args:
        finding_id (str):
        body (AssignmentRequest): Request to assign finding.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AssignFindingApiV1FindingsFindingIdAssignPutResponseAssignFindingApiV1FindingsFindingIdAssignPut | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            finding_id=finding_id,
            client=client,
            body=body,
        )
    ).parsed
