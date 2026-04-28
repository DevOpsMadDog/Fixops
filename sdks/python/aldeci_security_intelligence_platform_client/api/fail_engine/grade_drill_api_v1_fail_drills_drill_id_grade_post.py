from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.grade_request import GradeRequest
from ...models.grade_response import GradeResponse
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    drill_id: str,
    *,
    body: GradeRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/fail/drills/{drill_id}/grade".format(
            drill_id=quote(str(drill_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GradeResponse | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = GradeResponse.from_dict(response.json())

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
) -> Response[GradeResponse | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    drill_id: str,
    *,
    client: AuthenticatedClient,
    body: GradeRequest,
) -> Response[GradeResponse | HTTPValidationError]:
    """Grade team response to a drill

     Compute and persist the 4-dimension drill score.

    Scoring dimensions:
    - **Detection Speed** (30%) — How fast was the synthetic finding noticed?
    - **Triage Accuracy** (25%) — Was it correctly classified as critical/real?
    - **Remediation Speed** (30%) — How fast was the fix applied?
    - **Communication** (15%) — Was the right team notified? Escalation followed?

    Overall = weighted average of all four dimensions (0-10 scale).

    Args:
        drill_id (str):
        body (GradeRequest): Request to grade a drill's team response.

            Override fields allow manual override of auto-computed timings
            (e.g. when detection was reported verbally before the system was updated).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GradeResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        drill_id=drill_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    drill_id: str,
    *,
    client: AuthenticatedClient,
    body: GradeRequest,
) -> GradeResponse | HTTPValidationError | None:
    """Grade team response to a drill

     Compute and persist the 4-dimension drill score.

    Scoring dimensions:
    - **Detection Speed** (30%) — How fast was the synthetic finding noticed?
    - **Triage Accuracy** (25%) — Was it correctly classified as critical/real?
    - **Remediation Speed** (30%) — How fast was the fix applied?
    - **Communication** (15%) — Was the right team notified? Escalation followed?

    Overall = weighted average of all four dimensions (0-10 scale).

    Args:
        drill_id (str):
        body (GradeRequest): Request to grade a drill's team response.

            Override fields allow manual override of auto-computed timings
            (e.g. when detection was reported verbally before the system was updated).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GradeResponse | HTTPValidationError
    """

    return sync_detailed(
        drill_id=drill_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    drill_id: str,
    *,
    client: AuthenticatedClient,
    body: GradeRequest,
) -> Response[GradeResponse | HTTPValidationError]:
    """Grade team response to a drill

     Compute and persist the 4-dimension drill score.

    Scoring dimensions:
    - **Detection Speed** (30%) — How fast was the synthetic finding noticed?
    - **Triage Accuracy** (25%) — Was it correctly classified as critical/real?
    - **Remediation Speed** (30%) — How fast was the fix applied?
    - **Communication** (15%) — Was the right team notified? Escalation followed?

    Overall = weighted average of all four dimensions (0-10 scale).

    Args:
        drill_id (str):
        body (GradeRequest): Request to grade a drill's team response.

            Override fields allow manual override of auto-computed timings
            (e.g. when detection was reported verbally before the system was updated).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GradeResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        drill_id=drill_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    drill_id: str,
    *,
    client: AuthenticatedClient,
    body: GradeRequest,
) -> GradeResponse | HTTPValidationError | None:
    """Grade team response to a drill

     Compute and persist the 4-dimension drill score.

    Scoring dimensions:
    - **Detection Speed** (30%) — How fast was the synthetic finding noticed?
    - **Triage Accuracy** (25%) — Was it correctly classified as critical/real?
    - **Remediation Speed** (30%) — How fast was the fix applied?
    - **Communication** (15%) — Was the right team notified? Escalation followed?

    Overall = weighted average of all four dimensions (0-10 scale).

    Args:
        drill_id (str):
        body (GradeRequest): Request to grade a drill's team response.

            Override fields allow manual override of auto-computed timings
            (e.g. when detection was reported verbally before the system was updated).

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GradeResponse | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            drill_id=drill_id,
            client=client,
            body=body,
        )
    ).parsed
