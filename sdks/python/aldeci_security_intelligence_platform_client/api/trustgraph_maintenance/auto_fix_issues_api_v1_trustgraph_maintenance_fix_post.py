from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.fix_request import FixRequest
from ...models.fix_response import FixResponse
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    *,
    body: FixRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/trustgraph/maintenance/fix",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> FixResponse | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = FixResponse.from_dict(response.json())

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
) -> Response[FixResponse | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: FixRequest,
) -> Response[FixResponse | HTTPValidationError]:
    """Auto Fix Issues

     Auto-fix safe integrity issues detected in the Knowledge Cores.

    Fixable issue types:
    - orphan: Links orphaned entity to its core anchor via belongs_to_core relationship
    - duplicate: Soft-deletes all but the primary duplicate finding

    Args:
        req: FixRequest with dry_run flag and optional issue_types filter.

    Returns:
        FixResponse with counts of fixes applied, skipped, and errors.

    Args:
        body (FixRequest): Request body for auto-fix endpoint.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[FixResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: FixRequest,
) -> FixResponse | HTTPValidationError | None:
    """Auto Fix Issues

     Auto-fix safe integrity issues detected in the Knowledge Cores.

    Fixable issue types:
    - orphan: Links orphaned entity to its core anchor via belongs_to_core relationship
    - duplicate: Soft-deletes all but the primary duplicate finding

    Args:
        req: FixRequest with dry_run flag and optional issue_types filter.

    Returns:
        FixResponse with counts of fixes applied, skipped, and errors.

    Args:
        body (FixRequest): Request body for auto-fix endpoint.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        FixResponse | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: FixRequest,
) -> Response[FixResponse | HTTPValidationError]:
    """Auto Fix Issues

     Auto-fix safe integrity issues detected in the Knowledge Cores.

    Fixable issue types:
    - orphan: Links orphaned entity to its core anchor via belongs_to_core relationship
    - duplicate: Soft-deletes all but the primary duplicate finding

    Args:
        req: FixRequest with dry_run flag and optional issue_types filter.

    Returns:
        FixResponse with counts of fixes applied, skipped, and errors.

    Args:
        body (FixRequest): Request body for auto-fix endpoint.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[FixResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: FixRequest,
) -> FixResponse | HTTPValidationError | None:
    """Auto Fix Issues

     Auto-fix safe integrity issues detected in the Knowledge Cores.

    Fixable issue types:
    - orphan: Links orphaned entity to its core anchor via belongs_to_core relationship
    - duplicate: Soft-deletes all but the primary duplicate finding

    Args:
        req: FixRequest with dry_run flag and optional issue_types filter.

    Returns:
        FixResponse with counts of fixes applied, skipped, and errors.

    Args:
        body (FixRequest): Request body for auto-fix endpoint.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        FixResponse | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
