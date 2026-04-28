from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.approve_policy_request import ApprovePolicyRequest
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    policy_id: str,
    *,
    body: ApprovePolicyRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/policy-generator/policies/{policy_id}/approve".format(
            policy_id=quote(str(policy_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> HTTPValidationError | None:
    if response.status_code == 422:
        response_422 = HTTPValidationError.from_dict(response.json())

        return response_422

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    policy_id: str,
    *,
    client: AuthenticatedClient,
    body: ApprovePolicyRequest,
) -> Response[HTTPValidationError]:
    """Approve Policy

     Approve a policy document.

    Sets status to ACTIVE, records the approver, and sets effective_date to now.

    Args:
        policy_id (str):
        body (ApprovePolicyRequest): Request body for approving a policy.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError]
    """

    kwargs = _get_kwargs(
        policy_id=policy_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    policy_id: str,
    *,
    client: AuthenticatedClient,
    body: ApprovePolicyRequest,
) -> HTTPValidationError | None:
    """Approve Policy

     Approve a policy document.

    Sets status to ACTIVE, records the approver, and sets effective_date to now.

    Args:
        policy_id (str):
        body (ApprovePolicyRequest): Request body for approving a policy.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError
    """

    return sync_detailed(
        policy_id=policy_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    policy_id: str,
    *,
    client: AuthenticatedClient,
    body: ApprovePolicyRequest,
) -> Response[HTTPValidationError]:
    """Approve Policy

     Approve a policy document.

    Sets status to ACTIVE, records the approver, and sets effective_date to now.

    Args:
        policy_id (str):
        body (ApprovePolicyRequest): Request body for approving a policy.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError]
    """

    kwargs = _get_kwargs(
        policy_id=policy_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    policy_id: str,
    *,
    client: AuthenticatedClient,
    body: ApprovePolicyRequest,
) -> HTTPValidationError | None:
    """Approve Policy

     Approve a policy document.

    Sets status to ACTIVE, records the approver, and sets effective_date to now.

    Args:
        policy_id (str):
        body (ApprovePolicyRequest): Request body for approving a policy.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError
    """

    return (
        await asyncio_detailed(
            policy_id=policy_id,
            client=client,
            body=body,
        )
    ).parsed
