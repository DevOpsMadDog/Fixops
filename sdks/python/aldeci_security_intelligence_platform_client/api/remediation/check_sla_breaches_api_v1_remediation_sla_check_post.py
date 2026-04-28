from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.check_sla_breaches_api_v1_remediation_sla_check_post_response_check_sla_breaches_api_v1_remediation_sla_check_post import (
    CheckSlaBreachesApiV1RemediationSlaCheckPostResponseCheckSlaBreachesApiV1RemediationSlaCheckPost,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response


def _get_kwargs(
    *,
    org_id: str,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/remediation/sla/check",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    CheckSlaBreachesApiV1RemediationSlaCheckPostResponseCheckSlaBreachesApiV1RemediationSlaCheckPost
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = (
            CheckSlaBreachesApiV1RemediationSlaCheckPostResponseCheckSlaBreachesApiV1RemediationSlaCheckPost.from_dict(
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
    CheckSlaBreachesApiV1RemediationSlaCheckPostResponseCheckSlaBreachesApiV1RemediationSlaCheckPost
    | HTTPValidationError
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
    org_id: str,
) -> Response[
    CheckSlaBreachesApiV1RemediationSlaCheckPostResponseCheckSlaBreachesApiV1RemediationSlaCheckPost
    | HTTPValidationError
]:
    """Check Sla Breaches

     Check for SLA breaches and record them.

    Args:
        org_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CheckSlaBreachesApiV1RemediationSlaCheckPostResponseCheckSlaBreachesApiV1RemediationSlaCheckPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    org_id: str,
) -> (
    CheckSlaBreachesApiV1RemediationSlaCheckPostResponseCheckSlaBreachesApiV1RemediationSlaCheckPost
    | HTTPValidationError
    | None
):
    """Check Sla Breaches

     Check for SLA breaches and record them.

    Args:
        org_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CheckSlaBreachesApiV1RemediationSlaCheckPostResponseCheckSlaBreachesApiV1RemediationSlaCheckPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        org_id=org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str,
) -> Response[
    CheckSlaBreachesApiV1RemediationSlaCheckPostResponseCheckSlaBreachesApiV1RemediationSlaCheckPost
    | HTTPValidationError
]:
    """Check Sla Breaches

     Check for SLA breaches and record them.

    Args:
        org_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CheckSlaBreachesApiV1RemediationSlaCheckPostResponseCheckSlaBreachesApiV1RemediationSlaCheckPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    org_id: str,
) -> (
    CheckSlaBreachesApiV1RemediationSlaCheckPostResponseCheckSlaBreachesApiV1RemediationSlaCheckPost
    | HTTPValidationError
    | None
):
    """Check Sla Breaches

     Check for SLA breaches and record them.

    Args:
        org_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CheckSlaBreachesApiV1RemediationSlaCheckPostResponseCheckSlaBreachesApiV1RemediationSlaCheckPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            org_id=org_id,
        )
    ).parsed
