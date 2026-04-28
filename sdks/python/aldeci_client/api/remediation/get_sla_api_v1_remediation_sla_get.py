from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_sla_api_v1_remediation_sla_get_response_get_sla_api_v1_remediation_sla_get import (
    GetSlaApiV1RemediationSlaGetResponseGetSlaApiV1RemediationSlaGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    severity: str | Unset = "MEDIUM",
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["severity"] = severity

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/remediation/sla",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetSlaApiV1RemediationSlaGetResponseGetSlaApiV1RemediationSlaGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = GetSlaApiV1RemediationSlaGetResponseGetSlaApiV1RemediationSlaGet.from_dict(response.json())

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
) -> Response[GetSlaApiV1RemediationSlaGetResponseGetSlaApiV1RemediationSlaGet | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    severity: str | Unset = "MEDIUM",
) -> Response[GetSlaApiV1RemediationSlaGetResponseGetSlaApiV1RemediationSlaGet | HTTPValidationError]:
    """Get SLA deadline for a severity

     Return the SLA timedelta and hours for a given severity level.

    Args:
        severity (str | Unset):  Default: 'MEDIUM'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetSlaApiV1RemediationSlaGetResponseGetSlaApiV1RemediationSlaGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        severity=severity,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    severity: str | Unset = "MEDIUM",
) -> GetSlaApiV1RemediationSlaGetResponseGetSlaApiV1RemediationSlaGet | HTTPValidationError | None:
    """Get SLA deadline for a severity

     Return the SLA timedelta and hours for a given severity level.

    Args:
        severity (str | Unset):  Default: 'MEDIUM'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetSlaApiV1RemediationSlaGetResponseGetSlaApiV1RemediationSlaGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        severity=severity,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    severity: str | Unset = "MEDIUM",
) -> Response[GetSlaApiV1RemediationSlaGetResponseGetSlaApiV1RemediationSlaGet | HTTPValidationError]:
    """Get SLA deadline for a severity

     Return the SLA timedelta and hours for a given severity level.

    Args:
        severity (str | Unset):  Default: 'MEDIUM'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetSlaApiV1RemediationSlaGetResponseGetSlaApiV1RemediationSlaGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        severity=severity,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    severity: str | Unset = "MEDIUM",
) -> GetSlaApiV1RemediationSlaGetResponseGetSlaApiV1RemediationSlaGet | HTTPValidationError | None:
    """Get SLA deadline for a severity

     Return the SLA timedelta and hours for a given severity level.

    Args:
        severity (str | Unset):  Default: 'MEDIUM'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetSlaApiV1RemediationSlaGetResponseGetSlaApiV1RemediationSlaGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            severity=severity,
        )
    ).parsed
