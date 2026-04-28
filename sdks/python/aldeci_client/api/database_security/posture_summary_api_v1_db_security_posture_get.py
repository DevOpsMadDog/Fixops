from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.posture_summary_api_v1_db_security_posture_get_response_posture_summary_api_v1_db_security_posture_get import (
    PostureSummaryApiV1DbSecurityPostureGetResponsePostureSummaryApiV1DbSecurityPostureGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/db-security/posture",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> PostureSummaryApiV1DbSecurityPostureGetResponsePostureSummaryApiV1DbSecurityPostureGet | None:
    if response.status_code == 200:
        response_200 = PostureSummaryApiV1DbSecurityPostureGetResponsePostureSummaryApiV1DbSecurityPostureGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[PostureSummaryApiV1DbSecurityPostureGetResponsePostureSummaryApiV1DbSecurityPostureGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[PostureSummaryApiV1DbSecurityPostureGetResponsePostureSummaryApiV1DbSecurityPostureGet]:
    """Posture Summary

     Return aggregate security posture across all scanned databases.

    Includes average risk score, finding counts by severity, and per-database ranking.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostureSummaryApiV1DbSecurityPostureGetResponsePostureSummaryApiV1DbSecurityPostureGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> PostureSummaryApiV1DbSecurityPostureGetResponsePostureSummaryApiV1DbSecurityPostureGet | None:
    """Posture Summary

     Return aggregate security posture across all scanned databases.

    Includes average risk score, finding counts by severity, and per-database ranking.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostureSummaryApiV1DbSecurityPostureGetResponsePostureSummaryApiV1DbSecurityPostureGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[PostureSummaryApiV1DbSecurityPostureGetResponsePostureSummaryApiV1DbSecurityPostureGet]:
    """Posture Summary

     Return aggregate security posture across all scanned databases.

    Includes average risk score, finding counts by severity, and per-database ranking.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[PostureSummaryApiV1DbSecurityPostureGetResponsePostureSummaryApiV1DbSecurityPostureGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> PostureSummaryApiV1DbSecurityPostureGetResponsePostureSummaryApiV1DbSecurityPostureGet | None:
    """Posture Summary

     Return aggregate security posture across all scanned databases.

    Includes average risk score, finding counts by severity, and per-database ranking.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        PostureSummaryApiV1DbSecurityPostureGetResponsePostureSummaryApiV1DbSecurityPostureGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
