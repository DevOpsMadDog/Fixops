from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_org_summary_api_v1_orgs_org_id_summary_get_response_get_org_summary_api_v1_orgs_org_id_summary_get import (
    GetOrgSummaryApiV1OrgsOrgIdSummaryGetResponseGetOrgSummaryApiV1OrgsOrgIdSummaryGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    org_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/orgs/{org_id}/summary".format(
            org_id=quote(str(org_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetOrgSummaryApiV1OrgsOrgIdSummaryGetResponseGetOrgSummaryApiV1OrgsOrgIdSummaryGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = GetOrgSummaryApiV1OrgsOrgIdSummaryGetResponseGetOrgSummaryApiV1OrgsOrgIdSummaryGet.from_dict(
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
) -> Response[GetOrgSummaryApiV1OrgsOrgIdSummaryGetResponseGetOrgSummaryApiV1OrgsOrgIdSummaryGet | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    org_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[GetOrgSummaryApiV1OrgsOrgIdSummaryGetResponseGetOrgSummaryApiV1OrgsOrgIdSummaryGet | HTTPValidationError]:
    """Get Org Summary

     Return a dashboard summary for a specific org.

    Shows how many engine databases contain data for this org_id and the
    total row count across all tables.

    Args:
        org_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetOrgSummaryApiV1OrgsOrgIdSummaryGetResponseGetOrgSummaryApiV1OrgsOrgIdSummaryGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    org_id: str,
    *,
    client: AuthenticatedClient,
) -> GetOrgSummaryApiV1OrgsOrgIdSummaryGetResponseGetOrgSummaryApiV1OrgsOrgIdSummaryGet | HTTPValidationError | None:
    """Get Org Summary

     Return a dashboard summary for a specific org.

    Shows how many engine databases contain data for this org_id and the
    total row count across all tables.

    Args:
        org_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetOrgSummaryApiV1OrgsOrgIdSummaryGetResponseGetOrgSummaryApiV1OrgsOrgIdSummaryGet | HTTPValidationError
    """

    return sync_detailed(
        org_id=org_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    org_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[GetOrgSummaryApiV1OrgsOrgIdSummaryGetResponseGetOrgSummaryApiV1OrgsOrgIdSummaryGet | HTTPValidationError]:
    """Get Org Summary

     Return a dashboard summary for a specific org.

    Shows how many engine databases contain data for this org_id and the
    total row count across all tables.

    Args:
        org_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetOrgSummaryApiV1OrgsOrgIdSummaryGetResponseGetOrgSummaryApiV1OrgsOrgIdSummaryGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    org_id: str,
    *,
    client: AuthenticatedClient,
) -> GetOrgSummaryApiV1OrgsOrgIdSummaryGetResponseGetOrgSummaryApiV1OrgsOrgIdSummaryGet | HTTPValidationError | None:
    """Get Org Summary

     Return a dashboard summary for a specific org.

    Shows how many engine databases contain data for this org_id and the
    total row count across all tables.

    Args:
        org_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetOrgSummaryApiV1OrgsOrgIdSummaryGetResponseGetOrgSummaryApiV1OrgsOrgIdSummaryGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            org_id=org_id,
            client=client,
        )
    ).parsed
