from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_metrics_api_v1_remediation_metrics_org_id_get_response_get_metrics_api_v1_remediation_metrics_org_id_get import (
    GetMetricsApiV1RemediationMetricsOrgIdGetResponseGetMetricsApiV1RemediationMetricsOrgIdGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    org_id: str,
    *,
    app_id: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_app_id: None | str | Unset
    if isinstance(app_id, Unset):
        json_app_id = UNSET
    else:
        json_app_id = app_id
    params["app_id"] = json_app_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/remediation/metrics/{org_id}".format(
            org_id=quote(str(org_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetMetricsApiV1RemediationMetricsOrgIdGetResponseGetMetricsApiV1RemediationMetricsOrgIdGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = (
            GetMetricsApiV1RemediationMetricsOrgIdGetResponseGetMetricsApiV1RemediationMetricsOrgIdGet.from_dict(
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
    GetMetricsApiV1RemediationMetricsOrgIdGetResponseGetMetricsApiV1RemediationMetricsOrgIdGet | HTTPValidationError
]:
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
    app_id: None | str | Unset = UNSET,
) -> Response[
    GetMetricsApiV1RemediationMetricsOrgIdGetResponseGetMetricsApiV1RemediationMetricsOrgIdGet | HTTPValidationError
]:
    """Get Metrics

     Get remediation metrics including MTTR.

    Args:
        org_id (str):
        app_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetMetricsApiV1RemediationMetricsOrgIdGetResponseGetMetricsApiV1RemediationMetricsOrgIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        app_id=app_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    org_id: str,
    *,
    client: AuthenticatedClient,
    app_id: None | str | Unset = UNSET,
) -> (
    GetMetricsApiV1RemediationMetricsOrgIdGetResponseGetMetricsApiV1RemediationMetricsOrgIdGet
    | HTTPValidationError
    | None
):
    """Get Metrics

     Get remediation metrics including MTTR.

    Args:
        org_id (str):
        app_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetMetricsApiV1RemediationMetricsOrgIdGetResponseGetMetricsApiV1RemediationMetricsOrgIdGet | HTTPValidationError
    """

    return sync_detailed(
        org_id=org_id,
        client=client,
        app_id=app_id,
    ).parsed


async def asyncio_detailed(
    org_id: str,
    *,
    client: AuthenticatedClient,
    app_id: None | str | Unset = UNSET,
) -> Response[
    GetMetricsApiV1RemediationMetricsOrgIdGetResponseGetMetricsApiV1RemediationMetricsOrgIdGet | HTTPValidationError
]:
    """Get Metrics

     Get remediation metrics including MTTR.

    Args:
        org_id (str):
        app_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetMetricsApiV1RemediationMetricsOrgIdGetResponseGetMetricsApiV1RemediationMetricsOrgIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        app_id=app_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    org_id: str,
    *,
    client: AuthenticatedClient,
    app_id: None | str | Unset = UNSET,
) -> (
    GetMetricsApiV1RemediationMetricsOrgIdGetResponseGetMetricsApiV1RemediationMetricsOrgIdGet
    | HTTPValidationError
    | None
):
    """Get Metrics

     Get remediation metrics including MTTR.

    Args:
        org_id (str):
        app_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetMetricsApiV1RemediationMetricsOrgIdGetResponseGetMetricsApiV1RemediationMetricsOrgIdGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            org_id=org_id,
            client=client,
            app_id=app_id,
        )
    ).parsed
