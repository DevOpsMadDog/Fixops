from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_compliance_content_api_v1_marketplace_compliance_content_stage_get_response_get_compliance_content_api_v1_marketplace_compliance_content_stage_get import (
    GetComplianceContentApiV1MarketplaceComplianceContentStageGetResponseGetComplianceContentApiV1MarketplaceComplianceContentStageGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response


def _get_kwargs(
    stage: str,
    *,
    frameworks: str,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["frameworks"] = frameworks

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/marketplace/compliance-content/{stage}".format(
            stage=quote(str(stage), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetComplianceContentApiV1MarketplaceComplianceContentStageGetResponseGetComplianceContentApiV1MarketplaceComplianceContentStageGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = GetComplianceContentApiV1MarketplaceComplianceContentStageGetResponseGetComplianceContentApiV1MarketplaceComplianceContentStageGet.from_dict(
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
) -> Response[
    GetComplianceContentApiV1MarketplaceComplianceContentStageGetResponseGetComplianceContentApiV1MarketplaceComplianceContentStageGet
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    stage: str,
    *,
    client: AuthenticatedClient,
    frameworks: str,
) -> Response[
    GetComplianceContentApiV1MarketplaceComplianceContentStageGetResponseGetComplianceContentApiV1MarketplaceComplianceContentStageGet
    | HTTPValidationError
]:
    """Get Compliance Content

     Get marketplace content for a specific SSDLC stage and frameworks.

    Args:
        stage (str):
        frameworks (str): Comma-separated compliance frameworks

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetComplianceContentApiV1MarketplaceComplianceContentStageGetResponseGetComplianceContentApiV1MarketplaceComplianceContentStageGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        stage=stage,
        frameworks=frameworks,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    stage: str,
    *,
    client: AuthenticatedClient,
    frameworks: str,
) -> (
    GetComplianceContentApiV1MarketplaceComplianceContentStageGetResponseGetComplianceContentApiV1MarketplaceComplianceContentStageGet
    | HTTPValidationError
    | None
):
    """Get Compliance Content

     Get marketplace content for a specific SSDLC stage and frameworks.

    Args:
        stage (str):
        frameworks (str): Comma-separated compliance frameworks

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetComplianceContentApiV1MarketplaceComplianceContentStageGetResponseGetComplianceContentApiV1MarketplaceComplianceContentStageGet | HTTPValidationError
    """

    return sync_detailed(
        stage=stage,
        client=client,
        frameworks=frameworks,
    ).parsed


async def asyncio_detailed(
    stage: str,
    *,
    client: AuthenticatedClient,
    frameworks: str,
) -> Response[
    GetComplianceContentApiV1MarketplaceComplianceContentStageGetResponseGetComplianceContentApiV1MarketplaceComplianceContentStageGet
    | HTTPValidationError
]:
    """Get Compliance Content

     Get marketplace content for a specific SSDLC stage and frameworks.

    Args:
        stage (str):
        frameworks (str): Comma-separated compliance frameworks

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetComplianceContentApiV1MarketplaceComplianceContentStageGetResponseGetComplianceContentApiV1MarketplaceComplianceContentStageGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        stage=stage,
        frameworks=frameworks,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    stage: str,
    *,
    client: AuthenticatedClient,
    frameworks: str,
) -> (
    GetComplianceContentApiV1MarketplaceComplianceContentStageGetResponseGetComplianceContentApiV1MarketplaceComplianceContentStageGet
    | HTTPValidationError
    | None
):
    """Get Compliance Content

     Get marketplace content for a specific SSDLC stage and frameworks.

    Args:
        stage (str):
        frameworks (str): Comma-separated compliance frameworks

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetComplianceContentApiV1MarketplaceComplianceContentStageGetResponseGetComplianceContentApiV1MarketplaceComplianceContentStageGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            stage=stage,
            client=client,
            frameworks=frameworks,
        )
    ).parsed
