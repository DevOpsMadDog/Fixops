from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_recommendations_api_v1_marketplace_recommendations_get_response_get_recommendations_api_v1_marketplace_recommendations_get import (
    GetRecommendationsApiV1MarketplaceRecommendationsGetResponseGetRecommendationsApiV1MarketplaceRecommendationsGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    organization_type: str | Unset = "general",
    compliance_requirements: str | Unset = "",
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["organization_type"] = organization_type

    params["compliance_requirements"] = compliance_requirements

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/marketplace/recommendations",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetRecommendationsApiV1MarketplaceRecommendationsGetResponseGetRecommendationsApiV1MarketplaceRecommendationsGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = GetRecommendationsApiV1MarketplaceRecommendationsGetResponseGetRecommendationsApiV1MarketplaceRecommendationsGet.from_dict(
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
    GetRecommendationsApiV1MarketplaceRecommendationsGetResponseGetRecommendationsApiV1MarketplaceRecommendationsGet
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
    organization_type: str | Unset = "general",
    compliance_requirements: str | Unset = "",
) -> Response[
    GetRecommendationsApiV1MarketplaceRecommendationsGetResponseGetRecommendationsApiV1MarketplaceRecommendationsGet
    | HTTPValidationError
]:
    """Get Recommendations

     Get recommended marketplace content based on organization profile.

    Args:
        organization_type (str | Unset): Organization type Default: 'general'.
        compliance_requirements (str | Unset): Comma-separated compliance frameworks Default: ''.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetRecommendationsApiV1MarketplaceRecommendationsGetResponseGetRecommendationsApiV1MarketplaceRecommendationsGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        organization_type=organization_type,
        compliance_requirements=compliance_requirements,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    organization_type: str | Unset = "general",
    compliance_requirements: str | Unset = "",
) -> (
    GetRecommendationsApiV1MarketplaceRecommendationsGetResponseGetRecommendationsApiV1MarketplaceRecommendationsGet
    | HTTPValidationError
    | None
):
    """Get Recommendations

     Get recommended marketplace content based on organization profile.

    Args:
        organization_type (str | Unset): Organization type Default: 'general'.
        compliance_requirements (str | Unset): Comma-separated compliance frameworks Default: ''.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetRecommendationsApiV1MarketplaceRecommendationsGetResponseGetRecommendationsApiV1MarketplaceRecommendationsGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        organization_type=organization_type,
        compliance_requirements=compliance_requirements,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    organization_type: str | Unset = "general",
    compliance_requirements: str | Unset = "",
) -> Response[
    GetRecommendationsApiV1MarketplaceRecommendationsGetResponseGetRecommendationsApiV1MarketplaceRecommendationsGet
    | HTTPValidationError
]:
    """Get Recommendations

     Get recommended marketplace content based on organization profile.

    Args:
        organization_type (str | Unset): Organization type Default: 'general'.
        compliance_requirements (str | Unset): Comma-separated compliance frameworks Default: ''.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetRecommendationsApiV1MarketplaceRecommendationsGetResponseGetRecommendationsApiV1MarketplaceRecommendationsGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        organization_type=organization_type,
        compliance_requirements=compliance_requirements,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    organization_type: str | Unset = "general",
    compliance_requirements: str | Unset = "",
) -> (
    GetRecommendationsApiV1MarketplaceRecommendationsGetResponseGetRecommendationsApiV1MarketplaceRecommendationsGet
    | HTTPValidationError
    | None
):
    """Get Recommendations

     Get recommended marketplace content based on organization profile.

    Args:
        organization_type (str | Unset): Organization type Default: 'general'.
        compliance_requirements (str | Unset): Comma-separated compliance frameworks Default: ''.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetRecommendationsApiV1MarketplaceRecommendationsGetResponseGetRecommendationsApiV1MarketplaceRecommendationsGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            organization_type=organization_type,
            compliance_requirements=compliance_requirements,
        )
    ).parsed
