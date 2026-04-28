from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.browse_marketplace_api_v1_marketplace_browse_get_response_browse_marketplace_api_v1_marketplace_browse_get import (
    BrowseMarketplaceApiV1MarketplaceBrowseGetResponseBrowseMarketplaceApiV1MarketplaceBrowseGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    content_type: None | str | Unset = UNSET,
    compliance_framework: None | str | Unset = UNSET,
    ssdlc_stage: None | str | Unset = UNSET,
    pricing_model: None | str | Unset = UNSET,
    query: None | str | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_content_type: None | str | Unset
    if isinstance(content_type, Unset):
        json_content_type = UNSET
    else:
        json_content_type = content_type
    params["content_type"] = json_content_type

    json_compliance_framework: None | str | Unset
    if isinstance(compliance_framework, Unset):
        json_compliance_framework = UNSET
    else:
        json_compliance_framework = compliance_framework
    params["compliance_framework"] = json_compliance_framework

    json_ssdlc_stage: None | str | Unset
    if isinstance(ssdlc_stage, Unset):
        json_ssdlc_stage = UNSET
    else:
        json_ssdlc_stage = ssdlc_stage
    params["ssdlc_stage"] = json_ssdlc_stage

    json_pricing_model: None | str | Unset
    if isinstance(pricing_model, Unset):
        json_pricing_model = UNSET
    else:
        json_pricing_model = pricing_model
    params["pricing_model"] = json_pricing_model

    json_query: None | str | Unset
    if isinstance(query, Unset):
        json_query = UNSET
    else:
        json_query = query
    params["query"] = json_query

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/marketplace/browse",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    BrowseMarketplaceApiV1MarketplaceBrowseGetResponseBrowseMarketplaceApiV1MarketplaceBrowseGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = (
            BrowseMarketplaceApiV1MarketplaceBrowseGetResponseBrowseMarketplaceApiV1MarketplaceBrowseGet.from_dict(
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
    BrowseMarketplaceApiV1MarketplaceBrowseGetResponseBrowseMarketplaceApiV1MarketplaceBrowseGet | HTTPValidationError
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
    content_type: None | str | Unset = UNSET,
    compliance_framework: None | str | Unset = UNSET,
    ssdlc_stage: None | str | Unset = UNSET,
    pricing_model: None | str | Unset = UNSET,
    query: None | str | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    BrowseMarketplaceApiV1MarketplaceBrowseGetResponseBrowseMarketplaceApiV1MarketplaceBrowseGet | HTTPValidationError
]:
    """Browse Marketplace

     Browse and search marketplace items with optional filters.

    Args:
        content_type (None | str | Unset): Filter by content type
        compliance_framework (None | str | Unset): Filter by compliance framework
        ssdlc_stage (None | str | Unset): Filter by SSDLC stage
        pricing_model (None | str | Unset): Filter by pricing model
        query (None | str | Unset): Search query
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[BrowseMarketplaceApiV1MarketplaceBrowseGetResponseBrowseMarketplaceApiV1MarketplaceBrowseGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        content_type=content_type,
        compliance_framework=compliance_framework,
        ssdlc_stage=ssdlc_stage,
        pricing_model=pricing_model,
        query=query,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    content_type: None | str | Unset = UNSET,
    compliance_framework: None | str | Unset = UNSET,
    ssdlc_stage: None | str | Unset = UNSET,
    pricing_model: None | str | Unset = UNSET,
    query: None | str | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    BrowseMarketplaceApiV1MarketplaceBrowseGetResponseBrowseMarketplaceApiV1MarketplaceBrowseGet
    | HTTPValidationError
    | None
):
    """Browse Marketplace

     Browse and search marketplace items with optional filters.

    Args:
        content_type (None | str | Unset): Filter by content type
        compliance_framework (None | str | Unset): Filter by compliance framework
        ssdlc_stage (None | str | Unset): Filter by SSDLC stage
        pricing_model (None | str | Unset): Filter by pricing model
        query (None | str | Unset): Search query
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        BrowseMarketplaceApiV1MarketplaceBrowseGetResponseBrowseMarketplaceApiV1MarketplaceBrowseGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        content_type=content_type,
        compliance_framework=compliance_framework,
        ssdlc_stage=ssdlc_stage,
        pricing_model=pricing_model,
        query=query,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    content_type: None | str | Unset = UNSET,
    compliance_framework: None | str | Unset = UNSET,
    ssdlc_stage: None | str | Unset = UNSET,
    pricing_model: None | str | Unset = UNSET,
    query: None | str | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    BrowseMarketplaceApiV1MarketplaceBrowseGetResponseBrowseMarketplaceApiV1MarketplaceBrowseGet | HTTPValidationError
]:
    """Browse Marketplace

     Browse and search marketplace items with optional filters.

    Args:
        content_type (None | str | Unset): Filter by content type
        compliance_framework (None | str | Unset): Filter by compliance framework
        ssdlc_stage (None | str | Unset): Filter by SSDLC stage
        pricing_model (None | str | Unset): Filter by pricing model
        query (None | str | Unset): Search query
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[BrowseMarketplaceApiV1MarketplaceBrowseGetResponseBrowseMarketplaceApiV1MarketplaceBrowseGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        content_type=content_type,
        compliance_framework=compliance_framework,
        ssdlc_stage=ssdlc_stage,
        pricing_model=pricing_model,
        query=query,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    content_type: None | str | Unset = UNSET,
    compliance_framework: None | str | Unset = UNSET,
    ssdlc_stage: None | str | Unset = UNSET,
    pricing_model: None | str | Unset = UNSET,
    query: None | str | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    BrowseMarketplaceApiV1MarketplaceBrowseGetResponseBrowseMarketplaceApiV1MarketplaceBrowseGet
    | HTTPValidationError
    | None
):
    """Browse Marketplace

     Browse and search marketplace items with optional filters.

    Args:
        content_type (None | str | Unset): Filter by content type
        compliance_framework (None | str | Unset): Filter by compliance framework
        ssdlc_stage (None | str | Unset): Filter by SSDLC stage
        pricing_model (None | str | Unset): Filter by pricing model
        query (None | str | Unset): Search query
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        BrowseMarketplaceApiV1MarketplaceBrowseGetResponseBrowseMarketplaceApiV1MarketplaceBrowseGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            content_type=content_type,
            compliance_framework=compliance_framework,
            ssdlc_stage=ssdlc_stage,
            pricing_model=pricing_model,
            query=query,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
