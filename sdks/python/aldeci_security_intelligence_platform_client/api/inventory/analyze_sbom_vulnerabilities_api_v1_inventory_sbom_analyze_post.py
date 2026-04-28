from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.analyze_sbom_vulnerabilities_api_v1_inventory_sbom_analyze_post_sbom_data import (
    AnalyzeSbomVulnerabilitiesApiV1InventorySbomAnalyzePostSbomData,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: AnalyzeSbomVulnerabilitiesApiV1InventorySbomAnalyzePostSbomData,
    app_id: str,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    params: dict[str, Any] = {}

    params["app_id"] = app_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/inventory/sbom/analyze",
        "params": params,
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = response.json()
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
) -> Response[Any | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: AnalyzeSbomVulnerabilitiesApiV1InventorySbomAnalyzePostSbomData,
    app_id: str,
) -> Response[Any | HTTPValidationError]:
    """Analyze Sbom Vulnerabilities

     Analyze an SBOM for known vulnerabilities and generate a VEX document.

    Accepts CycloneDX or SPDX format. Cross-references all components against
    the embedded vulnerability database, returns findings with severity
    breakdown and auto-generates an OpenVEX companion document.

    Args:
        app_id (str):
        body (AnalyzeSbomVulnerabilitiesApiV1InventorySbomAnalyzePostSbomData):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
        app_id=app_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: AnalyzeSbomVulnerabilitiesApiV1InventorySbomAnalyzePostSbomData,
    app_id: str,
) -> Any | HTTPValidationError | None:
    """Analyze Sbom Vulnerabilities

     Analyze an SBOM for known vulnerabilities and generate a VEX document.

    Accepts CycloneDX or SPDX format. Cross-references all components against
    the embedded vulnerability database, returns findings with severity
    breakdown and auto-generates an OpenVEX companion document.

    Args:
        app_id (str):
        body (AnalyzeSbomVulnerabilitiesApiV1InventorySbomAnalyzePostSbomData):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
        app_id=app_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: AnalyzeSbomVulnerabilitiesApiV1InventorySbomAnalyzePostSbomData,
    app_id: str,
) -> Response[Any | HTTPValidationError]:
    """Analyze Sbom Vulnerabilities

     Analyze an SBOM for known vulnerabilities and generate a VEX document.

    Accepts CycloneDX or SPDX format. Cross-references all components against
    the embedded vulnerability database, returns findings with severity
    breakdown and auto-generates an OpenVEX companion document.

    Args:
        app_id (str):
        body (AnalyzeSbomVulnerabilitiesApiV1InventorySbomAnalyzePostSbomData):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
        app_id=app_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: AnalyzeSbomVulnerabilitiesApiV1InventorySbomAnalyzePostSbomData,
    app_id: str,
) -> Any | HTTPValidationError | None:
    """Analyze Sbom Vulnerabilities

     Analyze an SBOM for known vulnerabilities and generate a VEX document.

    Accepts CycloneDX or SPDX format. Cross-references all components against
    the embedded vulnerability database, returns findings with severity
    breakdown and auto-generates an OpenVEX companion document.

    Args:
        app_id (str):
        body (AnalyzeSbomVulnerabilitiesApiV1InventorySbomAnalyzePostSbomData):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            app_id=app_id,
        )
    ).parsed
