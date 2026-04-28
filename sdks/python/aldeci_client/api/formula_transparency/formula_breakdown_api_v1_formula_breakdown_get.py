from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.formula_breakdown_api_v1_formula_breakdown_get_response_formula_breakdown_api_v1_formula_breakdown_get import (
    FormulaBreakdownApiV1FormulaBreakdownGetResponseFormulaBreakdownApiV1FormulaBreakdownGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    org_id: None | str | Unset = UNSET,
    finding_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    json_finding_id: None | str | Unset
    if isinstance(finding_id, Unset):
        json_finding_id = UNSET
    else:
        json_finding_id = finding_id
    params["finding_id"] = json_finding_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/formula/breakdown",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    FormulaBreakdownApiV1FormulaBreakdownGetResponseFormulaBreakdownApiV1FormulaBreakdownGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = (
            FormulaBreakdownApiV1FormulaBreakdownGetResponseFormulaBreakdownApiV1FormulaBreakdownGet.from_dict(
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
    FormulaBreakdownApiV1FormulaBreakdownGetResponseFormulaBreakdownApiV1FormulaBreakdownGet | HTTPValidationError
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
    org_id: None | str | Unset = UNSET,
    finding_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    FormulaBreakdownApiV1FormulaBreakdownGetResponseFormulaBreakdownApiV1FormulaBreakdownGet | HTTPValidationError
]:
    """GAP-043: Return full scoring formula transparency

    Args:
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        finding_id (None | str | Unset): Optional finding id for contributor values
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[FormulaBreakdownApiV1FormulaBreakdownGetResponseFormulaBreakdownApiV1FormulaBreakdownGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        finding_id=finding_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    finding_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    FormulaBreakdownApiV1FormulaBreakdownGetResponseFormulaBreakdownApiV1FormulaBreakdownGet
    | HTTPValidationError
    | None
):
    """GAP-043: Return full scoring formula transparency

    Args:
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        finding_id (None | str | Unset): Optional finding id for contributor values
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        FormulaBreakdownApiV1FormulaBreakdownGetResponseFormulaBreakdownApiV1FormulaBreakdownGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        org_id=org_id,
        finding_id=finding_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    finding_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    FormulaBreakdownApiV1FormulaBreakdownGetResponseFormulaBreakdownApiV1FormulaBreakdownGet | HTTPValidationError
]:
    """GAP-043: Return full scoring formula transparency

    Args:
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        finding_id (None | str | Unset): Optional finding id for contributor values
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[FormulaBreakdownApiV1FormulaBreakdownGetResponseFormulaBreakdownApiV1FormulaBreakdownGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
        finding_id=finding_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    finding_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    FormulaBreakdownApiV1FormulaBreakdownGetResponseFormulaBreakdownApiV1FormulaBreakdownGet
    | HTTPValidationError
    | None
):
    """GAP-043: Return full scoring formula transparency

    Args:
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        finding_id (None | str | Unset): Optional finding id for contributor values
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        FormulaBreakdownApiV1FormulaBreakdownGetResponseFormulaBreakdownApiV1FormulaBreakdownGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            org_id=org_id,
            finding_id=finding_id,
            x_org_id=x_org_id,
        )
    ).parsed
