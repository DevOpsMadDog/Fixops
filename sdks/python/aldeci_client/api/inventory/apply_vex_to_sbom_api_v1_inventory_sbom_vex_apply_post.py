from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.body_apply_vex_to_sbom_api_v1_inventory_sbom_vex_apply_post import (
    BodyApplyVexToSbomApiV1InventorySbomVexApplyPost,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: BodyApplyVexToSbomApiV1InventorySbomVexApplyPost,
    app_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    params: dict[str, Any] = {}

    json_app_id: None | str | Unset
    if isinstance(app_id, Unset):
        json_app_id = UNSET
    else:
        json_app_id = app_id
    params["app_id"] = json_app_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/inventory/sbom/vex/apply",
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
    body: BodyApplyVexToSbomApiV1InventorySbomVexApplyPost,
    app_id: None | str | Unset = UNSET,
) -> Response[Any | HTTPValidationError]:
    """Apply Vex To Sbom

     Apply VEX status to an SBOM, enriching components with exploitability info.

    If no vex_data is provided, uses the stored VEX document for the app_id.
    Returns the SBOM with vulnerability status annotations on each component.

    Args:
        app_id (None | str | Unset):
        body (BodyApplyVexToSbomApiV1InventorySbomVexApplyPost):

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
    body: BodyApplyVexToSbomApiV1InventorySbomVexApplyPost,
    app_id: None | str | Unset = UNSET,
) -> Any | HTTPValidationError | None:
    """Apply Vex To Sbom

     Apply VEX status to an SBOM, enriching components with exploitability info.

    If no vex_data is provided, uses the stored VEX document for the app_id.
    Returns the SBOM with vulnerability status annotations on each component.

    Args:
        app_id (None | str | Unset):
        body (BodyApplyVexToSbomApiV1InventorySbomVexApplyPost):

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
    body: BodyApplyVexToSbomApiV1InventorySbomVexApplyPost,
    app_id: None | str | Unset = UNSET,
) -> Response[Any | HTTPValidationError]:
    """Apply Vex To Sbom

     Apply VEX status to an SBOM, enriching components with exploitability info.

    If no vex_data is provided, uses the stored VEX document for the app_id.
    Returns the SBOM with vulnerability status annotations on each component.

    Args:
        app_id (None | str | Unset):
        body (BodyApplyVexToSbomApiV1InventorySbomVexApplyPost):

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
    body: BodyApplyVexToSbomApiV1InventorySbomVexApplyPost,
    app_id: None | str | Unset = UNSET,
) -> Any | HTTPValidationError | None:
    """Apply Vex To Sbom

     Apply VEX status to an SBOM, enriching components with exploitability info.

    If no vex_data is provided, uses the stored VEX document for the app_id.
    Returns the SBOM with vulnerability status annotations on each component.

    Args:
        app_id (None | str | Unset):
        body (BodyApplyVexToSbomApiV1InventorySbomVexApplyPost):

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
