from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.maintenance_report_response import MaintenanceReportResponse
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    org_id: str | Unset = "default",
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/trustgraph/maintenance/sweep",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | MaintenanceReportResponse | None:
    if response.status_code == 200:
        response_200 = MaintenanceReportResponse.from_dict(response.json())

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
) -> Response[HTTPValidationError | MaintenanceReportResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> Response[HTTPValidationError | MaintenanceReportResponse]:
    """Run Maintenance Sweep

     Run a full Knowledge Core integrity sweep across all 5 cores.

    Checks performed:
    - Cross-core contradiction detection (Core 2 vs Core 4 verdicts)
    - Orphaned entity detection (no relationships in any core)
    - Duplicate finding detection (same source+rule+file in Core 2)
    - Temporal staleness (entities not updated in >30 days)
    - Missing required fields (severity in Core 2 findings)
    - Entity type consistency (type matches core assignment)

    Returns:
        MaintenanceReport with all issues found and summary stats.

    Args:
        org_id (str | Unset): Organisation/tenant scope for the sweep Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | MaintenanceReportResponse]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> HTTPValidationError | MaintenanceReportResponse | None:
    """Run Maintenance Sweep

     Run a full Knowledge Core integrity sweep across all 5 cores.

    Checks performed:
    - Cross-core contradiction detection (Core 2 vs Core 4 verdicts)
    - Orphaned entity detection (no relationships in any core)
    - Duplicate finding detection (same source+rule+file in Core 2)
    - Temporal staleness (entities not updated in >30 days)
    - Missing required fields (severity in Core 2 findings)
    - Entity type consistency (type matches core assignment)

    Returns:
        MaintenanceReport with all issues found and summary stats.

    Args:
        org_id (str | Unset): Organisation/tenant scope for the sweep Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | MaintenanceReportResponse
    """

    return sync_detailed(
        client=client,
        org_id=org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> Response[HTTPValidationError | MaintenanceReportResponse]:
    """Run Maintenance Sweep

     Run a full Knowledge Core integrity sweep across all 5 cores.

    Checks performed:
    - Cross-core contradiction detection (Core 2 vs Core 4 verdicts)
    - Orphaned entity detection (no relationships in any core)
    - Duplicate finding detection (same source+rule+file in Core 2)
    - Temporal staleness (entities not updated in >30 days)
    - Missing required fields (severity in Core 2 findings)
    - Entity type consistency (type matches core assignment)

    Returns:
        MaintenanceReport with all issues found and summary stats.

    Args:
        org_id (str | Unset): Organisation/tenant scope for the sweep Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | MaintenanceReportResponse]
    """

    kwargs = _get_kwargs(
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> HTTPValidationError | MaintenanceReportResponse | None:
    """Run Maintenance Sweep

     Run a full Knowledge Core integrity sweep across all 5 cores.

    Checks performed:
    - Cross-core contradiction detection (Core 2 vs Core 4 verdicts)
    - Orphaned entity detection (no relationships in any core)
    - Duplicate finding detection (same source+rule+file in Core 2)
    - Temporal staleness (entities not updated in >30 days)
    - Missing required fields (severity in Core 2 findings)
    - Entity type consistency (type matches core assignment)

    Returns:
        MaintenanceReport with all issues found and summary stats.

    Args:
        org_id (str | Unset): Organisation/tenant scope for the sweep Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | MaintenanceReportResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            org_id=org_id,
        )
    ).parsed
