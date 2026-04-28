from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_app_health_api_v1_integrations_apps_app_id_health_get_response_get_app_health_api_v1_integrations_apps_app_id_health_get import (
    GetAppHealthApiV1IntegrationsAppsAppIdHealthGetResponseGetAppHealthApiV1IntegrationsAppsAppIdHealthGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    app_id: str,
    *,
    org_id: None | str | Unset = UNSET,
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

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/integrations/apps/{app_id}/health".format(
            app_id=quote(str(app_id), safe=""),
        ),
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetAppHealthApiV1IntegrationsAppsAppIdHealthGetResponseGetAppHealthApiV1IntegrationsAppsAppIdHealthGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = GetAppHealthApiV1IntegrationsAppsAppIdHealthGetResponseGetAppHealthApiV1IntegrationsAppsAppIdHealthGet.from_dict(
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
    GetAppHealthApiV1IntegrationsAppsAppIdHealthGetResponseGetAppHealthApiV1IntegrationsAppsAppIdHealthGet
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    app_id: str,
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GetAppHealthApiV1IntegrationsAppsAppIdHealthGetResponseGetAppHealthApiV1IntegrationsAppsAppIdHealthGet
    | HTTPValidationError
]:
    """Check installed integration health

     Perform a lightweight health check on an installed integration.

    Validates that required configuration fields are present and the app is
    active. Returns a health report with status and details.

    Args:
        app_id (str):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetAppHealthApiV1IntegrationsAppsAppIdHealthGetResponseGetAppHealthApiV1IntegrationsAppsAppIdHealthGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        app_id=app_id,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    app_id: str,
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GetAppHealthApiV1IntegrationsAppsAppIdHealthGetResponseGetAppHealthApiV1IntegrationsAppsAppIdHealthGet
    | HTTPValidationError
    | None
):
    """Check installed integration health

     Perform a lightweight health check on an installed integration.

    Validates that required configuration fields are present and the app is
    active. Returns a health report with status and details.

    Args:
        app_id (str):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetAppHealthApiV1IntegrationsAppsAppIdHealthGetResponseGetAppHealthApiV1IntegrationsAppsAppIdHealthGet | HTTPValidationError
    """

    return sync_detailed(
        app_id=app_id,
        client=client,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    app_id: str,
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GetAppHealthApiV1IntegrationsAppsAppIdHealthGetResponseGetAppHealthApiV1IntegrationsAppsAppIdHealthGet
    | HTTPValidationError
]:
    """Check installed integration health

     Perform a lightweight health check on an installed integration.

    Validates that required configuration fields are present and the app is
    active. Returns a health report with status and details.

    Args:
        app_id (str):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetAppHealthApiV1IntegrationsAppsAppIdHealthGetResponseGetAppHealthApiV1IntegrationsAppsAppIdHealthGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        app_id=app_id,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    app_id: str,
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GetAppHealthApiV1IntegrationsAppsAppIdHealthGetResponseGetAppHealthApiV1IntegrationsAppsAppIdHealthGet
    | HTTPValidationError
    | None
):
    """Check installed integration health

     Perform a lightweight health check on an installed integration.

    Validates that required configuration fields are present and the app is
    active. Returns a health report with status and details.

    Args:
        app_id (str):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetAppHealthApiV1IntegrationsAppsAppIdHealthGetResponseGetAppHealthApiV1IntegrationsAppsAppIdHealthGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            app_id=app_id,
            client=client,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
