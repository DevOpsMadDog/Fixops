from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    scanner_type: str,
    *,
    app_id: str | Unset = "",
    component: str | Unset = "",
    pipeline: bool | Unset = False,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    params["app_id"] = app_id

    params["component"] = component

    params["pipeline"] = pipeline

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/scanner-ingest/webhook/{scanner_type}".format(
            scanner_type=quote(str(scanner_type), safe=""),
        ),
        "params": params,
    }

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
    scanner_type: str,
    *,
    client: AuthenticatedClient,
    app_id: str | Unset = "",
    component: str | Unset = "",
    pipeline: bool | Unset = False,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[Any | HTTPValidationError]:
    r""" Webhook Ingest

     Receive scanner output via webhook (raw body).

    Set up your CI/CD to POST scanner output directly:
      curl -X POST https://aldeci/api/v1/scanner-ingest/webhook/zap \
        -H \"X-API-Key: $KEY\" \
        -H \"Content-Type: application/json\" \
        --data-binary @zap-report.json

    Args:
        scanner_type (str):
        app_id (str | Unset):  Default: ''.
        component (str | Unset):  Default: ''.
        pipeline (bool | Unset):  Default: False.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
     """

    kwargs = _get_kwargs(
        scanner_type=scanner_type,
        app_id=app_id,
        component=component,
        pipeline=pipeline,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    scanner_type: str,
    *,
    client: AuthenticatedClient,
    app_id: str | Unset = "",
    component: str | Unset = "",
    pipeline: bool | Unset = False,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Any | HTTPValidationError | None:
    r""" Webhook Ingest

     Receive scanner output via webhook (raw body).

    Set up your CI/CD to POST scanner output directly:
      curl -X POST https://aldeci/api/v1/scanner-ingest/webhook/zap \
        -H \"X-API-Key: $KEY\" \
        -H \"Content-Type: application/json\" \
        --data-binary @zap-report.json

    Args:
        scanner_type (str):
        app_id (str | Unset):  Default: ''.
        component (str | Unset):  Default: ''.
        pipeline (bool | Unset):  Default: False.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
     """

    return sync_detailed(
        scanner_type=scanner_type,
        client=client,
        app_id=app_id,
        component=component,
        pipeline=pipeline,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    scanner_type: str,
    *,
    client: AuthenticatedClient,
    app_id: str | Unset = "",
    component: str | Unset = "",
    pipeline: bool | Unset = False,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[Any | HTTPValidationError]:
    r""" Webhook Ingest

     Receive scanner output via webhook (raw body).

    Set up your CI/CD to POST scanner output directly:
      curl -X POST https://aldeci/api/v1/scanner-ingest/webhook/zap \
        -H \"X-API-Key: $KEY\" \
        -H \"Content-Type: application/json\" \
        --data-binary @zap-report.json

    Args:
        scanner_type (str):
        app_id (str | Unset):  Default: ''.
        component (str | Unset):  Default: ''.
        pipeline (bool | Unset):  Default: False.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | HTTPValidationError]
     """

    kwargs = _get_kwargs(
        scanner_type=scanner_type,
        app_id=app_id,
        component=component,
        pipeline=pipeline,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    scanner_type: str,
    *,
    client: AuthenticatedClient,
    app_id: str | Unset = "",
    component: str | Unset = "",
    pipeline: bool | Unset = False,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Any | HTTPValidationError | None:
    r""" Webhook Ingest

     Receive scanner output via webhook (raw body).

    Set up your CI/CD to POST scanner output directly:
      curl -X POST https://aldeci/api/v1/scanner-ingest/webhook/zap \
        -H \"X-API-Key: $KEY\" \
        -H \"Content-Type: application/json\" \
        --data-binary @zap-report.json

    Args:
        scanner_type (str):
        app_id (str | Unset):  Default: ''.
        component (str | Unset):  Default: ''.
        pipeline (bool | Unset):  Default: False.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | HTTPValidationError
     """

    return (
        await asyncio_detailed(
            scanner_type=scanner_type,
            client=client,
            app_id=app_id,
            component=component,
            pipeline=pipeline,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
