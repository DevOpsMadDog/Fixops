from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.ide_findings_api_v1_ide_findings_get_response_ide_findings_api_v1_ide_findings_get import (
    IdeFindingsApiV1IdeFindingsGetResponseIdeFindingsApiV1IdeFindingsGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    repo: str,
    file: str,
    severity: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    params["repo"] = repo

    params["file"] = file

    json_severity: None | str | Unset
    if isinstance(severity, Unset):
        json_severity = UNSET
    else:
        json_severity = severity
    params["severity"] = json_severity

    params["limit"] = limit

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/ide/findings",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | IdeFindingsApiV1IdeFindingsGetResponseIdeFindingsApiV1IdeFindingsGet | None:
    if response.status_code == 200:
        response_200 = IdeFindingsApiV1IdeFindingsGetResponseIdeFindingsApiV1IdeFindingsGet.from_dict(response.json())

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
) -> Response[HTTPValidationError | IdeFindingsApiV1IdeFindingsGetResponseIdeFindingsApiV1IdeFindingsGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    repo: str,
    file: str,
    severity: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | IdeFindingsApiV1IdeFindingsGetResponseIdeFindingsApiV1IdeFindingsGet]:
    """List IDE-relevant findings filtered by repo+file

     Return findings scoped to a (repo, file) pair for IDE in-line overlay.

    Args:
        repo (str):
        file (str):
        severity (None | str | Unset):
        limit (int | Unset):  Default: 100.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | IdeFindingsApiV1IdeFindingsGetResponseIdeFindingsApiV1IdeFindingsGet]
    """

    kwargs = _get_kwargs(
        repo=repo,
        file=file,
        severity=severity,
        limit=limit,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    repo: str,
    file: str,
    severity: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | IdeFindingsApiV1IdeFindingsGetResponseIdeFindingsApiV1IdeFindingsGet | None:
    """List IDE-relevant findings filtered by repo+file

     Return findings scoped to a (repo, file) pair for IDE in-line overlay.

    Args:
        repo (str):
        file (str):
        severity (None | str | Unset):
        limit (int | Unset):  Default: 100.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | IdeFindingsApiV1IdeFindingsGetResponseIdeFindingsApiV1IdeFindingsGet
    """

    return sync_detailed(
        client=client,
        repo=repo,
        file=file,
        severity=severity,
        limit=limit,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    repo: str,
    file: str,
    severity: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | IdeFindingsApiV1IdeFindingsGetResponseIdeFindingsApiV1IdeFindingsGet]:
    """List IDE-relevant findings filtered by repo+file

     Return findings scoped to a (repo, file) pair for IDE in-line overlay.

    Args:
        repo (str):
        file (str):
        severity (None | str | Unset):
        limit (int | Unset):  Default: 100.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | IdeFindingsApiV1IdeFindingsGetResponseIdeFindingsApiV1IdeFindingsGet]
    """

    kwargs = _get_kwargs(
        repo=repo,
        file=file,
        severity=severity,
        limit=limit,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    repo: str,
    file: str,
    severity: None | str | Unset = UNSET,
    limit: int | Unset = 100,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | IdeFindingsApiV1IdeFindingsGetResponseIdeFindingsApiV1IdeFindingsGet | None:
    """List IDE-relevant findings filtered by repo+file

     Return findings scoped to a (repo, file) pair for IDE in-line overlay.

    Args:
        repo (str):
        file (str):
        severity (None | str | Unset):
        limit (int | Unset):  Default: 100.
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | IdeFindingsApiV1IdeFindingsGetResponseIdeFindingsApiV1IdeFindingsGet
    """

    return (
        await asyncio_detailed(
            client=client,
            repo=repo,
            file=file,
            severity=severity,
            limit=limit,
            x_org_id=x_org_id,
        )
    ).parsed
