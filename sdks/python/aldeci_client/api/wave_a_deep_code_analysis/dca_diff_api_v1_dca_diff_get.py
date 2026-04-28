from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.dca_diff_api_v1_dca_diff_get_response_dca_diff_api_v1_dca_diff_get import (
    DcaDiffApiV1DcaDiffGetResponseDcaDiffApiV1DcaDiffGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    repo: str,
    from_: str,
    to: str,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    params["repo"] = repo

    params["from"] = from_

    params["to"] = to

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/dca/diff",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> DcaDiffApiV1DcaDiffGetResponseDcaDiffApiV1DcaDiffGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = DcaDiffApiV1DcaDiffGetResponseDcaDiffApiV1DcaDiffGet.from_dict(response.json())

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
) -> Response[DcaDiffApiV1DcaDiffGetResponseDcaDiffApiV1DcaDiffGet | HTTPValidationError]:
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
    from_: str,
    to: str,
    x_org_id: None | str | Unset = UNSET,
) -> Response[DcaDiffApiV1DcaDiffGetResponseDcaDiffApiV1DcaDiffGet | HTTPValidationError]:
    """Diff DCA entity sets between two parse runs

     Diff entity sets between two parse runs (`from` → `to` revisions).

    Args:
        repo (str):
        from_ (str):
        to (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DcaDiffApiV1DcaDiffGetResponseDcaDiffApiV1DcaDiffGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        repo=repo,
        from_=from_,
        to=to,
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
    from_: str,
    to: str,
    x_org_id: None | str | Unset = UNSET,
) -> DcaDiffApiV1DcaDiffGetResponseDcaDiffApiV1DcaDiffGet | HTTPValidationError | None:
    """Diff DCA entity sets between two parse runs

     Diff entity sets between two parse runs (`from` → `to` revisions).

    Args:
        repo (str):
        from_ (str):
        to (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DcaDiffApiV1DcaDiffGetResponseDcaDiffApiV1DcaDiffGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        repo=repo,
        from_=from_,
        to=to,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    repo: str,
    from_: str,
    to: str,
    x_org_id: None | str | Unset = UNSET,
) -> Response[DcaDiffApiV1DcaDiffGetResponseDcaDiffApiV1DcaDiffGet | HTTPValidationError]:
    """Diff DCA entity sets between two parse runs

     Diff entity sets between two parse runs (`from` → `to` revisions).

    Args:
        repo (str):
        from_ (str):
        to (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DcaDiffApiV1DcaDiffGetResponseDcaDiffApiV1DcaDiffGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        repo=repo,
        from_=from_,
        to=to,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    repo: str,
    from_: str,
    to: str,
    x_org_id: None | str | Unset = UNSET,
) -> DcaDiffApiV1DcaDiffGetResponseDcaDiffApiV1DcaDiffGet | HTTPValidationError | None:
    """Diff DCA entity sets between two parse runs

     Diff entity sets between two parse runs (`from` → `to` revisions).

    Args:
        repo (str):
        from_ (str):
        to (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DcaDiffApiV1DcaDiffGetResponseDcaDiffApiV1DcaDiffGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            repo=repo,
            from_=from_,
            to=to,
            x_org_id=x_org_id,
        )
    ).parsed
