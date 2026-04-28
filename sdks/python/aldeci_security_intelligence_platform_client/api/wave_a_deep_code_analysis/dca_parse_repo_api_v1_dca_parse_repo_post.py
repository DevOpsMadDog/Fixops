from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.dca_parse_repo_api_v1_dca_parse_repo_post_response_dca_parse_repo_api_v1_dca_parse_repo_post import (
    DcaParseRepoApiV1DcaParseRepoPostResponseDcaParseRepoApiV1DcaParseRepoPost,
)
from ...models.dca_parse_repo_request import DCAParseRepoRequest
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: DCAParseRepoRequest,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/dca/parse-repo",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> DcaParseRepoApiV1DcaParseRepoPostResponseDcaParseRepoApiV1DcaParseRepoPost | HTTPValidationError | None:
    if response.status_code == 201:
        response_201 = DcaParseRepoApiV1DcaParseRepoPostResponseDcaParseRepoApiV1DcaParseRepoPost.from_dict(
            response.json()
        )

        return response_201

    if response.status_code == 422:
        response_422 = HTTPValidationError.from_dict(response.json())

        return response_422

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[DcaParseRepoApiV1DcaParseRepoPostResponseDcaParseRepoApiV1DcaParseRepoPost | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: DCAParseRepoRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[DcaParseRepoApiV1DcaParseRepoPostResponseDcaParseRepoApiV1DcaParseRepoPost | HTTPValidationError]:
    """Run Deep Code Analysis (DCA) on a repository

     Parse a repository into entities (functions, classes, modules).

    Uses the AST parser inside ``function_reachability_engine.parse_python_repo``
    when the repo is local + Python; otherwise records a parse-request that
    a worker can pick up later.

    Args:
        x_org_id (None | str | Unset):
        body (DCAParseRepoRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DcaParseRepoApiV1DcaParseRepoPostResponseDcaParseRepoApiV1DcaParseRepoPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: DCAParseRepoRequest,
    x_org_id: None | str | Unset = UNSET,
) -> DcaParseRepoApiV1DcaParseRepoPostResponseDcaParseRepoApiV1DcaParseRepoPost | HTTPValidationError | None:
    """Run Deep Code Analysis (DCA) on a repository

     Parse a repository into entities (functions, classes, modules).

    Uses the AST parser inside ``function_reachability_engine.parse_python_repo``
    when the repo is local + Python; otherwise records a parse-request that
    a worker can pick up later.

    Args:
        x_org_id (None | str | Unset):
        body (DCAParseRepoRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DcaParseRepoApiV1DcaParseRepoPostResponseDcaParseRepoApiV1DcaParseRepoPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: DCAParseRepoRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[DcaParseRepoApiV1DcaParseRepoPostResponseDcaParseRepoApiV1DcaParseRepoPost | HTTPValidationError]:
    """Run Deep Code Analysis (DCA) on a repository

     Parse a repository into entities (functions, classes, modules).

    Uses the AST parser inside ``function_reachability_engine.parse_python_repo``
    when the repo is local + Python; otherwise records a parse-request that
    a worker can pick up later.

    Args:
        x_org_id (None | str | Unset):
        body (DCAParseRepoRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DcaParseRepoApiV1DcaParseRepoPostResponseDcaParseRepoApiV1DcaParseRepoPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: DCAParseRepoRequest,
    x_org_id: None | str | Unset = UNSET,
) -> DcaParseRepoApiV1DcaParseRepoPostResponseDcaParseRepoApiV1DcaParseRepoPost | HTTPValidationError | None:
    """Run Deep Code Analysis (DCA) on a repository

     Parse a repository into entities (functions, classes, modules).

    Uses the AST parser inside ``function_reachability_engine.parse_python_repo``
    when the repo is local + Python; otherwise records a parse-request that
    a worker can pick up later.

    Args:
        x_org_id (None | str | Unset):
        body (DCAParseRepoRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DcaParseRepoApiV1DcaParseRepoPostResponseDcaParseRepoApiV1DcaParseRepoPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            x_org_id=x_org_id,
        )
    ).parsed
