from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.runtime_map_to_code_api_v1_runtime_map_to_code_post_response_runtime_map_to_code_api_v1_runtime_map_to_code_post import (
    RuntimeMapToCodeApiV1RuntimeMapToCodePostResponseRuntimeMapToCodeApiV1RuntimeMapToCodePost,
)
from ...models.runtime_map_to_code_request import RuntimeMapToCodeRequest
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: RuntimeMapToCodeRequest,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/runtime/map-to-code",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | RuntimeMapToCodeApiV1RuntimeMapToCodePostResponseRuntimeMapToCodeApiV1RuntimeMapToCodePost
    | None
):
    if response.status_code == 200:
        response_200 = (
            RuntimeMapToCodeApiV1RuntimeMapToCodePostResponseRuntimeMapToCodeApiV1RuntimeMapToCodePost.from_dict(
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
    HTTPValidationError | RuntimeMapToCodeApiV1RuntimeMapToCodePostResponseRuntimeMapToCodeApiV1RuntimeMapToCodePost
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
    body: RuntimeMapToCodeRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError | RuntimeMapToCodeApiV1RuntimeMapToCodePostResponseRuntimeMapToCodeApiV1RuntimeMapToCodePost
]:
    """Map a runtime telemetry event to source code locations

     Resolve a runtime event/stack-trace to candidate code locations.

    Wraps ``CodeToRuntimeMatcherEngine.match_event_to_code`` when an event id
    is provided; otherwise ingests the supplied stack trace and matches it.

    Args:
        x_org_id (None | str | Unset):
        body (RuntimeMapToCodeRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RuntimeMapToCodeApiV1RuntimeMapToCodePostResponseRuntimeMapToCodeApiV1RuntimeMapToCodePost]
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
    body: RuntimeMapToCodeRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | RuntimeMapToCodeApiV1RuntimeMapToCodePostResponseRuntimeMapToCodeApiV1RuntimeMapToCodePost
    | None
):
    """Map a runtime telemetry event to source code locations

     Resolve a runtime event/stack-trace to candidate code locations.

    Wraps ``CodeToRuntimeMatcherEngine.match_event_to_code`` when an event id
    is provided; otherwise ingests the supplied stack trace and matches it.

    Args:
        x_org_id (None | str | Unset):
        body (RuntimeMapToCodeRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RuntimeMapToCodeApiV1RuntimeMapToCodePostResponseRuntimeMapToCodeApiV1RuntimeMapToCodePost
    """

    return sync_detailed(
        client=client,
        body=body,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: RuntimeMapToCodeRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError | RuntimeMapToCodeApiV1RuntimeMapToCodePostResponseRuntimeMapToCodeApiV1RuntimeMapToCodePost
]:
    """Map a runtime telemetry event to source code locations

     Resolve a runtime event/stack-trace to candidate code locations.

    Wraps ``CodeToRuntimeMatcherEngine.match_event_to_code`` when an event id
    is provided; otherwise ingests the supplied stack trace and matches it.

    Args:
        x_org_id (None | str | Unset):
        body (RuntimeMapToCodeRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RuntimeMapToCodeApiV1RuntimeMapToCodePostResponseRuntimeMapToCodeApiV1RuntimeMapToCodePost]
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
    body: RuntimeMapToCodeRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | RuntimeMapToCodeApiV1RuntimeMapToCodePostResponseRuntimeMapToCodeApiV1RuntimeMapToCodePost
    | None
):
    """Map a runtime telemetry event to source code locations

     Resolve a runtime event/stack-trace to candidate code locations.

    Wraps ``CodeToRuntimeMatcherEngine.match_event_to_code`` when an event id
    is provided; otherwise ingests the supplied stack trace and matches it.

    Args:
        x_org_id (None | str | Unset):
        body (RuntimeMapToCodeRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RuntimeMapToCodeApiV1RuntimeMapToCodePostResponseRuntimeMapToCodeApiV1RuntimeMapToCodePost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            x_org_id=x_org_id,
        )
    ).parsed
