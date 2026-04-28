from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.copilot_traversal_trace_api_v1_copilot_q_id_traversal_trace_get_response_copilot_traversal_trace_api_v1_copilot_q_id_traversal_trace_get import (
    CopilotTraversalTraceApiV1CopilotQIdTraversalTraceGetResponseCopilotTraversalTraceApiV1CopilotQIdTraversalTraceGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    q_id: str,
    *,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/copilot/{q_id}/traversal-trace".format(
            q_id=quote(str(q_id), safe=""),
        ),
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    CopilotTraversalTraceApiV1CopilotQIdTraversalTraceGetResponseCopilotTraversalTraceApiV1CopilotQIdTraversalTraceGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = CopilotTraversalTraceApiV1CopilotQIdTraversalTraceGetResponseCopilotTraversalTraceApiV1CopilotQIdTraversalTraceGet.from_dict(
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
    CopilotTraversalTraceApiV1CopilotQIdTraversalTraceGetResponseCopilotTraversalTraceApiV1CopilotQIdTraversalTraceGet
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    q_id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    CopilotTraversalTraceApiV1CopilotQIdTraversalTraceGetResponseCopilotTraversalTraceApiV1CopilotQIdTraversalTraceGet
    | HTTPValidationError
]:
    """Copilot Traversal Trace

     Return the traversal trace for a previous Copilot query. (Multica 3d7e5388)

    Args:
        q_id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CopilotTraversalTraceApiV1CopilotQIdTraversalTraceGetResponseCopilotTraversalTraceApiV1CopilotQIdTraversalTraceGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        q_id=q_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    q_id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> (
    CopilotTraversalTraceApiV1CopilotQIdTraversalTraceGetResponseCopilotTraversalTraceApiV1CopilotQIdTraversalTraceGet
    | HTTPValidationError
    | None
):
    """Copilot Traversal Trace

     Return the traversal trace for a previous Copilot query. (Multica 3d7e5388)

    Args:
        q_id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CopilotTraversalTraceApiV1CopilotQIdTraversalTraceGetResponseCopilotTraversalTraceApiV1CopilotQIdTraversalTraceGet | HTTPValidationError
    """

    return sync_detailed(
        q_id=q_id,
        client=client,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    q_id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    CopilotTraversalTraceApiV1CopilotQIdTraversalTraceGetResponseCopilotTraversalTraceApiV1CopilotQIdTraversalTraceGet
    | HTTPValidationError
]:
    """Copilot Traversal Trace

     Return the traversal trace for a previous Copilot query. (Multica 3d7e5388)

    Args:
        q_id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CopilotTraversalTraceApiV1CopilotQIdTraversalTraceGetResponseCopilotTraversalTraceApiV1CopilotQIdTraversalTraceGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        q_id=q_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    q_id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> (
    CopilotTraversalTraceApiV1CopilotQIdTraversalTraceGetResponseCopilotTraversalTraceApiV1CopilotQIdTraversalTraceGet
    | HTTPValidationError
    | None
):
    """Copilot Traversal Trace

     Return the traversal trace for a previous Copilot query. (Multica 3d7e5388)

    Args:
        q_id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CopilotTraversalTraceApiV1CopilotQIdTraversalTraceGetResponseCopilotTraversalTraceApiV1CopilotQIdTraversalTraceGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            q_id=q_id,
            client=client,
            x_org_id=x_org_id,
        )
    ).parsed
