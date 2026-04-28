from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.soar_execution import SOARExecution
from ...models.trigger_event_request import TriggerEventRequest
from ...types import Response


def _get_kwargs(
    *,
    body: TriggerEventRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/soar/trigger",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[SOARExecution] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = SOARExecution.from_dict(response_200_item_data)

            response_200.append(response_200_item)

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
) -> Response[HTTPValidationError | list[SOARExecution]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: TriggerEventRequest,
) -> Response[HTTPValidationError | list[SOARExecution]]:
    """Evaluate an event and fire matching playbooks

     Submit a security event for automated response.

    Matches the event against all enabled playbooks with the given trigger type
    and condition set. Returns execution records for every playbook that fired.

    Args:
        body (TriggerEventRequest): Body for evaluating an incoming security event against
            playbooks.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[SOARExecution]]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: TriggerEventRequest,
) -> HTTPValidationError | list[SOARExecution] | None:
    """Evaluate an event and fire matching playbooks

     Submit a security event for automated response.

    Matches the event against all enabled playbooks with the given trigger type
    and condition set. Returns execution records for every playbook that fired.

    Args:
        body (TriggerEventRequest): Body for evaluating an incoming security event against
            playbooks.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[SOARExecution]
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: TriggerEventRequest,
) -> Response[HTTPValidationError | list[SOARExecution]]:
    """Evaluate an event and fire matching playbooks

     Submit a security event for automated response.

    Matches the event against all enabled playbooks with the given trigger type
    and condition set. Returns execution records for every playbook that fired.

    Args:
        body (TriggerEventRequest): Body for evaluating an incoming security event against
            playbooks.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[SOARExecution]]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: TriggerEventRequest,
) -> HTTPValidationError | list[SOARExecution] | None:
    """Evaluate an event and fire matching playbooks

     Submit a security event for automated response.

    Matches the event against all enabled playbooks with the given trigger type
    and condition set. Returns execution records for every playbook that fired.

    Args:
        body (TriggerEventRequest): Body for evaluating an incoming security event against
            playbooks.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[SOARExecution]
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
