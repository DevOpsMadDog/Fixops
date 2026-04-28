from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/servicenow-sync/webhooks",
    }

    return _kwargs


def _parse_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Any | None:
    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(*, client: AuthenticatedClient | Client, response: httpx.Response) -> Response[Any]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[Any]:
    """Receive ServiceNow webhook events

     Receive and process ServiceNow webhook ``POST`` callbacks.

    ServiceNow Business Rules or Flow Designer POST a JSON payload for every
    incident event (insert, update, delete). The engine translates the
    ServiceNow state into an ALDECI finding status and records the event in
    sync history.

    Expected payload keys:
      - ``sys_id``        — ServiceNow sys_id of the incident
      - ``number``        — incident number (e.g. INC0010042)
      - ``state``         — state code (1=New, 2=In Progress, 6=Resolved, 7=Closed)
      - ``table_name``    — should be ``incident``
      - ``action``        — ``insert`` | ``update`` | ``delete``
      - ``sys_updated_on``— ISO timestamp of the last update

    If ``webhook_secret`` is configured the engine validates it against the
    ``X-ServiceNow-Webhook-Secret`` request header.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


async def asyncio_detailed(
    *,
    client: AuthenticatedClient | Client,
) -> Response[Any]:
    """Receive ServiceNow webhook events

     Receive and process ServiceNow webhook ``POST`` callbacks.

    ServiceNow Business Rules or Flow Designer POST a JSON payload for every
    incident event (insert, update, delete). The engine translates the
    ServiceNow state into an ALDECI finding status and records the event in
    sync history.

    Expected payload keys:
      - ``sys_id``        — ServiceNow sys_id of the incident
      - ``number``        — incident number (e.g. INC0010042)
      - ``state``         — state code (1=New, 2=In Progress, 6=Resolved, 7=Closed)
      - ``table_name``    — should be ``incident``
      - ``action``        — ``insert`` | ``update`` | ``delete``
      - ``sys_updated_on``— ISO timestamp of the last update

    If ``webhook_secret`` is configured the engine validates it against the
    ``X-ServiceNow-Webhook-Secret`` request header.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)
