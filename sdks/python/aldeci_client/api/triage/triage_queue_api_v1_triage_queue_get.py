from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.triage_queue_response import TriageQueueResponse
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    include_demo: bool | Unset = False,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    params["limit"] = limit

    params["offset"] = offset

    params["include_demo"] = include_demo

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/triage/queue",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | TriageQueueResponse | None:
    if response.status_code == 200:
        response_200 = TriageQueueResponse.from_dict(response.json())

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
) -> Response[HTTPValidationError | TriageQueueResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    include_demo: bool | Unset = False,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | TriageQueueResponse]:
    """Triage Queue

     Smart triage queue.

    Returns untriaged findings ordered by a composite priority score:
        ``risk_score * (1 + sla_urgency) * (1 + attack_path_count * 0.1)``

    Findings that already have analyst feedback are excluded.  Results
    are bucketed into four groups: ``requires_immediate_action``,
    ``high_priority``, ``standard``, and ``can_wait``.

    By default, pre-seeded demo findings are excluded. Pass
    ``include_demo=true`` to show them.

    Args:
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.
        include_demo (bool | Unset): Include demo/seeded findings Default: False.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | TriageQueueResponse]
    """

    kwargs = _get_kwargs(
        limit=limit,
        offset=offset,
        include_demo=include_demo,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    include_demo: bool | Unset = False,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | TriageQueueResponse | None:
    """Triage Queue

     Smart triage queue.

    Returns untriaged findings ordered by a composite priority score:
        ``risk_score * (1 + sla_urgency) * (1 + attack_path_count * 0.1)``

    Findings that already have analyst feedback are excluded.  Results
    are bucketed into four groups: ``requires_immediate_action``,
    ``high_priority``, ``standard``, and ``can_wait``.

    By default, pre-seeded demo findings are excluded. Pass
    ``include_demo=true`` to show them.

    Args:
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.
        include_demo (bool | Unset): Include demo/seeded findings Default: False.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | TriageQueueResponse
    """

    return sync_detailed(
        client=client,
        limit=limit,
        offset=offset,
        include_demo=include_demo,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    include_demo: bool | Unset = False,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | TriageQueueResponse]:
    """Triage Queue

     Smart triage queue.

    Returns untriaged findings ordered by a composite priority score:
        ``risk_score * (1 + sla_urgency) * (1 + attack_path_count * 0.1)``

    Findings that already have analyst feedback are excluded.  Results
    are bucketed into four groups: ``requires_immediate_action``,
    ``high_priority``, ``standard``, and ``can_wait``.

    By default, pre-seeded demo findings are excluded. Pass
    ``include_demo=true`` to show them.

    Args:
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.
        include_demo (bool | Unset): Include demo/seeded findings Default: False.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | TriageQueueResponse]
    """

    kwargs = _get_kwargs(
        limit=limit,
        offset=offset,
        include_demo=include_demo,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    limit: int | Unset = 100,
    offset: int | Unset = 0,
    include_demo: bool | Unset = False,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> HTTPValidationError | TriageQueueResponse | None:
    """Triage Queue

     Smart triage queue.

    Returns untriaged findings ordered by a composite priority score:
        ``risk_score * (1 + sla_urgency) * (1 + attack_path_count * 0.1)``

    Findings that already have analyst feedback are excluded.  Results
    are bucketed into four groups: ``requires_immediate_action``,
    ``high_priority``, ``standard``, and ``can_wait``.

    By default, pre-seeded demo findings are excluded. Pass
    ``include_demo=true`` to show them.

    Args:
        limit (int | Unset):  Default: 100.
        offset (int | Unset):  Default: 0.
        include_demo (bool | Unset): Include demo/seeded findings Default: False.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | TriageQueueResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            limit=limit,
            offset=offset,
            include_demo=include_demo,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
