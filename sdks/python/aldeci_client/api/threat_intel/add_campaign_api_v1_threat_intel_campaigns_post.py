from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.campaign import Campaign
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    *,
    body: Campaign,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/threat-intel/campaigns",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Campaign | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = Campaign.from_dict(response.json())

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
) -> Response[Campaign | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: Campaign,
) -> Response[Campaign | HTTPValidationError]:
    """Add Campaign

     Register a new threat campaign. Upserts on duplicate ID.

    Args:
        body (Campaign): Threat campaign linking actors to a coordinated attack effort.

            Attributes:
                id: Unique campaign identifier
                name: Campaign name
                threat_actor_id: ID of the responsible threat actor
                start_date: Campaign start date (ISO 8601)
                status: "active", "concluded", or "suspected"
                targets: Target sectors or org names
                iocs: Campaign-specific IOCs
                ttps: TTPs observed in this campaign

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Campaign | HTTPValidationError]
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
    body: Campaign,
) -> Campaign | HTTPValidationError | None:
    """Add Campaign

     Register a new threat campaign. Upserts on duplicate ID.

    Args:
        body (Campaign): Threat campaign linking actors to a coordinated attack effort.

            Attributes:
                id: Unique campaign identifier
                name: Campaign name
                threat_actor_id: ID of the responsible threat actor
                start_date: Campaign start date (ISO 8601)
                status: "active", "concluded", or "suspected"
                targets: Target sectors or org names
                iocs: Campaign-specific IOCs
                ttps: TTPs observed in this campaign

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Campaign | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: Campaign,
) -> Response[Campaign | HTTPValidationError]:
    """Add Campaign

     Register a new threat campaign. Upserts on duplicate ID.

    Args:
        body (Campaign): Threat campaign linking actors to a coordinated attack effort.

            Attributes:
                id: Unique campaign identifier
                name: Campaign name
                threat_actor_id: ID of the responsible threat actor
                start_date: Campaign start date (ISO 8601)
                status: "active", "concluded", or "suspected"
                targets: Target sectors or org names
                iocs: Campaign-specific IOCs
                ttps: TTPs observed in this campaign

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Campaign | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: Campaign,
) -> Campaign | HTTPValidationError | None:
    """Add Campaign

     Register a new threat campaign. Upserts on duplicate ID.

    Args:
        body (Campaign): Threat campaign linking actors to a coordinated attack effort.

            Attributes:
                id: Unique campaign identifier
                name: Campaign name
                threat_actor_id: ID of the responsible threat actor
                start_date: Campaign start date (ISO 8601)
                status: "active", "concluded", or "suspected"
                targets: Target sectors or org names
                iocs: Campaign-specific IOCs
                ttps: TTPs observed in this campaign

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Campaign | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
