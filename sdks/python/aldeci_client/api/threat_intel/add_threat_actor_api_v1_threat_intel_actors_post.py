from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.threat_actor import ThreatActor
from ...types import Response


def _get_kwargs(
    *,
    body: ThreatActor,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/threat-intel/actors",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | ThreatActor | None:
    if response.status_code == 200:
        response_200 = ThreatActor.from_dict(response.json())

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
) -> Response[HTTPValidationError | ThreatActor]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: ThreatActor,
) -> Response[HTTPValidationError | ThreatActor]:
    """Add Threat Actor

     Register a new threat actor profile. If an actor with the same ID
    already exists it will be replaced (upsert).

    Args:
        body (ThreatActor): Known threat actor (APT group, criminal org, nation-state).

            Attributes:
                id: Unique actor identifier (e.g. "apt29")
                name: Common name (e.g. "Cozy Bear")
                aliases: Known alternate names
                ttps: MITRE ATT&CK technique IDs (e.g. ["T1566", "T1078"])
                motivation: Primary motivation (espionage, financial, etc.)
                origin_country: Attributed country of origin
                active: Whether actor is currently active
                associated_campaigns: Campaign IDs linked to this actor
                iocs: Indicators of Compromise (IPs, domains, hashes, etc.)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ThreatActor]
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
    body: ThreatActor,
) -> HTTPValidationError | ThreatActor | None:
    """Add Threat Actor

     Register a new threat actor profile. If an actor with the same ID
    already exists it will be replaced (upsert).

    Args:
        body (ThreatActor): Known threat actor (APT group, criminal org, nation-state).

            Attributes:
                id: Unique actor identifier (e.g. "apt29")
                name: Common name (e.g. "Cozy Bear")
                aliases: Known alternate names
                ttps: MITRE ATT&CK technique IDs (e.g. ["T1566", "T1078"])
                motivation: Primary motivation (espionage, financial, etc.)
                origin_country: Attributed country of origin
                active: Whether actor is currently active
                associated_campaigns: Campaign IDs linked to this actor
                iocs: Indicators of Compromise (IPs, domains, hashes, etc.)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ThreatActor
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: ThreatActor,
) -> Response[HTTPValidationError | ThreatActor]:
    """Add Threat Actor

     Register a new threat actor profile. If an actor with the same ID
    already exists it will be replaced (upsert).

    Args:
        body (ThreatActor): Known threat actor (APT group, criminal org, nation-state).

            Attributes:
                id: Unique actor identifier (e.g. "apt29")
                name: Common name (e.g. "Cozy Bear")
                aliases: Known alternate names
                ttps: MITRE ATT&CK technique IDs (e.g. ["T1566", "T1078"])
                motivation: Primary motivation (espionage, financial, etc.)
                origin_country: Attributed country of origin
                active: Whether actor is currently active
                associated_campaigns: Campaign IDs linked to this actor
                iocs: Indicators of Compromise (IPs, domains, hashes, etc.)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ThreatActor]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: ThreatActor,
) -> HTTPValidationError | ThreatActor | None:
    """Add Threat Actor

     Register a new threat actor profile. If an actor with the same ID
    already exists it will be replaced (upsert).

    Args:
        body (ThreatActor): Known threat actor (APT group, criminal org, nation-state).

            Attributes:
                id: Unique actor identifier (e.g. "apt29")
                name: Common name (e.g. "Cozy Bear")
                aliases: Known alternate names
                ttps: MITRE ATT&CK technique IDs (e.g. ["T1566", "T1078"])
                motivation: Primary motivation (espionage, financial, etc.)
                origin_country: Attributed country of origin
                active: Whether actor is currently active
                associated_campaigns: Campaign IDs linked to this actor
                iocs: Indicators of Compromise (IPs, domains, hashes, etc.)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ThreatActor
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
