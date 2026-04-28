from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_actor_profile_api_v1_threat_intel_actors_actor_id_get_response_get_actor_profile_api_v1_threat_intel_actors_actor_id_get import (
    GetActorProfileApiV1ThreatIntelActorsActorIdGetResponseGetActorProfileApiV1ThreatIntelActorsActorIdGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    actor_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/threat-intel/actors/{actor_id}".format(
            actor_id=quote(str(actor_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetActorProfileApiV1ThreatIntelActorsActorIdGetResponseGetActorProfileApiV1ThreatIntelActorsActorIdGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = GetActorProfileApiV1ThreatIntelActorsActorIdGetResponseGetActorProfileApiV1ThreatIntelActorsActorIdGet.from_dict(
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
    GetActorProfileApiV1ThreatIntelActorsActorIdGetResponseGetActorProfileApiV1ThreatIntelActorsActorIdGet
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    actor_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetActorProfileApiV1ThreatIntelActorsActorIdGetResponseGetActorProfileApiV1ThreatIntelActorsActorIdGet
    | HTTPValidationError
]:
    """Get Actor Profile

     Return full actor dossier: profile, associated campaigns, and
    recent finding correlations.

    Args:
        actor_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetActorProfileApiV1ThreatIntelActorsActorIdGetResponseGetActorProfileApiV1ThreatIntelActorsActorIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        actor_id=actor_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    actor_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetActorProfileApiV1ThreatIntelActorsActorIdGetResponseGetActorProfileApiV1ThreatIntelActorsActorIdGet
    | HTTPValidationError
    | None
):
    """Get Actor Profile

     Return full actor dossier: profile, associated campaigns, and
    recent finding correlations.

    Args:
        actor_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetActorProfileApiV1ThreatIntelActorsActorIdGetResponseGetActorProfileApiV1ThreatIntelActorsActorIdGet | HTTPValidationError
    """

    return sync_detailed(
        actor_id=actor_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    actor_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetActorProfileApiV1ThreatIntelActorsActorIdGetResponseGetActorProfileApiV1ThreatIntelActorsActorIdGet
    | HTTPValidationError
]:
    """Get Actor Profile

     Return full actor dossier: profile, associated campaigns, and
    recent finding correlations.

    Args:
        actor_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetActorProfileApiV1ThreatIntelActorsActorIdGetResponseGetActorProfileApiV1ThreatIntelActorsActorIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        actor_id=actor_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    actor_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetActorProfileApiV1ThreatIntelActorsActorIdGetResponseGetActorProfileApiV1ThreatIntelActorsActorIdGet
    | HTTPValidationError
    | None
):
    """Get Actor Profile

     Return full actor dossier: profile, associated campaigns, and
    recent finding correlations.

    Args:
        actor_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetActorProfileApiV1ThreatIntelActorsActorIdGetResponseGetActorProfileApiV1ThreatIntelActorsActorIdGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            actor_id=actor_id,
            client=client,
        )
    ).parsed
