from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.evidence_response import EvidenceResponse
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    incident_id: str,
    *,
    org_id: str | Unset = "default",
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/ir/incidents/{incident_id}/evidence".format(
            incident_id=quote(str(incident_id), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[EvidenceResponse] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = EvidenceResponse.from_dict(response_200_item_data)

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
) -> Response[HTTPValidationError | list[EvidenceResponse]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    incident_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> Response[HTTPValidationError | list[EvidenceResponse]]:
    """Get Evidence Chain

     Return the cryptographically-linked evidence chain for an incident. Each item includes SHA-256 hash,
    collector ID, and chain integrity status.

    Args:
        incident_id (str):
        org_id (str | Unset): Organization ID Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[EvidenceResponse]]
    """

    kwargs = _get_kwargs(
        incident_id=incident_id,
        org_id=org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    incident_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> HTTPValidationError | list[EvidenceResponse] | None:
    """Get Evidence Chain

     Return the cryptographically-linked evidence chain for an incident. Each item includes SHA-256 hash,
    collector ID, and chain integrity status.

    Args:
        incident_id (str):
        org_id (str | Unset): Organization ID Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[EvidenceResponse]
    """

    return sync_detailed(
        incident_id=incident_id,
        client=client,
        org_id=org_id,
    ).parsed


async def asyncio_detailed(
    incident_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> Response[HTTPValidationError | list[EvidenceResponse]]:
    """Get Evidence Chain

     Return the cryptographically-linked evidence chain for an incident. Each item includes SHA-256 hash,
    collector ID, and chain integrity status.

    Args:
        incident_id (str):
        org_id (str | Unset): Organization ID Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[EvidenceResponse]]
    """

    kwargs = _get_kwargs(
        incident_id=incident_id,
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    incident_id: str,
    *,
    client: AuthenticatedClient,
    org_id: str | Unset = "default",
) -> HTTPValidationError | list[EvidenceResponse] | None:
    """Get Evidence Chain

     Return the cryptographically-linked evidence chain for an incident. Each item includes SHA-256 hash,
    collector ID, and chain integrity status.

    Args:
        incident_id (str):
        org_id (str | Unset): Organization ID Default: 'default'.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[EvidenceResponse]
    """

    return (
        await asyncio_detailed(
            incident_id=incident_id,
            client=client,
            org_id=org_id,
        )
    ).parsed
