from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_campaign_timeline_api_v1_threat_intel_campaigns_campaign_id_timeline_get_response_get_campaign_timeline_api_v1_threat_intel_campaigns_campaign_id_timeline_get import (
    GetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGetResponseGetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    campaign_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/threat-intel/campaigns/{campaign_id}/timeline".format(
            campaign_id=quote(str(campaign_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGetResponseGetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = GetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGetResponseGetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGet.from_dict(
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
    GetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGetResponseGetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGet
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    campaign_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGetResponseGetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGet
    | HTTPValidationError
]:
    """Get Campaign Timeline

     Return campaign details and all correlated finding events as a
    chronological timeline.

    Args:
        campaign_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGetResponseGetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        campaign_id=campaign_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    campaign_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGetResponseGetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGet
    | HTTPValidationError
    | None
):
    """Get Campaign Timeline

     Return campaign details and all correlated finding events as a
    chronological timeline.

    Args:
        campaign_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGetResponseGetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGet | HTTPValidationError
    """

    return sync_detailed(
        campaign_id=campaign_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    campaign_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    GetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGetResponseGetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGet
    | HTTPValidationError
]:
    """Get Campaign Timeline

     Return campaign details and all correlated finding events as a
    chronological timeline.

    Args:
        campaign_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGetResponseGetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        campaign_id=campaign_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    campaign_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    GetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGetResponseGetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGet
    | HTTPValidationError
    | None
):
    """Get Campaign Timeline

     Return campaign details and all correlated finding events as a
    chronological timeline.

    Args:
        campaign_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGetResponseGetCampaignTimelineApiV1ThreatIntelCampaignsCampaignIdTimelineGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            campaign_id=campaign_id,
            client=client,
        )
    ).parsed
