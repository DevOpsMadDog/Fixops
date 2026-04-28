from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_drill_api_v1_fail_drills_drill_id_get_response_get_drill_api_v1_fail_drills_drill_id_get import (
    GetDrillApiV1FailDrillsDrillIdGetResponseGetDrillApiV1FailDrillsDrillIdGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    drill_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/fail/drills/{drill_id}".format(
            drill_id=quote(str(drill_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> GetDrillApiV1FailDrillsDrillIdGetResponseGetDrillApiV1FailDrillsDrillIdGet | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = GetDrillApiV1FailDrillsDrillIdGetResponseGetDrillApiV1FailDrillsDrillIdGet.from_dict(
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
) -> Response[GetDrillApiV1FailDrillsDrillIdGetResponseGetDrillApiV1FailDrillsDrillIdGet | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    drill_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[GetDrillApiV1FailDrillsDrillIdGetResponseGetDrillApiV1FailDrillsDrillIdGet | HTTPValidationError]:
    """Drill detail with timeline and score

     Get full detail for a drill including timeline events and score breakdown.

    Args:
        drill_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetDrillApiV1FailDrillsDrillIdGetResponseGetDrillApiV1FailDrillsDrillIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        drill_id=drill_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    drill_id: str,
    *,
    client: AuthenticatedClient,
) -> GetDrillApiV1FailDrillsDrillIdGetResponseGetDrillApiV1FailDrillsDrillIdGet | HTTPValidationError | None:
    """Drill detail with timeline and score

     Get full detail for a drill including timeline events and score breakdown.

    Args:
        drill_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetDrillApiV1FailDrillsDrillIdGetResponseGetDrillApiV1FailDrillsDrillIdGet | HTTPValidationError
    """

    return sync_detailed(
        drill_id=drill_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    drill_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[GetDrillApiV1FailDrillsDrillIdGetResponseGetDrillApiV1FailDrillsDrillIdGet | HTTPValidationError]:
    """Drill detail with timeline and score

     Get full detail for a drill including timeline events and score breakdown.

    Args:
        drill_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetDrillApiV1FailDrillsDrillIdGetResponseGetDrillApiV1FailDrillsDrillIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        drill_id=drill_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    drill_id: str,
    *,
    client: AuthenticatedClient,
) -> GetDrillApiV1FailDrillsDrillIdGetResponseGetDrillApiV1FailDrillsDrillIdGet | HTTPValidationError | None:
    """Drill detail with timeline and score

     Get full detail for a drill including timeline events and score breakdown.

    Args:
        drill_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetDrillApiV1FailDrillsDrillIdGetResponseGetDrillApiV1FailDrillsDrillIdGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            drill_id=drill_id,
            client=client,
        )
    ).parsed
