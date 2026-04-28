from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.delete_risk_api_v1_risks_risk_id_delete_response_delete_risk_api_v1_risks_risk_id_delete import (
    DeleteRiskApiV1RisksRiskIdDeleteResponseDeleteRiskApiV1RisksRiskIdDelete,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    risk_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "delete",
        "url": "/api/v1/risks/{risk_id}".format(
            risk_id=quote(str(risk_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> DeleteRiskApiV1RisksRiskIdDeleteResponseDeleteRiskApiV1RisksRiskIdDelete | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = DeleteRiskApiV1RisksRiskIdDeleteResponseDeleteRiskApiV1RisksRiskIdDelete.from_dict(
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
) -> Response[DeleteRiskApiV1RisksRiskIdDeleteResponseDeleteRiskApiV1RisksRiskIdDelete | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    risk_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[DeleteRiskApiV1RisksRiskIdDeleteResponseDeleteRiskApiV1RisksRiskIdDelete | HTTPValidationError]:
    """Delete a risk

    Args:
        risk_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteRiskApiV1RisksRiskIdDeleteResponseDeleteRiskApiV1RisksRiskIdDelete | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        risk_id=risk_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    risk_id: str,
    *,
    client: AuthenticatedClient,
) -> DeleteRiskApiV1RisksRiskIdDeleteResponseDeleteRiskApiV1RisksRiskIdDelete | HTTPValidationError | None:
    """Delete a risk

    Args:
        risk_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteRiskApiV1RisksRiskIdDeleteResponseDeleteRiskApiV1RisksRiskIdDelete | HTTPValidationError
    """

    return sync_detailed(
        risk_id=risk_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    risk_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[DeleteRiskApiV1RisksRiskIdDeleteResponseDeleteRiskApiV1RisksRiskIdDelete | HTTPValidationError]:
    """Delete a risk

    Args:
        risk_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[DeleteRiskApiV1RisksRiskIdDeleteResponseDeleteRiskApiV1RisksRiskIdDelete | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        risk_id=risk_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    risk_id: str,
    *,
    client: AuthenticatedClient,
) -> DeleteRiskApiV1RisksRiskIdDeleteResponseDeleteRiskApiV1RisksRiskIdDelete | HTTPValidationError | None:
    """Delete a risk

    Args:
        risk_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        DeleteRiskApiV1RisksRiskIdDeleteResponseDeleteRiskApiV1RisksRiskIdDelete | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            risk_id=risk_id,
            client=client,
        )
    ).parsed
