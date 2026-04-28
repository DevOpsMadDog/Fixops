from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.list_plans_api_v1_remediation_plans_get_response_list_plans_api_v1_remediation_plans_get import (
    ListPlansApiV1RemediationPlansGetResponseListPlansApiV1RemediationPlansGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    finding_id: None | str | Unset = UNSET,
    state: None | str | Unset = UNSET,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    json_finding_id: None | str | Unset
    if isinstance(finding_id, Unset):
        json_finding_id = UNSET
    else:
        json_finding_id = finding_id
    params["finding_id"] = json_finding_id

    json_state: None | str | Unset
    if isinstance(state, Unset):
        json_state = UNSET
    else:
        json_state = state
    params["state"] = json_state

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/remediation/plans",
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | ListPlansApiV1RemediationPlansGetResponseListPlansApiV1RemediationPlansGet | None:
    if response.status_code == 200:
        response_200 = ListPlansApiV1RemediationPlansGetResponseListPlansApiV1RemediationPlansGet.from_dict(
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
) -> Response[HTTPValidationError | ListPlansApiV1RemediationPlansGetResponseListPlansApiV1RemediationPlansGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    finding_id: None | str | Unset = UNSET,
    state: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | ListPlansApiV1RemediationPlansGetResponseListPlansApiV1RemediationPlansGet]:
    """List all remediation plans

     List remediation plans with optional filters.

    Args:
        finding_id (None | str | Unset):
        state (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListPlansApiV1RemediationPlansGetResponseListPlansApiV1RemediationPlansGet]
    """

    kwargs = _get_kwargs(
        finding_id=finding_id,
        state=state,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    finding_id: None | str | Unset = UNSET,
    state: None | str | Unset = UNSET,
) -> HTTPValidationError | ListPlansApiV1RemediationPlansGetResponseListPlansApiV1RemediationPlansGet | None:
    """List all remediation plans

     List remediation plans with optional filters.

    Args:
        finding_id (None | str | Unset):
        state (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListPlansApiV1RemediationPlansGetResponseListPlansApiV1RemediationPlansGet
    """

    return sync_detailed(
        client=client,
        finding_id=finding_id,
        state=state,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    finding_id: None | str | Unset = UNSET,
    state: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | ListPlansApiV1RemediationPlansGetResponseListPlansApiV1RemediationPlansGet]:
    """List all remediation plans

     List remediation plans with optional filters.

    Args:
        finding_id (None | str | Unset):
        state (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListPlansApiV1RemediationPlansGetResponseListPlansApiV1RemediationPlansGet]
    """

    kwargs = _get_kwargs(
        finding_id=finding_id,
        state=state,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    finding_id: None | str | Unset = UNSET,
    state: None | str | Unset = UNSET,
) -> HTTPValidationError | ListPlansApiV1RemediationPlansGetResponseListPlansApiV1RemediationPlansGet | None:
    """List all remediation plans

     List remediation plans with optional filters.

    Args:
        finding_id (None | str | Unset):
        state (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListPlansApiV1RemediationPlansGetResponseListPlansApiV1RemediationPlansGet
    """

    return (
        await asyncio_detailed(
            client=client,
            finding_id=finding_id,
            state=state,
        )
    ).parsed
