from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.step_config_response import StepConfigResponse
from ...types import UNSET, Response


def _get_kwargs(
    step: str,
    *,
    org_id: str,
) -> dict[str, Any]:

    params: dict[str, Any] = {}

    params["org_id"] = org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/onboarding/steps/{step}/config".format(
            step=quote(str(step), safe=""),
        ),
        "params": params,
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | StepConfigResponse | None:
    if response.status_code == 200:
        response_200 = StepConfigResponse.from_dict(response.json())

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
) -> Response[HTTPValidationError | StepConfigResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    step: str,
    *,
    client: AuthenticatedClient,
    org_id: str,
) -> Response[HTTPValidationError | StepConfigResponse]:
    """Get Step Config

     Retrieve configuration stored when a step was completed.

    Args:
        step (str): Onboarding step name
        org_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | StepConfigResponse]
    """

    kwargs = _get_kwargs(
        step=step,
        org_id=org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    step: str,
    *,
    client: AuthenticatedClient,
    org_id: str,
) -> HTTPValidationError | StepConfigResponse | None:
    """Get Step Config

     Retrieve configuration stored when a step was completed.

    Args:
        step (str): Onboarding step name
        org_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | StepConfigResponse
    """

    return sync_detailed(
        step=step,
        client=client,
        org_id=org_id,
    ).parsed


async def asyncio_detailed(
    step: str,
    *,
    client: AuthenticatedClient,
    org_id: str,
) -> Response[HTTPValidationError | StepConfigResponse]:
    """Get Step Config

     Retrieve configuration stored when a step was completed.

    Args:
        step (str): Onboarding step name
        org_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | StepConfigResponse]
    """

    kwargs = _get_kwargs(
        step=step,
        org_id=org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    step: str,
    *,
    client: AuthenticatedClient,
    org_id: str,
) -> HTTPValidationError | StepConfigResponse | None:
    """Get Step Config

     Retrieve configuration stored when a step was completed.

    Args:
        step (str): Onboarding step name
        org_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | StepConfigResponse
    """

    return (
        await asyncio_detailed(
            step=step,
            client=client,
            org_id=org_id,
        )
    ).parsed
