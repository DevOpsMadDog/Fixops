from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.onboarding_progress_response import OnboardingProgressResponse
from ...models.skip_step_request import SkipStepRequest
from ...types import Response


def _get_kwargs(
    step: str,
    *,
    body: SkipStepRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/onboarding/steps/{step}/skip".format(
            step=quote(str(step), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | OnboardingProgressResponse | None:
    if response.status_code == 200:
        response_200 = OnboardingProgressResponse.from_dict(response.json())

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
) -> Response[HTTPValidationError | OnboardingProgressResponse]:
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
    body: SkipStepRequest,
) -> Response[HTTPValidationError | OnboardingProgressResponse]:
    """Skip Step

     Mark a step as skipped.

    Args:
        step (str): Onboarding step name to skip
        body (SkipStepRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | OnboardingProgressResponse]
    """

    kwargs = _get_kwargs(
        step=step,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    step: str,
    *,
    client: AuthenticatedClient,
    body: SkipStepRequest,
) -> HTTPValidationError | OnboardingProgressResponse | None:
    """Skip Step

     Mark a step as skipped.

    Args:
        step (str): Onboarding step name to skip
        body (SkipStepRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | OnboardingProgressResponse
    """

    return sync_detailed(
        step=step,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    step: str,
    *,
    client: AuthenticatedClient,
    body: SkipStepRequest,
) -> Response[HTTPValidationError | OnboardingProgressResponse]:
    """Skip Step

     Mark a step as skipped.

    Args:
        step (str): Onboarding step name to skip
        body (SkipStepRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | OnboardingProgressResponse]
    """

    kwargs = _get_kwargs(
        step=step,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    step: str,
    *,
    client: AuthenticatedClient,
    body: SkipStepRequest,
) -> HTTPValidationError | OnboardingProgressResponse | None:
    """Skip Step

     Mark a step as skipped.

    Args:
        step (str): Onboarding step name to skip
        body (SkipStepRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | OnboardingProgressResponse
    """

    return (
        await asyncio_detailed(
            step=step,
            client=client,
            body=body,
        )
    ).parsed
