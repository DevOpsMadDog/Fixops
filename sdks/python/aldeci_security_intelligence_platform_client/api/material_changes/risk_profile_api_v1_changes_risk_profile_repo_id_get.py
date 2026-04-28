from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.risk_profile_api_v1_changes_risk_profile_repo_id_get_response_risk_profile_api_v1_changes_risk_profile_repo_id_get import (
    RiskProfileApiV1ChangesRiskProfileRepoIdGetResponseRiskProfileApiV1ChangesRiskProfileRepoIdGet,
)
from ...types import Response


def _get_kwargs(
    repo_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/changes/risk-profile/{repo_id}".format(
            repo_id=quote(str(repo_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | RiskProfileApiV1ChangesRiskProfileRepoIdGetResponseRiskProfileApiV1ChangesRiskProfileRepoIdGet
    | None
):
    if response.status_code == 200:
        response_200 = (
            RiskProfileApiV1ChangesRiskProfileRepoIdGetResponseRiskProfileApiV1ChangesRiskProfileRepoIdGet.from_dict(
                response.json()
            )
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
    HTTPValidationError | RiskProfileApiV1ChangesRiskProfileRepoIdGetResponseRiskProfileApiV1ChangesRiskProfileRepoIdGet
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    repo_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    HTTPValidationError | RiskProfileApiV1ChangesRiskProfileRepoIdGetResponseRiskProfileApiV1ChangesRiskProfileRepoIdGet
]:
    """Risk Profile

     Get risk profile for a repository based on recent changes.

    Args:
        repo_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RiskProfileApiV1ChangesRiskProfileRepoIdGetResponseRiskProfileApiV1ChangesRiskProfileRepoIdGet]
    """

    kwargs = _get_kwargs(
        repo_id=repo_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    repo_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    HTTPValidationError
    | RiskProfileApiV1ChangesRiskProfileRepoIdGetResponseRiskProfileApiV1ChangesRiskProfileRepoIdGet
    | None
):
    """Risk Profile

     Get risk profile for a repository based on recent changes.

    Args:
        repo_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RiskProfileApiV1ChangesRiskProfileRepoIdGetResponseRiskProfileApiV1ChangesRiskProfileRepoIdGet
    """

    return sync_detailed(
        repo_id=repo_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    repo_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    HTTPValidationError | RiskProfileApiV1ChangesRiskProfileRepoIdGetResponseRiskProfileApiV1ChangesRiskProfileRepoIdGet
]:
    """Risk Profile

     Get risk profile for a repository based on recent changes.

    Args:
        repo_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RiskProfileApiV1ChangesRiskProfileRepoIdGetResponseRiskProfileApiV1ChangesRiskProfileRepoIdGet]
    """

    kwargs = _get_kwargs(
        repo_id=repo_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    repo_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    HTTPValidationError
    | RiskProfileApiV1ChangesRiskProfileRepoIdGetResponseRiskProfileApiV1ChangesRiskProfileRepoIdGet
    | None
):
    """Risk Profile

     Get risk profile for a repository based on recent changes.

    Args:
        repo_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RiskProfileApiV1ChangesRiskProfileRepoIdGetResponseRiskProfileApiV1ChangesRiskProfileRepoIdGet
    """

    return (
        await asyncio_detailed(
            repo_id=repo_id,
            client=client,
        )
    ).parsed
