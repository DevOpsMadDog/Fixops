from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_training_data_api_v1_fail_training_data_get_response_get_training_data_api_v1_fail_training_data_get import (
    GetTrainingDataApiV1FailTrainingDataGetResponseGetTrainingDataApiV1FailTrainingDataGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    scenario_id: None | str | Unset = UNSET,
    limit: int | Unset = 1000,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_scenario_id: None | str | Unset
    if isinstance(scenario_id, Unset):
        json_scenario_id = UNSET
    else:
        json_scenario_id = scenario_id
    params["scenario_id"] = json_scenario_id

    params["limit"] = limit

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/fail/training-data",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetTrainingDataApiV1FailTrainingDataGetResponseGetTrainingDataApiV1FailTrainingDataGet | HTTPValidationError | None
):
    if response.status_code == 200:
        response_200 = GetTrainingDataApiV1FailTrainingDataGetResponseGetTrainingDataApiV1FailTrainingDataGet.from_dict(
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
    GetTrainingDataApiV1FailTrainingDataGetResponseGetTrainingDataApiV1FailTrainingDataGet | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    scenario_id: None | str | Unset = UNSET,
    limit: int | Unset = 1000,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GetTrainingDataApiV1FailTrainingDataGetResponseGetTrainingDataApiV1FailTrainingDataGet | HTTPValidationError
]:
    r"""Export labeled training samples

     Export labeled training samples generated from completed drills.

    Each sample includes two labeled signals for ML feedback loops:
    - **Detection signal**: `detection_label` ∈ {fast, slow, very_slow, missed}
    - **Triage signal**: `triage_label` ∈ {correct, incorrect, skipped}

    These samples feed into the self-learning detection and triage loops:
    - Loop 1: Detection model — learns what \"fast detection\" looks like per scenario
    - Loop 2: Triage model — learns correct severity classification per finding type

    Args:
        scenario_id (None | str | Unset): Filter by scenario
        limit (int | Unset): Maximum samples to return Default: 1000.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetTrainingDataApiV1FailTrainingDataGetResponseGetTrainingDataApiV1FailTrainingDataGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        scenario_id=scenario_id,
        limit=limit,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    scenario_id: None | str | Unset = UNSET,
    limit: int | Unset = 1000,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GetTrainingDataApiV1FailTrainingDataGetResponseGetTrainingDataApiV1FailTrainingDataGet | HTTPValidationError | None
):
    r"""Export labeled training samples

     Export labeled training samples generated from completed drills.

    Each sample includes two labeled signals for ML feedback loops:
    - **Detection signal**: `detection_label` ∈ {fast, slow, very_slow, missed}
    - **Triage signal**: `triage_label` ∈ {correct, incorrect, skipped}

    These samples feed into the self-learning detection and triage loops:
    - Loop 1: Detection model — learns what \"fast detection\" looks like per scenario
    - Loop 2: Triage model — learns correct severity classification per finding type

    Args:
        scenario_id (None | str | Unset): Filter by scenario
        limit (int | Unset): Maximum samples to return Default: 1000.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetTrainingDataApiV1FailTrainingDataGetResponseGetTrainingDataApiV1FailTrainingDataGet | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        scenario_id=scenario_id,
        limit=limit,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    scenario_id: None | str | Unset = UNSET,
    limit: int | Unset = 1000,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GetTrainingDataApiV1FailTrainingDataGetResponseGetTrainingDataApiV1FailTrainingDataGet | HTTPValidationError
]:
    r"""Export labeled training samples

     Export labeled training samples generated from completed drills.

    Each sample includes two labeled signals for ML feedback loops:
    - **Detection signal**: `detection_label` ∈ {fast, slow, very_slow, missed}
    - **Triage signal**: `triage_label` ∈ {correct, incorrect, skipped}

    These samples feed into the self-learning detection and triage loops:
    - Loop 1: Detection model — learns what \"fast detection\" looks like per scenario
    - Loop 2: Triage model — learns correct severity classification per finding type

    Args:
        scenario_id (None | str | Unset): Filter by scenario
        limit (int | Unset): Maximum samples to return Default: 1000.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetTrainingDataApiV1FailTrainingDataGetResponseGetTrainingDataApiV1FailTrainingDataGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        scenario_id=scenario_id,
        limit=limit,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    scenario_id: None | str | Unset = UNSET,
    limit: int | Unset = 1000,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GetTrainingDataApiV1FailTrainingDataGetResponseGetTrainingDataApiV1FailTrainingDataGet | HTTPValidationError | None
):
    r"""Export labeled training samples

     Export labeled training samples generated from completed drills.

    Each sample includes two labeled signals for ML feedback loops:
    - **Detection signal**: `detection_label` ∈ {fast, slow, very_slow, missed}
    - **Triage signal**: `triage_label` ∈ {correct, incorrect, skipped}

    These samples feed into the self-learning detection and triage loops:
    - Loop 1: Detection model — learns what \"fast detection\" looks like per scenario
    - Loop 2: Triage model — learns correct severity classification per finding type

    Args:
        scenario_id (None | str | Unset): Filter by scenario
        limit (int | Unset): Maximum samples to return Default: 1000.
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetTrainingDataApiV1FailTrainingDataGetResponseGetTrainingDataApiV1FailTrainingDataGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            scenario_id=scenario_id,
            limit=limit,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
