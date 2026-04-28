from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.list_scenarios_api_v1_fail_scenarios_get_response_list_scenarios_api_v1_fail_scenarios_get import (
    ListScenariosApiV1FailScenariosGetResponseListScenariosApiV1FailScenariosGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/fail/scenarios",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ListScenariosApiV1FailScenariosGetResponseListScenariosApiV1FailScenariosGet | None:
    if response.status_code == 200:
        response_200 = ListScenariosApiV1FailScenariosGetResponseListScenariosApiV1FailScenariosGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ListScenariosApiV1FailScenariosGetResponseListScenariosApiV1FailScenariosGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[ListScenariosApiV1FailScenariosGetResponseListScenariosApiV1FailScenariosGet]:
    """List available injection scenarios

     List all available FAIL injection scenarios (built-in and custom).

    Each scenario includes:
    - Synthetic finding payload (CVE, CVSS, evidence)
    - MITRE ATT&CK technique/tactic mapping
    - CWE identifiers
    - Expected detection timeline and triage classification
    - Recommended remediation approach

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ListScenariosApiV1FailScenariosGetResponseListScenariosApiV1FailScenariosGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> ListScenariosApiV1FailScenariosGetResponseListScenariosApiV1FailScenariosGet | None:
    """List available injection scenarios

     List all available FAIL injection scenarios (built-in and custom).

    Each scenario includes:
    - Synthetic finding payload (CVE, CVSS, evidence)
    - MITRE ATT&CK technique/tactic mapping
    - CWE identifiers
    - Expected detection timeline and triage classification
    - Recommended remediation approach

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ListScenariosApiV1FailScenariosGetResponseListScenariosApiV1FailScenariosGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[ListScenariosApiV1FailScenariosGetResponseListScenariosApiV1FailScenariosGet]:
    """List available injection scenarios

     List all available FAIL injection scenarios (built-in and custom).

    Each scenario includes:
    - Synthetic finding payload (CVE, CVSS, evidence)
    - MITRE ATT&CK technique/tactic mapping
    - CWE identifiers
    - Expected detection timeline and triage classification
    - Recommended remediation approach

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ListScenariosApiV1FailScenariosGetResponseListScenariosApiV1FailScenariosGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> ListScenariosApiV1FailScenariosGetResponseListScenariosApiV1FailScenariosGet | None:
    """List available injection scenarios

     List all available FAIL injection scenarios (built-in and custom).

    Each scenario includes:
    - Synthetic finding payload (CVE, CVSS, evidence)
    - MITRE ATT&CK technique/tactic mapping
    - CWE identifiers
    - Expected detection timeline and triage classification
    - Recommended remediation approach

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ListScenariosApiV1FailScenariosGetResponseListScenariosApiV1FailScenariosGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
