from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_policy_api_v1_policy_engine_policies_policy_id_get_response_get_policy_api_v1_policy_engine_policies_policy_id_get import (
    GetPolicyApiV1PolicyEnginePoliciesPolicyIdGetResponseGetPolicyApiV1PolicyEnginePoliciesPolicyIdGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    policy_id: str,
    *,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/policy-engine/policies/{policy_id}".format(
            policy_id=quote(str(policy_id), safe=""),
        ),
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetPolicyApiV1PolicyEnginePoliciesPolicyIdGetResponseGetPolicyApiV1PolicyEnginePoliciesPolicyIdGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = GetPolicyApiV1PolicyEnginePoliciesPolicyIdGetResponseGetPolicyApiV1PolicyEnginePoliciesPolicyIdGet.from_dict(
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
    GetPolicyApiV1PolicyEnginePoliciesPolicyIdGetResponseGetPolicyApiV1PolicyEnginePoliciesPolicyIdGet
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    policy_id: str,
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GetPolicyApiV1PolicyEnginePoliciesPolicyIdGetResponseGetPolicyApiV1PolicyEnginePoliciesPolicyIdGet
    | HTTPValidationError
]:
    """Get Policy

     Retrieve a single policy by ID.

    Args:
        policy_id (str):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetPolicyApiV1PolicyEnginePoliciesPolicyIdGetResponseGetPolicyApiV1PolicyEnginePoliciesPolicyIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        policy_id=policy_id,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    policy_id: str,
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GetPolicyApiV1PolicyEnginePoliciesPolicyIdGetResponseGetPolicyApiV1PolicyEnginePoliciesPolicyIdGet
    | HTTPValidationError
    | None
):
    """Get Policy

     Retrieve a single policy by ID.

    Args:
        policy_id (str):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetPolicyApiV1PolicyEnginePoliciesPolicyIdGetResponseGetPolicyApiV1PolicyEnginePoliciesPolicyIdGet | HTTPValidationError
    """

    return sync_detailed(
        policy_id=policy_id,
        client=client,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    policy_id: str,
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GetPolicyApiV1PolicyEnginePoliciesPolicyIdGetResponseGetPolicyApiV1PolicyEnginePoliciesPolicyIdGet
    | HTTPValidationError
]:
    """Get Policy

     Retrieve a single policy by ID.

    Args:
        policy_id (str):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetPolicyApiV1PolicyEnginePoliciesPolicyIdGetResponseGetPolicyApiV1PolicyEnginePoliciesPolicyIdGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        policy_id=policy_id,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    policy_id: str,
    *,
    client: AuthenticatedClient,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GetPolicyApiV1PolicyEnginePoliciesPolicyIdGetResponseGetPolicyApiV1PolicyEnginePoliciesPolicyIdGet
    | HTTPValidationError
    | None
):
    """Get Policy

     Retrieve a single policy by ID.

    Args:
        policy_id (str):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetPolicyApiV1PolicyEnginePoliciesPolicyIdGetResponseGetPolicyApiV1PolicyEnginePoliciesPolicyIdGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            policy_id=policy_id,
            client=client,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
