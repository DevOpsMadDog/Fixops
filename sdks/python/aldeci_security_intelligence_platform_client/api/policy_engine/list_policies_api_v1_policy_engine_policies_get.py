from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.list_policies_api_v1_policy_engine_policies_get_response_list_policies_api_v1_policy_engine_policies_get import (
    ListPoliciesApiV1PolicyEnginePoliciesGetResponseListPoliciesApiV1PolicyEnginePoliciesGet,
)
from ...models.policy_scope import PolicyScope
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    scope: None | PolicyScope | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    params: dict[str, Any] = {}

    json_scope: None | str | Unset
    if isinstance(scope, Unset):
        json_scope = UNSET
    elif isinstance(scope, PolicyScope):
        json_scope = scope.value
    else:
        json_scope = scope
    params["scope"] = json_scope

    json_org_id: None | str | Unset
    if isinstance(org_id, Unset):
        json_org_id = UNSET
    else:
        json_org_id = org_id
    params["org_id"] = json_org_id

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/policy-engine/policies",
        "params": params,
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | ListPoliciesApiV1PolicyEnginePoliciesGetResponseListPoliciesApiV1PolicyEnginePoliciesGet
    | None
):
    if response.status_code == 200:
        response_200 = (
            ListPoliciesApiV1PolicyEnginePoliciesGetResponseListPoliciesApiV1PolicyEnginePoliciesGet.from_dict(
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
    HTTPValidationError | ListPoliciesApiV1PolicyEnginePoliciesGetResponseListPoliciesApiV1PolicyEnginePoliciesGet
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
    scope: None | PolicyScope | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError | ListPoliciesApiV1PolicyEnginePoliciesGetResponseListPoliciesApiV1PolicyEnginePoliciesGet
]:
    """List Policies

     List all policies for the org, optionally filtered by scope.

    Args:
        scope (None | PolicyScope | Unset): Filter by scope
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListPoliciesApiV1PolicyEnginePoliciesGetResponseListPoliciesApiV1PolicyEnginePoliciesGet]
    """

    kwargs = _get_kwargs(
        scope=scope,
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
    scope: None | PolicyScope | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | ListPoliciesApiV1PolicyEnginePoliciesGetResponseListPoliciesApiV1PolicyEnginePoliciesGet
    | None
):
    """List Policies

     List all policies for the org, optionally filtered by scope.

    Args:
        scope (None | PolicyScope | Unset): Filter by scope
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListPoliciesApiV1PolicyEnginePoliciesGetResponseListPoliciesApiV1PolicyEnginePoliciesGet
    """

    return sync_detailed(
        client=client,
        scope=scope,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    scope: None | PolicyScope | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError | ListPoliciesApiV1PolicyEnginePoliciesGetResponseListPoliciesApiV1PolicyEnginePoliciesGet
]:
    """List Policies

     List all policies for the org, optionally filtered by scope.

    Args:
        scope (None | PolicyScope | Unset): Filter by scope
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ListPoliciesApiV1PolicyEnginePoliciesGetResponseListPoliciesApiV1PolicyEnginePoliciesGet]
    """

    kwargs = _get_kwargs(
        scope=scope,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    scope: None | PolicyScope | Unset = UNSET,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | ListPoliciesApiV1PolicyEnginePoliciesGetResponseListPoliciesApiV1PolicyEnginePoliciesGet
    | None
):
    """List Policies

     List all policies for the org, optionally filtered by scope.

    Args:
        scope (None | PolicyScope | Unset): Filter by scope
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ListPoliciesApiV1PolicyEnginePoliciesGetResponseListPoliciesApiV1PolicyEnginePoliciesGet
    """

    return (
        await asyncio_detailed(
            client=client,
            scope=scope,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
