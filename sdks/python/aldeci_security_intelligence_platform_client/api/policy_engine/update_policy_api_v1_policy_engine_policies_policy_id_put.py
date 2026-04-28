from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.update_policy_api_v1_policy_engine_policies_policy_id_put_response_update_policy_api_v1_policy_engine_policies_policy_id_put import (
    UpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPutResponseUpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPut,
)
from ...models.update_policy_request import UpdatePolicyRequest
from ...types import UNSET, Response, Unset


def _get_kwargs(
    policy_id: str,
    *,
    body: UpdatePolicyRequest,
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
        "method": "put",
        "url": "/api/v1/policy-engine/policies/{policy_id}".format(
            policy_id=quote(str(policy_id), safe=""),
        ),
        "params": params,
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | UpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPutResponseUpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPut
    | None
):
    if response.status_code == 200:
        response_200 = UpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPutResponseUpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPut.from_dict(
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
    HTTPValidationError
    | UpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPutResponseUpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPut
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
    body: UpdatePolicyRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError
    | UpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPutResponseUpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPut
]:
    """Update Policy

     Update a policy (version auto-incremented).

    Args:
        policy_id (str):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (UpdatePolicyRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPutResponseUpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPut]
    """

    kwargs = _get_kwargs(
        policy_id=policy_id,
        body=body,
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
    body: UpdatePolicyRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | UpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPutResponseUpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPut
    | None
):
    """Update Policy

     Update a policy (version auto-incremented).

    Args:
        policy_id (str):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (UpdatePolicyRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPutResponseUpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPut
    """

    return sync_detailed(
        policy_id=policy_id,
        client=client,
        body=body,
        org_id=org_id,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    policy_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdatePolicyRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError
    | UpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPutResponseUpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPut
]:
    """Update Policy

     Update a policy (version auto-incremented).

    Args:
        policy_id (str):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (UpdatePolicyRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPutResponseUpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPut]
    """

    kwargs = _get_kwargs(
        policy_id=policy_id,
        body=body,
        org_id=org_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    policy_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdatePolicyRequest,
    org_id: None | str | Unset = UNSET,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | UpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPutResponseUpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPut
    | None
):
    """Update Policy

     Update a policy (version auto-incremented).

    Args:
        policy_id (str):
        org_id (None | str | Unset): Organization ID (query parameter, overrides header)
        x_org_id (None | str | Unset): Organization ID (header)
        body (UpdatePolicyRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPutResponseUpdatePolicyApiV1PolicyEnginePoliciesPolicyIdPut
    """

    return (
        await asyncio_detailed(
            policy_id=policy_id,
            client=client,
            body=body,
            org_id=org_id,
            x_org_id=x_org_id,
        )
    ).parsed
