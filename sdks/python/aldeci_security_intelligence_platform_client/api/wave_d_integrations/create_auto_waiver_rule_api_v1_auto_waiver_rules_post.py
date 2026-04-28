from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.auto_waiver_rule_request import AutoWaiverRuleRequest
from ...models.create_auto_waiver_rule_api_v1_auto_waiver_rules_post_response_create_auto_waiver_rule_api_v1_auto_waiver_rules_post import (
    CreateAutoWaiverRuleApiV1AutoWaiverRulesPostResponseCreateAutoWaiverRuleApiV1AutoWaiverRulesPost,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: AutoWaiverRuleRequest,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/auto-waiver-rules",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    CreateAutoWaiverRuleApiV1AutoWaiverRulesPostResponseCreateAutoWaiverRuleApiV1AutoWaiverRulesPost
    | HTTPValidationError
    | None
):
    if response.status_code == 201:
        response_201 = (
            CreateAutoWaiverRuleApiV1AutoWaiverRulesPostResponseCreateAutoWaiverRuleApiV1AutoWaiverRulesPost.from_dict(
                response.json()
            )
        )

        return response_201

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
    CreateAutoWaiverRuleApiV1AutoWaiverRulesPostResponseCreateAutoWaiverRuleApiV1AutoWaiverRulesPost
    | HTTPValidationError
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
    body: AutoWaiverRuleRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    CreateAutoWaiverRuleApiV1AutoWaiverRulesPostResponseCreateAutoWaiverRuleApiV1AutoWaiverRulesPost
    | HTTPValidationError
]:
    """Create Auto Waiver Rule

     Register an auto-waiver rule. (Multica 1f5d8fc9)

    Args:
        x_org_id (None | str | Unset):
        body (AutoWaiverRuleRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateAutoWaiverRuleApiV1AutoWaiverRulesPostResponseCreateAutoWaiverRuleApiV1AutoWaiverRulesPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: AutoWaiverRuleRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    CreateAutoWaiverRuleApiV1AutoWaiverRulesPostResponseCreateAutoWaiverRuleApiV1AutoWaiverRulesPost
    | HTTPValidationError
    | None
):
    """Create Auto Waiver Rule

     Register an auto-waiver rule. (Multica 1f5d8fc9)

    Args:
        x_org_id (None | str | Unset):
        body (AutoWaiverRuleRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateAutoWaiverRuleApiV1AutoWaiverRulesPostResponseCreateAutoWaiverRuleApiV1AutoWaiverRulesPost | HTTPValidationError
    """

    return sync_detailed(
        client=client,
        body=body,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: AutoWaiverRuleRequest,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    CreateAutoWaiverRuleApiV1AutoWaiverRulesPostResponseCreateAutoWaiverRuleApiV1AutoWaiverRulesPost
    | HTTPValidationError
]:
    """Create Auto Waiver Rule

     Register an auto-waiver rule. (Multica 1f5d8fc9)

    Args:
        x_org_id (None | str | Unset):
        body (AutoWaiverRuleRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CreateAutoWaiverRuleApiV1AutoWaiverRulesPostResponseCreateAutoWaiverRuleApiV1AutoWaiverRulesPost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        body=body,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: AutoWaiverRuleRequest,
    x_org_id: None | str | Unset = UNSET,
) -> (
    CreateAutoWaiverRuleApiV1AutoWaiverRulesPostResponseCreateAutoWaiverRuleApiV1AutoWaiverRulesPost
    | HTTPValidationError
    | None
):
    """Create Auto Waiver Rule

     Register an auto-waiver rule. (Multica 1f5d8fc9)

    Args:
        x_org_id (None | str | Unset):
        body (AutoWaiverRuleRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CreateAutoWaiverRuleApiV1AutoWaiverRulesPostResponseCreateAutoWaiverRuleApiV1AutoWaiverRulesPost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            x_org_id=x_org_id,
        )
    ).parsed
