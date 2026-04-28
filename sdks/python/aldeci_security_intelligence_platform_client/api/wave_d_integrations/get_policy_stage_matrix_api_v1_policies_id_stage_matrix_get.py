from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.get_policy_stage_matrix_api_v1_policies_id_stage_matrix_get_response_get_policy_stage_matrix_api_v1_policies_id_stage_matrix_get import (
    GetPolicyStageMatrixApiV1PoliciesIdStageMatrixGetResponseGetPolicyStageMatrixApiV1PoliciesIdStageMatrixGet,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import UNSET, Response, Unset


def _get_kwargs(
    id: str,
    *,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/policies/{id}/stage-matrix".format(
            id=quote(str(id), safe=""),
        ),
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    GetPolicyStageMatrixApiV1PoliciesIdStageMatrixGetResponseGetPolicyStageMatrixApiV1PoliciesIdStageMatrixGet
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = GetPolicyStageMatrixApiV1PoliciesIdStageMatrixGetResponseGetPolicyStageMatrixApiV1PoliciesIdStageMatrixGet.from_dict(
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
    GetPolicyStageMatrixApiV1PoliciesIdStageMatrixGetResponseGetPolicyStageMatrixApiV1PoliciesIdStageMatrixGet
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GetPolicyStageMatrixApiV1PoliciesIdStageMatrixGetResponseGetPolicyStageMatrixApiV1PoliciesIdStageMatrixGet
    | HTTPValidationError
]:
    """Get Policy Stage Matrix

     Return the CTEM stage matrix for a policy. (Multica 181dc9f8)

    Args:
        id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetPolicyStageMatrixApiV1PoliciesIdStageMatrixGetResponseGetPolicyStageMatrixApiV1PoliciesIdStageMatrixGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        id=id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GetPolicyStageMatrixApiV1PoliciesIdStageMatrixGetResponseGetPolicyStageMatrixApiV1PoliciesIdStageMatrixGet
    | HTTPValidationError
    | None
):
    """Get Policy Stage Matrix

     Return the CTEM stage matrix for a policy. (Multica 181dc9f8)

    Args:
        id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetPolicyStageMatrixApiV1PoliciesIdStageMatrixGetResponseGetPolicyStageMatrixApiV1PoliciesIdStageMatrixGet | HTTPValidationError
    """

    return sync_detailed(
        id=id,
        client=client,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    GetPolicyStageMatrixApiV1PoliciesIdStageMatrixGetResponseGetPolicyStageMatrixApiV1PoliciesIdStageMatrixGet
    | HTTPValidationError
]:
    """Get Policy Stage Matrix

     Return the CTEM stage matrix for a policy. (Multica 181dc9f8)

    Args:
        id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[GetPolicyStageMatrixApiV1PoliciesIdStageMatrixGetResponseGetPolicyStageMatrixApiV1PoliciesIdStageMatrixGet | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        id=id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> (
    GetPolicyStageMatrixApiV1PoliciesIdStageMatrixGetResponseGetPolicyStageMatrixApiV1PoliciesIdStageMatrixGet
    | HTTPValidationError
    | None
):
    """Get Policy Stage Matrix

     Return the CTEM stage matrix for a policy. (Multica 181dc9f8)

    Args:
        id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        GetPolicyStageMatrixApiV1PoliciesIdStageMatrixGetResponseGetPolicyStageMatrixApiV1PoliciesIdStageMatrixGet | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            id=id,
            client=client,
            x_org_id=x_org_id,
        )
    ).parsed
