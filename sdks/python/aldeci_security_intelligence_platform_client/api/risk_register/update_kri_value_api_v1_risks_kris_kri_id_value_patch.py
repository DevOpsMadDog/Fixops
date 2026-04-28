from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.update_kri_value_api_v1_risks_kris_kri_id_value_patch_response_update_kri_value_api_v1_risks_kris_kri_id_value_patch import (
    UpdateKriValueApiV1RisksKrisKriIdValuePatchResponseUpdateKriValueApiV1RisksKrisKriIdValuePatch,
)
from ...models.update_kri_value_request import UpdateKRIValueRequest
from ...types import Response


def _get_kwargs(
    kri_id: str,
    *,
    body: UpdateKRIValueRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "patch",
        "url": "/api/v1/risks/kris/{kri_id}/value".format(
            kri_id=quote(str(kri_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | UpdateKriValueApiV1RisksKrisKriIdValuePatchResponseUpdateKriValueApiV1RisksKrisKriIdValuePatch
    | None
):
    if response.status_code == 200:
        response_200 = (
            UpdateKriValueApiV1RisksKrisKriIdValuePatchResponseUpdateKriValueApiV1RisksKrisKriIdValuePatch.from_dict(
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
    HTTPValidationError | UpdateKriValueApiV1RisksKrisKriIdValuePatchResponseUpdateKriValueApiV1RisksKrisKriIdValuePatch
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    kri_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateKRIValueRequest,
) -> Response[
    HTTPValidationError | UpdateKriValueApiV1RisksKrisKriIdValuePatchResponseUpdateKriValueApiV1RisksKrisKriIdValuePatch
]:
    """Update KRI current value

    Args:
        kri_id (str):
        body (UpdateKRIValueRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UpdateKriValueApiV1RisksKrisKriIdValuePatchResponseUpdateKriValueApiV1RisksKrisKriIdValuePatch]
    """

    kwargs = _get_kwargs(
        kri_id=kri_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    kri_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateKRIValueRequest,
) -> (
    HTTPValidationError
    | UpdateKriValueApiV1RisksKrisKriIdValuePatchResponseUpdateKriValueApiV1RisksKrisKriIdValuePatch
    | None
):
    """Update KRI current value

    Args:
        kri_id (str):
        body (UpdateKRIValueRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UpdateKriValueApiV1RisksKrisKriIdValuePatchResponseUpdateKriValueApiV1RisksKrisKriIdValuePatch
    """

    return sync_detailed(
        kri_id=kri_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    kri_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateKRIValueRequest,
) -> Response[
    HTTPValidationError | UpdateKriValueApiV1RisksKrisKriIdValuePatchResponseUpdateKriValueApiV1RisksKrisKriIdValuePatch
]:
    """Update KRI current value

    Args:
        kri_id (str):
        body (UpdateKRIValueRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UpdateKriValueApiV1RisksKrisKriIdValuePatchResponseUpdateKriValueApiV1RisksKrisKriIdValuePatch]
    """

    kwargs = _get_kwargs(
        kri_id=kri_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    kri_id: str,
    *,
    client: AuthenticatedClient,
    body: UpdateKRIValueRequest,
) -> (
    HTTPValidationError
    | UpdateKriValueApiV1RisksKrisKriIdValuePatchResponseUpdateKriValueApiV1RisksKrisKriIdValuePatch
    | None
):
    """Update KRI current value

    Args:
        kri_id (str):
        body (UpdateKRIValueRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UpdateKriValueApiV1RisksKrisKriIdValuePatchResponseUpdateKriValueApiV1RisksKrisKriIdValuePatch
    """

    return (
        await asyncio_detailed(
            kri_id=kri_id,
            client=client,
            body=body,
        )
    ).parsed
