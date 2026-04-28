from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.key_result_update import KeyResultUpdate
from ...models.update_key_result_api_v1_metrics_objectives_obj_id_key_results_kr_id_patch_response_update_key_result_api_v1_metrics_objectives_obj_id_key_results_kr_id_patch import (
    UpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatchResponseUpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatch,
)
from ...types import Response


def _get_kwargs(
    obj_id: str,
    kr_id: str,
    *,
    body: KeyResultUpdate,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "patch",
        "url": "/api/v1/metrics/objectives/{obj_id}/key-results/{kr_id}".format(
            obj_id=quote(str(obj_id), safe=""),
            kr_id=quote(str(kr_id), safe=""),
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
    | UpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatchResponseUpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatch
    | None
):
    if response.status_code == 200:
        response_200 = UpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatchResponseUpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatch.from_dict(
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
    | UpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatchResponseUpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatch
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    obj_id: str,
    kr_id: str,
    *,
    client: AuthenticatedClient,
    body: KeyResultUpdate,
) -> Response[
    HTTPValidationError
    | UpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatchResponseUpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatch
]:
    """Update key result progress

    Args:
        obj_id (str):
        kr_id (str):
        body (KeyResultUpdate): Request body for updating a key result's progress.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatchResponseUpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatch]
    """

    kwargs = _get_kwargs(
        obj_id=obj_id,
        kr_id=kr_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    obj_id: str,
    kr_id: str,
    *,
    client: AuthenticatedClient,
    body: KeyResultUpdate,
) -> (
    HTTPValidationError
    | UpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatchResponseUpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatch
    | None
):
    """Update key result progress

    Args:
        obj_id (str):
        kr_id (str):
        body (KeyResultUpdate): Request body for updating a key result's progress.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatchResponseUpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatch
    """

    return sync_detailed(
        obj_id=obj_id,
        kr_id=kr_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    obj_id: str,
    kr_id: str,
    *,
    client: AuthenticatedClient,
    body: KeyResultUpdate,
) -> Response[
    HTTPValidationError
    | UpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatchResponseUpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatch
]:
    """Update key result progress

    Args:
        obj_id (str):
        kr_id (str):
        body (KeyResultUpdate): Request body for updating a key result's progress.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | UpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatchResponseUpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatch]
    """

    kwargs = _get_kwargs(
        obj_id=obj_id,
        kr_id=kr_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    obj_id: str,
    kr_id: str,
    *,
    client: AuthenticatedClient,
    body: KeyResultUpdate,
) -> (
    HTTPValidationError
    | UpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatchResponseUpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatch
    | None
):
    """Update key result progress

    Args:
        obj_id (str):
        kr_id (str):
        body (KeyResultUpdate): Request body for updating a key result's progress.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | UpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatchResponseUpdateKeyResultApiV1MetricsObjectivesObjIdKeyResultsKrIdPatch
    """

    return (
        await asyncio_detailed(
            obj_id=obj_id,
            kr_id=kr_id,
            client=client,
            body=body,
        )
    ).parsed
