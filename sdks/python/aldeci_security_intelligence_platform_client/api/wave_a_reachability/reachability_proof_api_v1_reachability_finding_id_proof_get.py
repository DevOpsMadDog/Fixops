from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.reachability_proof_api_v1_reachability_finding_id_proof_get_response_reachability_proof_api_v1_reachability_finding_id_proof_get import (
    ReachabilityProofApiV1ReachabilityFindingIdProofGetResponseReachabilityProofApiV1ReachabilityFindingIdProofGet,
)
from ...types import UNSET, Response, Unset


def _get_kwargs(
    finding_id: str,
    *,
    x_org_id: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}
    if not isinstance(x_org_id, Unset):
        headers["X-Org-ID"] = x_org_id

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/reachability/{finding_id}/proof".format(
            finding_id=quote(str(finding_id), safe=""),
        ),
    }

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | ReachabilityProofApiV1ReachabilityFindingIdProofGetResponseReachabilityProofApiV1ReachabilityFindingIdProofGet
    | None
):
    if response.status_code == 200:
        response_200 = ReachabilityProofApiV1ReachabilityFindingIdProofGetResponseReachabilityProofApiV1ReachabilityFindingIdProofGet.from_dict(
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
    | ReachabilityProofApiV1ReachabilityFindingIdProofGetResponseReachabilityProofApiV1ReachabilityFindingIdProofGet
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    finding_id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError
    | ReachabilityProofApiV1ReachabilityFindingIdProofGetResponseReachabilityProofApiV1ReachabilityFindingIdProofGet
]:
    """Return reachability proof / verdict for a finding

     Return the reachability verdict (path) for a finding.

    Wraps ``FunctionReachabilityEngine.get_finding_verdict``.
    Returns 404 if no verdict has been computed.

    Args:
        finding_id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ReachabilityProofApiV1ReachabilityFindingIdProofGetResponseReachabilityProofApiV1ReachabilityFindingIdProofGet]
    """

    kwargs = _get_kwargs(
        finding_id=finding_id,
        x_org_id=x_org_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    finding_id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | ReachabilityProofApiV1ReachabilityFindingIdProofGetResponseReachabilityProofApiV1ReachabilityFindingIdProofGet
    | None
):
    """Return reachability proof / verdict for a finding

     Return the reachability verdict (path) for a finding.

    Wraps ``FunctionReachabilityEngine.get_finding_verdict``.
    Returns 404 if no verdict has been computed.

    Args:
        finding_id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ReachabilityProofApiV1ReachabilityFindingIdProofGetResponseReachabilityProofApiV1ReachabilityFindingIdProofGet
    """

    return sync_detailed(
        finding_id=finding_id,
        client=client,
        x_org_id=x_org_id,
    ).parsed


async def asyncio_detailed(
    finding_id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> Response[
    HTTPValidationError
    | ReachabilityProofApiV1ReachabilityFindingIdProofGetResponseReachabilityProofApiV1ReachabilityFindingIdProofGet
]:
    """Return reachability proof / verdict for a finding

     Return the reachability verdict (path) for a finding.

    Wraps ``FunctionReachabilityEngine.get_finding_verdict``.
    Returns 404 if no verdict has been computed.

    Args:
        finding_id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ReachabilityProofApiV1ReachabilityFindingIdProofGetResponseReachabilityProofApiV1ReachabilityFindingIdProofGet]
    """

    kwargs = _get_kwargs(
        finding_id=finding_id,
        x_org_id=x_org_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    finding_id: str,
    *,
    client: AuthenticatedClient,
    x_org_id: None | str | Unset = UNSET,
) -> (
    HTTPValidationError
    | ReachabilityProofApiV1ReachabilityFindingIdProofGetResponseReachabilityProofApiV1ReachabilityFindingIdProofGet
    | None
):
    """Return reachability proof / verdict for a finding

     Return the reachability verdict (path) for a finding.

    Wraps ``FunctionReachabilityEngine.get_finding_verdict``.
    Returns 404 if no verdict has been computed.

    Args:
        finding_id (str):
        x_org_id (None | str | Unset):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ReachabilityProofApiV1ReachabilityFindingIdProofGetResponseReachabilityProofApiV1ReachabilityFindingIdProofGet
    """

    return (
        await asyncio_detailed(
            finding_id=finding_id,
            client=client,
            x_org_id=x_org_id,
        )
    ).parsed
