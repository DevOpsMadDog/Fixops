from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.deployment_record import DeploymentRecord
from ...models.http_validation_error import HTTPValidationError
from ...models.record_deployment_api_v1_metrics_deployments_post_response_record_deployment_api_v1_metrics_deployments_post import (
    RecordDeploymentApiV1MetricsDeploymentsPostResponseRecordDeploymentApiV1MetricsDeploymentsPost,
)
from ...types import Response


def _get_kwargs(
    *,
    body: DeploymentRecord,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/metrics/deployments",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    HTTPValidationError
    | RecordDeploymentApiV1MetricsDeploymentsPostResponseRecordDeploymentApiV1MetricsDeploymentsPost
    | None
):
    if response.status_code == 201:
        response_201 = (
            RecordDeploymentApiV1MetricsDeploymentsPostResponseRecordDeploymentApiV1MetricsDeploymentsPost.from_dict(
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
    HTTPValidationError | RecordDeploymentApiV1MetricsDeploymentsPostResponseRecordDeploymentApiV1MetricsDeploymentsPost
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
    body: DeploymentRecord,
) -> Response[
    HTTPValidationError | RecordDeploymentApiV1MetricsDeploymentsPostResponseRecordDeploymentApiV1MetricsDeploymentsPost
]:
    """Record a deployment

     Record a deployment event for Change Failure Rate tracking.

    Args:
        body (DeploymentRecord): Request body for recording a deployment.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RecordDeploymentApiV1MetricsDeploymentsPostResponseRecordDeploymentApiV1MetricsDeploymentsPost]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: DeploymentRecord,
) -> (
    HTTPValidationError
    | RecordDeploymentApiV1MetricsDeploymentsPostResponseRecordDeploymentApiV1MetricsDeploymentsPost
    | None
):
    """Record a deployment

     Record a deployment event for Change Failure Rate tracking.

    Args:
        body (DeploymentRecord): Request body for recording a deployment.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RecordDeploymentApiV1MetricsDeploymentsPostResponseRecordDeploymentApiV1MetricsDeploymentsPost
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: DeploymentRecord,
) -> Response[
    HTTPValidationError | RecordDeploymentApiV1MetricsDeploymentsPostResponseRecordDeploymentApiV1MetricsDeploymentsPost
]:
    """Record a deployment

     Record a deployment event for Change Failure Rate tracking.

    Args:
        body (DeploymentRecord): Request body for recording a deployment.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RecordDeploymentApiV1MetricsDeploymentsPostResponseRecordDeploymentApiV1MetricsDeploymentsPost]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: DeploymentRecord,
) -> (
    HTTPValidationError
    | RecordDeploymentApiV1MetricsDeploymentsPostResponseRecordDeploymentApiV1MetricsDeploymentsPost
    | None
):
    """Record a deployment

     Record a deployment event for Change Failure Rate tracking.

    Args:
        body (DeploymentRecord): Request body for recording a deployment.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RecordDeploymentApiV1MetricsDeploymentsPostResponseRecordDeploymentApiV1MetricsDeploymentsPost
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
