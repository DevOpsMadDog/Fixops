from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.compliance_template_response import ComplianceTemplateResponse
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    framework: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/compliance/templates/{framework}".format(
            framework=quote(str(framework), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | list[ComplianceTemplateResponse] | None:
    if response.status_code == 200:
        response_200 = []
        _response_200 = response.json()
        for response_200_item_data in _response_200:
            response_200_item = ComplianceTemplateResponse.from_dict(response_200_item_data)

            response_200.append(response_200_item)

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
) -> Response[HTTPValidationError | list[ComplianceTemplateResponse]]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    framework: str,
    *,
    client: AuthenticatedClient,
) -> Response[HTTPValidationError | list[ComplianceTemplateResponse]]:
    """Get Framework Templates

     Get all templates for a specific compliance framework.

    Args:
        framework (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[ComplianceTemplateResponse]]
    """

    kwargs = _get_kwargs(
        framework=framework,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    framework: str,
    *,
    client: AuthenticatedClient,
) -> HTTPValidationError | list[ComplianceTemplateResponse] | None:
    """Get Framework Templates

     Get all templates for a specific compliance framework.

    Args:
        framework (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[ComplianceTemplateResponse]
    """

    return sync_detailed(
        framework=framework,
        client=client,
    ).parsed


async def asyncio_detailed(
    framework: str,
    *,
    client: AuthenticatedClient,
) -> Response[HTTPValidationError | list[ComplianceTemplateResponse]]:
    """Get Framework Templates

     Get all templates for a specific compliance framework.

    Args:
        framework (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | list[ComplianceTemplateResponse]]
    """

    kwargs = _get_kwargs(
        framework=framework,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    framework: str,
    *,
    client: AuthenticatedClient,
) -> HTTPValidationError | list[ComplianceTemplateResponse] | None:
    """Get Framework Templates

     Get all templates for a specific compliance framework.

    Args:
        framework (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | list[ComplianceTemplateResponse]
    """

    return (
        await asyncio_detailed(
            framework=framework,
            client=client,
        )
    ).parsed
