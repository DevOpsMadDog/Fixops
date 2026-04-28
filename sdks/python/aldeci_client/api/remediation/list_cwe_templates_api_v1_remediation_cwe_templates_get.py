from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.list_cwe_templates_api_v1_remediation_cwe_templates_get_response_list_cwe_templates_api_v1_remediation_cwe_templates_get import (
    ListCweTemplatesApiV1RemediationCweTemplatesGetResponseListCweTemplatesApiV1RemediationCweTemplatesGet,
)
from ...types import Response


def _get_kwargs() -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "get",
        "url": "/api/v1/remediation/cwe-templates",
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ListCweTemplatesApiV1RemediationCweTemplatesGetResponseListCweTemplatesApiV1RemediationCweTemplatesGet | None:
    if response.status_code == 200:
        response_200 = ListCweTemplatesApiV1RemediationCweTemplatesGetResponseListCweTemplatesApiV1RemediationCweTemplatesGet.from_dict(
            response.json()
        )

        return response_200

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[ListCweTemplatesApiV1RemediationCweTemplatesGetResponseListCweTemplatesApiV1RemediationCweTemplatesGet]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[ListCweTemplatesApiV1RemediationCweTemplatesGetResponseListCweTemplatesApiV1RemediationCweTemplatesGet]:
    """List CWE remediation templates

     Return all built-in CWE remediation templates with effort and step counts.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ListCweTemplatesApiV1RemediationCweTemplatesGetResponseListCweTemplatesApiV1RemediationCweTemplatesGet]
    """

    kwargs = _get_kwargs()

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
) -> ListCweTemplatesApiV1RemediationCweTemplatesGetResponseListCweTemplatesApiV1RemediationCweTemplatesGet | None:
    """List CWE remediation templates

     Return all built-in CWE remediation templates with effort and step counts.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ListCweTemplatesApiV1RemediationCweTemplatesGetResponseListCweTemplatesApiV1RemediationCweTemplatesGet
    """

    return sync_detailed(
        client=client,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
) -> Response[ListCweTemplatesApiV1RemediationCweTemplatesGetResponseListCweTemplatesApiV1RemediationCweTemplatesGet]:
    """List CWE remediation templates

     Return all built-in CWE remediation templates with effort and step counts.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ListCweTemplatesApiV1RemediationCweTemplatesGetResponseListCweTemplatesApiV1RemediationCweTemplatesGet]
    """

    kwargs = _get_kwargs()

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
) -> ListCweTemplatesApiV1RemediationCweTemplatesGetResponseListCweTemplatesApiV1RemediationCweTemplatesGet | None:
    """List CWE remediation templates

     Return all built-in CWE remediation templates with effort and step counts.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ListCweTemplatesApiV1RemediationCweTemplatesGetResponseListCweTemplatesApiV1RemediationCweTemplatesGet
    """

    return (
        await asyncio_detailed(
            client=client,
        )
    ).parsed
