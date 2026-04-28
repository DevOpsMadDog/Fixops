from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.classification_validation_response import ClassificationValidationResponse
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    app_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/apps/{app_id}/validate".format(
            app_id=quote(str(app_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> ClassificationValidationResponse | HTTPValidationError | None:
    if response.status_code == 200:
        response_200 = ClassificationValidationResponse.from_dict(response.json())

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
) -> Response[ClassificationValidationResponse | HTTPValidationError]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    app_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[ClassificationValidationResponse | HTTPValidationError]:
    """Validate classification consistency

     Validate that policy classification level is appropriate for data classification.

    Checks include:
    - Policy level must meet minimum required by data type (PHI/PCI/PII → CUI minimum)
    - TOP_SECRET/SCI data cannot have UNCLASSIFIED policies
    - ITAR in compliance list must have itar_controlled = true
    - Air-gapped environments should not reference cloud-only scanners

    Args:
        app_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ClassificationValidationResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        app_id=app_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    app_id: str,
    *,
    client: AuthenticatedClient,
) -> ClassificationValidationResponse | HTTPValidationError | None:
    """Validate classification consistency

     Validate that policy classification level is appropriate for data classification.

    Checks include:
    - Policy level must meet minimum required by data type (PHI/PCI/PII → CUI minimum)
    - TOP_SECRET/SCI data cannot have UNCLASSIFIED policies
    - ITAR in compliance list must have itar_controlled = true
    - Air-gapped environments should not reference cloud-only scanners

    Args:
        app_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ClassificationValidationResponse | HTTPValidationError
    """

    return sync_detailed(
        app_id=app_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    app_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[ClassificationValidationResponse | HTTPValidationError]:
    """Validate classification consistency

     Validate that policy classification level is appropriate for data classification.

    Checks include:
    - Policy level must meet minimum required by data type (PHI/PCI/PII → CUI minimum)
    - TOP_SECRET/SCI data cannot have UNCLASSIFIED policies
    - ITAR in compliance list must have itar_controlled = true
    - Air-gapped environments should not reference cloud-only scanners

    Args:
        app_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[ClassificationValidationResponse | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        app_id=app_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    app_id: str,
    *,
    client: AuthenticatedClient,
) -> ClassificationValidationResponse | HTTPValidationError | None:
    """Validate classification consistency

     Validate that policy classification level is appropriate for data classification.

    Checks include:
    - Policy level must meet minimum required by data type (PHI/PCI/PII → CUI minimum)
    - TOP_SECRET/SCI data cannot have UNCLASSIFIED policies
    - ITAR in compliance list must have itar_controlled = true
    - Air-gapped environments should not reference cloud-only scanners

    Args:
        app_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        ClassificationValidationResponse | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            app_id=app_id,
            client=client,
        )
    ).parsed
