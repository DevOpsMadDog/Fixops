from http import HTTPStatus
from typing import Any

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.body_validate_input_api_v1_validate_input_post import BodyValidateInputApiV1ValidateInputPost
from ...models.http_validation_error import HTTPValidationError
from ...models.validation_result import ValidationResult
from ...types import UNSET, Response, Unset


def _get_kwargs(
    *,
    body: BodyValidateInputApiV1ValidateInputPost,
    input_type: None | str | Unset = UNSET,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    params: dict[str, Any] = {}

    json_input_type: None | str | Unset
    if isinstance(input_type, Unset):
        json_input_type = UNSET
    else:
        json_input_type = input_type
    params["input_type"] = json_input_type

    params = {k: v for k, v in params.items() if v is not UNSET and v is not None}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/validate/input",
        "params": params,
    }

    _kwargs["files"] = body.to_multipart()

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> HTTPValidationError | ValidationResult | None:
    if response.status_code == 200:
        response_200 = ValidationResult.from_dict(response.json())

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
) -> Response[HTTPValidationError | ValidationResult]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: BodyValidateInputApiV1ValidateInputPost,
    input_type: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | ValidationResult]:
    """Validate Input

     Validate a security tool output without persisting it.

    This endpoint tests whether FixOps can successfully parse and normalize
    the provided file. Use this to verify compatibility before deployment.

    Args:
        file: The security tool output file to validate
        input_type: Optional hint for input type (sarif, sbom, cve, vex, cnapp)

    Returns:
        ValidationResult with parsing status, detected format, and any warnings

    Args:
        input_type (None | str | Unset):
        body (BodyValidateInputApiV1ValidateInputPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ValidationResult]
    """

    kwargs = _get_kwargs(
        body=body,
        input_type=input_type,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: BodyValidateInputApiV1ValidateInputPost,
    input_type: None | str | Unset = UNSET,
) -> HTTPValidationError | ValidationResult | None:
    """Validate Input

     Validate a security tool output without persisting it.

    This endpoint tests whether FixOps can successfully parse and normalize
    the provided file. Use this to verify compatibility before deployment.

    Args:
        file: The security tool output file to validate
        input_type: Optional hint for input type (sarif, sbom, cve, vex, cnapp)

    Returns:
        ValidationResult with parsing status, detected format, and any warnings

    Args:
        input_type (None | str | Unset):
        body (BodyValidateInputApiV1ValidateInputPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ValidationResult
    """

    return sync_detailed(
        client=client,
        body=body,
        input_type=input_type,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: BodyValidateInputApiV1ValidateInputPost,
    input_type: None | str | Unset = UNSET,
) -> Response[HTTPValidationError | ValidationResult]:
    """Validate Input

     Validate a security tool output without persisting it.

    This endpoint tests whether FixOps can successfully parse and normalize
    the provided file. Use this to verify compatibility before deployment.

    Args:
        file: The security tool output file to validate
        input_type: Optional hint for input type (sarif, sbom, cve, vex, cnapp)

    Returns:
        ValidationResult with parsing status, detected format, and any warnings

    Args:
        input_type (None | str | Unset):
        body (BodyValidateInputApiV1ValidateInputPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | ValidationResult]
    """

    kwargs = _get_kwargs(
        body=body,
        input_type=input_type,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: BodyValidateInputApiV1ValidateInputPost,
    input_type: None | str | Unset = UNSET,
) -> HTTPValidationError | ValidationResult | None:
    """Validate Input

     Validate a security tool output without persisting it.

    This endpoint tests whether FixOps can successfully parse and normalize
    the provided file. Use this to verify compatibility before deployment.

    Args:
        file: The security tool output file to validate
        input_type: Optional hint for input type (sarif, sbom, cve, vex, cnapp)

    Returns:
        ValidationResult with parsing status, detected format, and any warnings

    Args:
        input_type (None | str | Unset):
        body (BodyValidateInputApiV1ValidateInputPost):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | ValidationResult
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
            input_type=input_type,
        )
    ).parsed
