from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.add_blue_team_action_api_v1_purple_team_exercises_exercise_id_response_post_response_add_blue_team_action_api_v1_purple_team_exercises_exercise_id_response_post import (
    AddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePostResponseAddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePost,
)
from ...models.blue_team_action_request import BlueTeamActionRequest
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    exercise_id: str,
    *,
    body: BlueTeamActionRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/purple-team/exercises/{exercise_id}/response".format(
            exercise_id=quote(str(exercise_id), safe=""),
        ),
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    AddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePostResponseAddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePost
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = AddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePostResponseAddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePost.from_dict(
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
    AddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePostResponseAddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePost
    | HTTPValidationError
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    exercise_id: str,
    *,
    client: AuthenticatedClient,
    body: BlueTeamActionRequest,
) -> Response[
    AddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePostResponseAddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePost
    | HTTPValidationError
]:
    """Add a blue team containment/response action

     Log a blue team response action for a specific attack step.
    Tracks: action type, actor, effectiveness, timestamp.

    Args:
        exercise_id (str):
        body (BlueTeamActionRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePostResponseAddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        exercise_id=exercise_id,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    exercise_id: str,
    *,
    client: AuthenticatedClient,
    body: BlueTeamActionRequest,
) -> (
    AddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePostResponseAddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePost
    | HTTPValidationError
    | None
):
    """Add a blue team containment/response action

     Log a blue team response action for a specific attack step.
    Tracks: action type, actor, effectiveness, timestamp.

    Args:
        exercise_id (str):
        body (BlueTeamActionRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePostResponseAddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePost | HTTPValidationError
    """

    return sync_detailed(
        exercise_id=exercise_id,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    exercise_id: str,
    *,
    client: AuthenticatedClient,
    body: BlueTeamActionRequest,
) -> Response[
    AddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePostResponseAddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePost
    | HTTPValidationError
]:
    """Add a blue team containment/response action

     Log a blue team response action for a specific attack step.
    Tracks: action type, actor, effectiveness, timestamp.

    Args:
        exercise_id (str):
        body (BlueTeamActionRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[AddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePostResponseAddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        exercise_id=exercise_id,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    exercise_id: str,
    *,
    client: AuthenticatedClient,
    body: BlueTeamActionRequest,
) -> (
    AddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePostResponseAddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePost
    | HTTPValidationError
    | None
):
    """Add a blue team containment/response action

     Log a blue team response action for a specific attack step.
    Tracks: action type, actor, effectiveness, timestamp.

    Args:
        exercise_id (str):
        body (BlueTeamActionRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        AddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePostResponseAddBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            exercise_id=exercise_id,
            client=client,
            body=body,
        )
    ).parsed
