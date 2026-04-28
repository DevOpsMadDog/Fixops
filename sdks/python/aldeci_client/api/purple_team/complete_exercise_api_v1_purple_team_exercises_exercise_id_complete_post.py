from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.complete_exercise_api_v1_purple_team_exercises_exercise_id_complete_post_response_complete_exercise_api_v1_purple_team_exercises_exercise_id_complete_post import (
    CompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePostResponseCompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePost,
)
from ...models.http_validation_error import HTTPValidationError
from ...types import Response


def _get_kwargs(
    exercise_id: str,
) -> dict[str, Any]:

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/purple-team/exercises/{exercise_id}/complete".format(
            exercise_id=quote(str(exercise_id), safe=""),
        ),
    }

    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> (
    CompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePostResponseCompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePost
    | HTTPValidationError
    | None
):
    if response.status_code == 200:
        response_200 = CompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePostResponseCompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePost.from_dict(
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
    CompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePostResponseCompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePost
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
) -> Response[
    CompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePostResponseCompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePost
    | HTTPValidationError
]:
    """Complete exercise and compute scores + gaps

     Mark the exercise as complete. Automatically:
    - Computes red/blue team scores (detection rate, MTTD, coverage score)
    - Identifies detection gaps (undetected steps → backlog)
    Returns the completed exercise with scores and gap list.

    Args:
        exercise_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePostResponseCompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        exercise_id=exercise_id,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    exercise_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    CompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePostResponseCompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePost
    | HTTPValidationError
    | None
):
    """Complete exercise and compute scores + gaps

     Mark the exercise as complete. Automatically:
    - Computes red/blue team scores (detection rate, MTTD, coverage score)
    - Identifies detection gaps (undetected steps → backlog)
    Returns the completed exercise with scores and gap list.

    Args:
        exercise_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePostResponseCompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePost | HTTPValidationError
    """

    return sync_detailed(
        exercise_id=exercise_id,
        client=client,
    ).parsed


async def asyncio_detailed(
    exercise_id: str,
    *,
    client: AuthenticatedClient,
) -> Response[
    CompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePostResponseCompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePost
    | HTTPValidationError
]:
    """Complete exercise and compute scores + gaps

     Mark the exercise as complete. Automatically:
    - Computes red/blue team scores (detection rate, MTTD, coverage score)
    - Identifies detection gaps (undetected steps → backlog)
    Returns the completed exercise with scores and gap list.

    Args:
        exercise_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[CompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePostResponseCompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePost | HTTPValidationError]
    """

    kwargs = _get_kwargs(
        exercise_id=exercise_id,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    exercise_id: str,
    *,
    client: AuthenticatedClient,
) -> (
    CompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePostResponseCompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePost
    | HTTPValidationError
    | None
):
    """Complete exercise and compute scores + gaps

     Mark the exercise as complete. Automatically:
    - Computes red/blue team scores (detection rate, MTTD, coverage score)
    - Identifies detection gaps (undetected steps → backlog)
    Returns the completed exercise with scores and gap list.

    Args:
        exercise_id (str):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        CompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePostResponseCompleteExerciseApiV1PurpleTeamExercisesExerciseIdCompletePost | HTTPValidationError
    """

    return (
        await asyncio_detailed(
            exercise_id=exercise_id,
            client=client,
        )
    ).parsed
