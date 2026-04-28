from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.http_validation_error import HTTPValidationError
from ...models.record_step_request import RecordStepRequest
from ...models.record_step_result_api_v1_purple_team_exercises_exercise_id_steps_step_index_post_response_record_step_result_api_v1_purple_team_exercises_exercise_id_steps_step_index_post import (
    RecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPostResponseRecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPost,
)
from ...types import Response


def _get_kwargs(
    exercise_id: str,
    step_index: int,
    *,
    body: RecordStepRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/api/v1/purple-team/exercises/{exercise_id}/steps/{step_index}".format(
            exercise_id=quote(str(exercise_id), safe=""),
            step_index=quote(str(step_index), safe=""),
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
    | RecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPostResponseRecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPost
    | None
):
    if response.status_code == 200:
        response_200 = RecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPostResponseRecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPost.from_dict(
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
    | RecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPostResponseRecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPost
]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    exercise_id: str,
    step_index: int,
    *,
    client: AuthenticatedClient,
    body: RecordStepRequest,
) -> Response[
    HTTPValidationError
    | RecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPostResponseRecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPost
]:
    """Record detection result for an attack step

     Record whether ALDECI detected a specific attack step.
    Captures: outcome, detection engine, alert fired, time to detect.
    Exercise must be in 'active' status.

    Args:
        exercise_id (str):
        step_index (int):
        body (RecordStepRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPostResponseRecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPost]
    """

    kwargs = _get_kwargs(
        exercise_id=exercise_id,
        step_index=step_index,
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    exercise_id: str,
    step_index: int,
    *,
    client: AuthenticatedClient,
    body: RecordStepRequest,
) -> (
    HTTPValidationError
    | RecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPostResponseRecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPost
    | None
):
    """Record detection result for an attack step

     Record whether ALDECI detected a specific attack step.
    Captures: outcome, detection engine, alert fired, time to detect.
    Exercise must be in 'active' status.

    Args:
        exercise_id (str):
        step_index (int):
        body (RecordStepRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPostResponseRecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPost
    """

    return sync_detailed(
        exercise_id=exercise_id,
        step_index=step_index,
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    exercise_id: str,
    step_index: int,
    *,
    client: AuthenticatedClient,
    body: RecordStepRequest,
) -> Response[
    HTTPValidationError
    | RecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPostResponseRecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPost
]:
    """Record detection result for an attack step

     Record whether ALDECI detected a specific attack step.
    Captures: outcome, detection engine, alert fired, time to detect.
    Exercise must be in 'active' status.

    Args:
        exercise_id (str):
        step_index (int):
        body (RecordStepRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[HTTPValidationError | RecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPostResponseRecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPost]
    """

    kwargs = _get_kwargs(
        exercise_id=exercise_id,
        step_index=step_index,
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    exercise_id: str,
    step_index: int,
    *,
    client: AuthenticatedClient,
    body: RecordStepRequest,
) -> (
    HTTPValidationError
    | RecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPostResponseRecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPost
    | None
):
    """Record detection result for an attack step

     Record whether ALDECI detected a specific attack step.
    Captures: outcome, detection engine, alert fired, time to detect.
    Exercise must be in 'active' status.

    Args:
        exercise_id (str):
        step_index (int):
        body (RecordStepRequest):

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        HTTPValidationError | RecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPostResponseRecordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPost
    """

    return (
        await asyncio_detailed(
            exercise_id=exercise_id,
            step_index=step_index,
            client=client,
            body=body,
        )
    ).parsed
