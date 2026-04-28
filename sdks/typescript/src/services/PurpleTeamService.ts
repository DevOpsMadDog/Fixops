/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { BlueTeamActionRequest } from '../models/BlueTeamActionRequest';
import type { CreateExerciseRequest } from '../models/CreateExerciseRequest';
import type { ExerciseSummaryResponse } from '../models/ExerciseSummaryResponse';
import type { RecordStepRequest } from '../models/RecordStepRequest';
import type { ScenarioListResponse } from '../models/ScenarioListResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class PurpleTeamService {
    /**
     * Create a purple team exercise
     * Create a new purple team exercise from a pre-built scenario.
     * Returns the full exercise object including all steps.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createExerciseApiV1PurpleTeamExercisesPost(
        requestBody: CreateExerciseRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/purple-team/exercises',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List all exercises
     * @param status Filter by status
     * @param category Filter by scenario category
     * @returns ExerciseSummaryResponse Successful Response
     * @throws ApiError
     */
    public static listExercisesApiV1PurpleTeamExercisesGet(
        status?: (string | null),
        category?: (string | null),
    ): CancelablePromise<Array<ExerciseSummaryResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/purple-team/exercises',
            query: {
                'status': status,
                'category': category,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get a specific exercise
     * @param exerciseId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getExerciseApiV1PurpleTeamExercisesExerciseIdGet(
        exerciseId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/purple-team/exercises/{exercise_id}',
            path: {
                'exercise_id': exerciseId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Start (run) an exercise
     * Transitions exercise from draft/planned → active.
     * Records the start timestamp.
     * @param exerciseId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static runExerciseApiV1PurpleTeamExercisesExerciseIdRunPost(
        exerciseId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/purple-team/exercises/{exercise_id}/run',
            path: {
                'exercise_id': exerciseId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Record detection result for an attack step
     * Record whether ALDECI detected a specific attack step.
     * Captures: outcome, detection engine, alert fired, time to detect.
     * Exercise must be in 'active' status.
     * @param exerciseId
     * @param stepIndex
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static recordStepResultApiV1PurpleTeamExercisesExerciseIdStepsStepIndexPost(
        exerciseId: string,
        stepIndex: number,
        requestBody: RecordStepRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/purple-team/exercises/{exercise_id}/steps/{step_index}',
            path: {
                'exercise_id': exerciseId,
                'step_index': stepIndex,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Add a blue team containment/response action
     * Log a blue team response action for a specific attack step.
     * Tracks: action type, actor, effectiveness, timestamp.
     * @param exerciseId
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static addBlueTeamActionApiV1PurpleTeamExercisesExerciseIdResponsePost(
        exerciseId: string,
        requestBody: BlueTeamActionRequest,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/purple-team/exercises/{exercise_id}/response',
            path: {
                'exercise_id': exerciseId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Complete exercise and compute scores + gaps
     * Mark the exercise as complete. Automatically:
     * - Computes red/blue team scores (detection rate, MTTD, coverage score)
     * - Identifies detection gaps (undetected steps → backlog)
     * Returns the completed exercise with scores and gap list.
     * @param exerciseId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static completeExerciseApiV1PurpleTeamExercisesExerciseIdCompletePost(
        exerciseId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/purple-team/exercises/{exercise_id}/complete',
            path: {
                'exercise_id': exerciseId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Generate after-action report
     * Generate a full after-action report for a completed exercise.
     * Includes executive summary, technique-by-technique results,
     * tactic coverage breakdown, detection gaps, and recommended improvements.
     * @param exerciseId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getReportApiV1PurpleTeamExercisesExerciseIdReportGet(
        exerciseId: string,
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/purple-team/exercises/{exercise_id}/report',
            path: {
                'exercise_id': exerciseId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List pre-built attack scenarios
     * Returns the built-in scenario library (30+ scenarios).
     * Each scenario has pre-mapped MITRE ATT&CK techniques and estimated duration.
     * @param category Filter by category (e.g. ransomware, cloud_breach)
     * @returns ScenarioListResponse Successful Response
     * @throws ApiError
     */
    public static listScenariosApiV1PurpleTeamScenariosGet(
        category?: (string | null),
    ): CancelablePromise<Array<ScenarioListResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/purple-team/scenarios',
            query: {
                'category': category,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
