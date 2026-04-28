/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__ir_playbook_runner_router__ExecutePlaybookRequest } from '../models/apps__api__ir_playbook_runner_router__ExecutePlaybookRequest';
import type { ExecutionResponse } from '../models/ExecutionResponse';
import type { PlaybookLibraryEntry } from '../models/PlaybookLibraryEntry';
import type { StepOverrideRequest } from '../models/StepOverrideRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class IrPlaybookRunnerService {
    /**
     * Execute Playbook
     * Trigger an IR playbook for an incident. Executes all steps synchronously and returns the full execution record with per-step results. Available playbooks: phishing_response, ransomware_response, data_exfiltration, unauthorized_access, malware_detected.
     * @param requestBody
     * @returns ExecutionResponse Successful Response
     * @throws ApiError
     */
    public static executePlaybookApiV1PlaybooksExecutePost(
        requestBody: apps__api__ir_playbook_runner_router__ExecutePlaybookRequest,
    ): CancelablePromise<ExecutionResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/playbooks/execute',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Execution Status
     * Get the current status and step results for a specific playbook execution.
     * @param executionId
     * @returns ExecutionResponse Successful Response
     * @throws ApiError
     */
    public static getExecutionApiV1PlaybooksExecutionExecutionIdGet(
        executionId: string,
    ): CancelablePromise<ExecutionResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/playbooks/execution/{execution_id}',
            path: {
                'execution_id': executionId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Playbook Library
     * Return all 5 built-in IR playbooks with their trigger conditions, step definitions, and action types.
     * @returns PlaybookLibraryEntry Successful Response
     * @throws ApiError
     */
    public static listLibraryApiV1PlaybooksLibraryGet(): CancelablePromise<Array<PlaybookLibraryEntry>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/playbooks/library',
        });
    }
    /**
     * Manual Step Override
     * Analyst manually marks a step as overridden (completed or skipped). Useful when automated action fails but analyst completed it manually.
     * @param executionId
     * @param stepId
     * @param requestBody
     * @returns ExecutionResponse Successful Response
     * @throws ApiError
     */
    public static manualStepOverrideApiV1PlaybooksExecutionExecutionIdStepStepIdOverridePost(
        executionId: string,
        stepId: string,
        requestBody: StepOverrideRequest,
    ): CancelablePromise<ExecutionResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/playbooks/execution/{execution_id}/step/{step_id}/override',
            path: {
                'execution_id': executionId,
                'step_id': stepId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
