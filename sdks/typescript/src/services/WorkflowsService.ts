/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__workflows_router__WorkflowUpdate } from '../models/apps__api__workflows_router__WorkflowUpdate';
import type { WorkflowExecutionResponse } from '../models/WorkflowExecutionResponse';
import type { WorkflowResponse } from '../models/WorkflowResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class WorkflowsService {
    /**
     * Get Workflow
     * Get workflow details by ID.
     * @param id
     * @returns WorkflowResponse Successful Response
     * @throws ApiError
     */
    public static getWorkflowApiV1WorkflowsIdGet(
        id: string,
    ): CancelablePromise<WorkflowResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/workflows/{id}',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update Workflow
     * Update a workflow.
     * @param id
     * @param requestBody
     * @returns WorkflowResponse Successful Response
     * @throws ApiError
     */
    public static updateWorkflowApiV1WorkflowsIdPut(
        id: string,
        requestBody: apps__api__workflows_router__WorkflowUpdate,
    ): CancelablePromise<WorkflowResponse> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/workflows/{id}',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Delete Workflow
     * Delete a workflow.
     * @param id
     * @returns void
     * @throws ApiError
     */
    public static deleteWorkflowApiV1WorkflowsIdDelete(
        id: string,
    ): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/workflows/{id}',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Execute Workflow
     * Execute a workflow with real step-by-step processing.
     *
     * Supports conditional branching, retries with exponential back-off,
     * parallel step groups, and SLA deadline checking.
     * @param id
     * @param requestBody
     * @returns WorkflowExecutionResponse Successful Response
     * @throws ApiError
     */
    public static executeWorkflowApiV1WorkflowsIdExecutePost(
        id: string,
        requestBody?: (Record<string, any> | null),
    ): CancelablePromise<WorkflowExecutionResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/workflows/{id}/execute',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Workflow History
     * Get workflow execution history.
     * @param id
     * @param limit
     * @param offset
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getWorkflowHistoryApiV1WorkflowsIdHistoryGet(
        id: string,
        limit: number = 100,
        offset?: number,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/workflows/{id}/history',
            path: {
                'id': id,
            },
            query: {
                'limit': limit,
                'offset': offset,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Set Workflow Sla
     * Set SLA configuration for a workflow.
     *
     * Config: {max_duration_seconds, notification_channels, escalation_policy}.
     * @param id
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static setWorkflowSlaApiV1WorkflowsIdSlaPut(
        id: string,
        requestBody: Record<string, any>,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/workflows/{id}/sla',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Workflow Sla
     * Get SLA configuration for a workflow.
     * @param id
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getWorkflowSlaApiV1WorkflowsIdSlaGet(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/workflows/{id}/sla',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Pause Execution
     * Pause a running workflow execution.
     * @param execId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static pauseExecutionApiV1WorkflowsExecutionsExecIdPausePost(
        execId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/workflows/executions/{exec_id}/pause',
            path: {
                'exec_id': execId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Resume Execution
     * Resume a paused workflow execution.
     * @param execId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static resumeExecutionApiV1WorkflowsExecutionsExecIdResumePost(
        execId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/workflows/executions/{exec_id}/resume',
            path: {
                'exec_id': execId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Execution Timeline
     * Get detailed step-by-step timeline for an execution.
     * @param execId
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getExecutionTimelineApiV1WorkflowsExecutionsExecIdTimelineGet(
        execId: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/workflows/executions/{exec_id}/timeline',
            path: {
                'exec_id': execId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
