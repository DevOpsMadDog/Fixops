/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__ai_orchestrator_router__CreateTaskRequest } from '../models/apps__api__ai_orchestrator_router__CreateTaskRequest';
import type { ConsensusRequest } from '../models/ConsensusRequest';
import type { ContextRequirementRequest } from '../models/ContextRequirementRequest';
import type { ExecuteTaskResponse } from '../models/ExecuteTaskResponse';
import type { PipelineRequest } from '../models/PipelineRequest';
import type { PreflightRequest } from '../models/PreflightRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class AiOrchestratorService {
    /**
     * Create an agent task
     * Create a new agent task (does not execute it yet).
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createTaskApiV1AiOrchestratorTasksPost(
        requestBody: apps__api__ai_orchestrator_router__CreateTaskRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/ai-orchestrator/tasks',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List task history
     * Return task history, optionally filtered by role and status.
     * @param role Filter by agent role
     * @param status Filter by status: pending|running|completed|failed
     * @param limit
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listTasksApiV1AiOrchestratorTasksGet(
        role?: (string | null),
        status?: (string | null),
        limit: number = 50,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/ai-orchestrator/tasks',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'role': role,
                'status': status,
                'limit': limit,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Execute a pending task
     * Run the task through the LLM agent and return the result.
     * @param taskId
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns ExecuteTaskResponse Successful Response
     * @throws ApiError
     */
    public static executeTaskApiV1AiOrchestratorTasksTaskIdExecutePost(
        taskId: string,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<ExecuteTaskResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/ai-orchestrator/tasks/{task_id}/execute',
            path: {
                'task_id': taskId,
            },
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get task status and result
     * Retrieve a task by ID.
     * @param taskId
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns ExecuteTaskResponse Successful Response
     * @throws ApiError
     */
    public static getTaskApiV1AiOrchestratorTasksTaskIdGet(
        taskId: string,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<ExecuteTaskResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/ai-orchestrator/tasks/{task_id}',
            path: {
                'task_id': taskId,
            },
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Multi-agent consensus on a security decision
     * Query multiple agent roles and return a consensus decision.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static multiAgentConsensusApiV1AiOrchestratorConsensusPost(
        requestBody: ConsensusRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/ai-orchestrator/consensus',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Sequential agent pipeline
     * Execute tasks sequentially. Each task receives the previous result in its context.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static chainPipelineApiV1AiOrchestratorPipelineChainPost(
        requestBody: PipelineRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/ai-orchestrator/pipeline/chain',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Parallel agent pipeline
     * Execute all tasks concurrently and return results.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static parallelPipelineApiV1AiOrchestratorPipelineParallelPost(
        requestBody: PipelineRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/ai-orchestrator/pipeline/parallel',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Consensus agreement statistics
     * Return consensus agreement rates and decision distribution for the org.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static consensusStatsApiV1AiOrchestratorStatsGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/ai-orchestrator/stats',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * GAP-061: Register/upsert per-rule LLM context tier
     * Assign an LLM context tier (metadata/targeted/full_file) to a rule.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static registerContextRequirementApiV1AiOrchestratorContextRequirementPost(
        requestBody: ContextRequirementRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/ai-orchestrator/context-requirement',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * GAP-061: List registered rule context requirements
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listContextRequirementsApiV1AiOrchestratorContextRequirementsGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/ai-orchestrator/context-requirements',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * GAP-061: Pre-flight LLM cost estimate for a set of rules
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static preflightEstimateApiV1AiOrchestratorPreflightEstimatePost(
        requestBody: PreflightRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/ai-orchestrator/preflight-estimate',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'org_id': orgId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
