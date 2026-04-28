/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__workflow_router__WorkflowCreate } from '../models/apps__api__workflow_router__WorkflowCreate';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class WorkflowEngineService {
    /**
     * List Workflows
     * List workflows, optionally filtered by org_id and trigger type.
     * @param orgId
     * @param triggerType
     * @param status
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listWorkflowsApiV1WorkflowsGet(
        orgId: string = 'default',
        triggerType?: (string | null),
        status?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/workflows',
            query: {
                'org_id': orgId,
                'trigger_type': triggerType,
                'status': status,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create Workflow
     * Create a new workflow.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createWorkflowApiV1WorkflowsPost(
        requestBody: apps__api__workflow_router__WorkflowCreate,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/workflows',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
