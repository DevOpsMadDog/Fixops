/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class WorkflowsGapService {
    /**
     * List Workflow Rules
     * List automation workflow rules from WorkflowDB.
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listWorkflowRulesApiV1WorkflowsRulesGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/workflows/rules',
        });
    }
}
