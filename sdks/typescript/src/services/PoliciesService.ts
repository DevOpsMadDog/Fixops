/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__policies_router__PolicyResponse } from '../models/apps__api__policies_router__PolicyResponse';
import type { apps__api__policies_router__PolicyUpdate } from '../models/apps__api__policies_router__PolicyUpdate';
import type { EnableToggleRequest } from '../models/EnableToggleRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class PoliciesService {
    /**
     * Get Policy
     * Get policy details by ID.
     * @param id
     * @returns apps__api__policies_router__PolicyResponse Successful Response
     * @throws ApiError
     */
    public static getPolicyApiV1PoliciesIdGet(
        id: string,
    ): CancelablePromise<apps__api__policies_router__PolicyResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/policies/{id}',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update Policy
     * Update a policy.
     * @param id
     * @param requestBody
     * @returns apps__api__policies_router__PolicyResponse Successful Response
     * @throws ApiError
     */
    public static updatePolicyApiV1PoliciesIdPut(
        id: string,
        requestBody: apps__api__policies_router__PolicyUpdate,
    ): CancelablePromise<apps__api__policies_router__PolicyResponse> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/policies/{id}',
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
     * Delete Policy
     * Delete a policy.
     * @param id
     * @returns void
     * @throws ApiError
     */
    public static deletePolicyApiV1PoliciesIdDelete(
        id: string,
    ): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/policies/{id}',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Validate Policy
     * Validate policy syntax and rules.
     *
     * Deep-validates conditions, operators, actions, and structure.
     * @param id
     * @returns any Successful Response
     * @throws ApiError
     */
    public static validatePolicyApiV1PoliciesIdValidatePost(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/policies/{id}/validate',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Test Policy
     * Test policy against sample data (dry-run).
     *
     * Provide {"items": [...]} to evaluate the policy conditions.
     * @param id
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static testPolicyApiV1PoliciesIdTestPost(
        id: string,
        requestBody: Record<string, any>,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/policies/{id}/test',
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
     * Get Policy Violations
     * Get recorded policy violations.
     * @param id
     * @param limit
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getPolicyViolationsApiV1PoliciesIdViolationsGet(
        id: string,
        limit: number = 100,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/policies/{id}/violations',
            path: {
                'id': id,
            },
            query: {
                'limit': limit,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Enforce Policy
     * Auto-enforce a policy against current findings.
     *
     * Evaluates the policy against all open findings and records violations.
     * @param id
     * @returns any Successful Response
     * @throws ApiError
     */
    public static enforcePolicyApiV1PoliciesIdEnforcePost(
        id: string,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/policies/{id}/enforce',
            path: {
                'id': id,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Simulate Policies
     * Simulate ALL active policies against test data (bulk dry-run).
     *
     * Provide {"items": [...]} to evaluate all active policies.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static simulatePoliciesApiV1PoliciesSimulatePost(
        requestBody: Record<string, any>,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/policies/simulate',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Detect Conflicts
     * Detect conflicts between overlapping policies.
     *
     * Finds policies whose conditions overlap on the same fields with
     * contradictory actions (e.g., one blocks, another allows).
     * @returns any Successful Response
     * @throws ApiError
     */
    public static detectConflictsApiV1PoliciesConflictsGet(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/policies/conflicts',
        });
    }
    /**
     * List All Violations
     * List all policy violations across all policies in the past N days.
     * @param limit
     * @param days
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listAllViolationsApiV1PoliciesViolationsGet(
        limit: number = 100,
        days: number = 30,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/policies/violations',
            query: {
                'limit': limit,
                'days': days,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Toggle Policy Enabled
     * Enable or disable a policy without full update.
     * @param id
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static togglePolicyEnabledApiV1PoliciesIdEnablePut(
        id: string,
        requestBody: EnableToggleRequest,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/policies/{id}/enable',
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
}
