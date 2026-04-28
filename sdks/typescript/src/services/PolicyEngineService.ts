/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__policy_engine_router__CreatePolicyRequest } from '../models/apps__api__policy_engine_router__CreatePolicyRequest';
import type { apps__api__policy_engine_router__EvaluateRequest } from '../models/apps__api__policy_engine_router__EvaluateRequest';
import type { apps__api__policy_engine_router__UpdatePolicyRequest } from '../models/apps__api__policy_engine_router__UpdatePolicyRequest';
import type { apps__api__policy_router__EvaluateRequest } from '../models/apps__api__policy_router__EvaluateRequest';
import type { apps__api__policy_router__PolicyCreate } from '../models/apps__api__policy_router__PolicyCreate';
import type { EvaluateBatchRequest } from '../models/EvaluateBatchRequest';
import type { ImportPoliciesRequest } from '../models/ImportPoliciesRequest';
import type { PolicyScope } from '../models/PolicyScope';
import type { TestPolicyRequest } from '../models/TestPolicyRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class PolicyEngineService {
    /**
     * List Policies
     * List policies for an org, optionally filtered by scope.
     * @param orgId
     * @param scope
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listPoliciesApiV1PoliciesGet(
        orgId: string = 'default',
        scope?: (string | null),
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/policies',
            query: {
                'org_id': orgId,
                'scope': scope,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create Policy
     * Create a new policy.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createPolicyApiV1PoliciesPost(
        requestBody: apps__api__policy_router__PolicyCreate,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/policies',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Evaluate Policy
     * Evaluate input data against all enabled policies for the given scope.
     * @param requestBody
     * @returns any Successful Response
     * @throws ApiError
     */
    public static evaluatePolicyApiV1PoliciesEvaluatePost(
        requestBody: apps__api__policy_router__EvaluateRequest,
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/policies/evaluate',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Create Policy
     * Create a new policy.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static createPolicyApiV1PolicyEnginePoliciesPost(
        requestBody: apps__api__policy_engine_router__CreatePolicyRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/policy-engine/policies',
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
     * List Policies
     * List all policies for the org, optionally filtered by scope.
     * @param scope Filter by scope
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static listPoliciesApiV1PolicyEnginePoliciesGet(
        scope?: (PolicyScope | null),
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/policy-engine/policies',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'scope': scope,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Policy
     * Retrieve a single policy by ID.
     * @param policyId
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getPolicyApiV1PolicyEnginePoliciesPolicyIdGet(
        policyId: string,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/policy-engine/policies/{policy_id}',
            path: {
                'policy_id': policyId,
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
     * Update Policy
     * Update a policy (version auto-incremented).
     * @param policyId
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static updatePolicyApiV1PolicyEnginePoliciesPolicyIdPut(
        policyId: string,
        requestBody: apps__api__policy_engine_router__UpdatePolicyRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/policy-engine/policies/{policy_id}',
            path: {
                'policy_id': policyId,
            },
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
     * Delete Policy
     * Delete a policy.
     * @param policyId
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns void
     * @throws ApiError
     */
    public static deletePolicyApiV1PolicyEnginePoliciesPolicyIdDelete(
        policyId: string,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/v1/policy-engine/policies/{policy_id}',
            path: {
                'policy_id': policyId,
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
     * Evaluate
     * Evaluate input data against all enabled policies for the given scope.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static evaluateApiV1PolicyEngineEvaluatePost(
        requestBody: apps__api__policy_engine_router__EvaluateRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/policy-engine/evaluate',
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
     * Evaluate Batch
     * Evaluate a list of inputs against policies. Returns one result per input.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static evaluateBatchApiV1PolicyEngineEvaluateBatchPost(
        requestBody: EvaluateBatchRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/policy-engine/evaluate/batch',
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
     * Test Policy
     * Dry-run a policy definition against test input without persisting.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static testPolicyApiV1PolicyEngineTestPost(
        requestBody: TestPolicyRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/policy-engine/test',
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
     * Get Evaluation History
     * Return past evaluations, optionally filtered by policy.
     * @param policyId Filter by policy ID
     * @param limit
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getEvaluationHistoryApiV1PolicyEngineHistoryGet(
        policyId?: (string | null),
        limit: number = 100,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/policy-engine/history',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'policy_id': policyId,
                'limit': limit,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Policy Stats
     * Return aggregate policy and evaluation statistics.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getPolicyStatsApiV1PolicyEngineStatsGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/policy-engine/stats',
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
     * Import Policies
     * Bulk-import policies from a JSON string.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static importPoliciesApiV1PolicyEngineImportPost(
        requestBody: ImportPoliciesRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/policy-engine/import',
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
     * Export Policies
     * Export all org policies as JSON.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static exportPoliciesApiV1PolicyEngineExportGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/policy-engine/export',
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
}
