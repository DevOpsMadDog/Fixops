/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ApprovePolicyRequest } from '../models/ApprovePolicyRequest';
import type { apps__api__policy_generator_router__PolicyResponse } from '../models/apps__api__policy_generator_router__PolicyResponse';
import type { apps__api__policy_generator_router__UpdatePolicyRequest } from '../models/apps__api__policy_generator_router__UpdatePolicyRequest';
import type { GeneratePolicyRequest } from '../models/GeneratePolicyRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class PolicyGeneratorService {
    /**
     * Generate Policy
     * Auto-generate a security policy document from built-in best-practice templates.
     *
     * Returns a DRAFT policy that can be reviewed, edited, and approved.
     * @param requestBody
     * @returns apps__api__policy_generator_router__PolicyResponse Successful Response
     * @throws ApiError
     */
    public static generatePolicyApiV1PolicyGeneratorGeneratePost(
        requestBody: GeneratePolicyRequest,
    ): CancelablePromise<apps__api__policy_generator_router__PolicyResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/policy-generator/generate',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * List Policies
     * List all policy documents for an organisation.
     * @param orgId Organisation ID
     * @returns apps__api__policy_generator_router__PolicyResponse Successful Response
     * @throws ApiError
     */
    public static listPoliciesApiV1PolicyGeneratorPoliciesGet(
        orgId: string = 'default',
    ): CancelablePromise<Array<apps__api__policy_generator_router__PolicyResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/policy-generator/policies',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Policies Due Review
     * Return policies that are overdue for review (review_date is in the past).
     * @param orgId Organisation ID
     * @returns apps__api__policy_generator_router__PolicyResponse Successful Response
     * @throws ApiError
     */
    public static getPoliciesDueReviewApiV1PolicyGeneratorPoliciesDueReviewGet(
        orgId: string = 'default',
    ): CancelablePromise<Array<apps__api__policy_generator_router__PolicyResponse>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/policy-generator/policies/due-review',
            query: {
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Get Policy
     * Retrieve a single policy document by ID.
     * @param policyId
     * @returns apps__api__policy_generator_router__PolicyResponse Successful Response
     * @throws ApiError
     */
    public static getPolicyApiV1PolicyGeneratorPoliciesPolicyIdGet(
        policyId: string,
    ): CancelablePromise<apps__api__policy_generator_router__PolicyResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/policy-generator/policies/{policy_id}',
            path: {
                'policy_id': policyId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Update Policy
     * Update the Markdown content of an existing policy document.
     * @param policyId
     * @param requestBody
     * @returns apps__api__policy_generator_router__PolicyResponse Successful Response
     * @throws ApiError
     */
    public static updatePolicyApiV1PolicyGeneratorPoliciesPolicyIdContentPut(
        policyId: string,
        requestBody: apps__api__policy_generator_router__UpdatePolicyRequest,
    ): CancelablePromise<apps__api__policy_generator_router__PolicyResponse> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/policy-generator/policies/{policy_id}/content',
            path: {
                'policy_id': policyId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Approve Policy
     * Approve a policy document.
     *
     * Sets status to ACTIVE, records the approver, and sets effective_date to now.
     * @param policyId
     * @param requestBody
     * @returns apps__api__policy_generator_router__PolicyResponse Successful Response
     * @throws ApiError
     */
    public static approvePolicyApiV1PolicyGeneratorPoliciesPolicyIdApprovePost(
        policyId: string,
        requestBody: ApprovePolicyRequest,
    ): CancelablePromise<apps__api__policy_generator_router__PolicyResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/policy-generator/policies/{policy_id}/approve',
            path: {
                'policy_id': policyId,
            },
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Archive Policy
     * Archive a policy document (marks it as ARCHIVED).
     * @param policyId
     * @returns apps__api__policy_generator_router__PolicyResponse Successful Response
     * @throws ApiError
     */
    public static archivePolicyApiV1PolicyGeneratorPoliciesPolicyIdArchivePost(
        policyId: string,
    ): CancelablePromise<apps__api__policy_generator_router__PolicyResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/policy-generator/policies/{policy_id}/archive',
            path: {
                'policy_id': policyId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
    /**
     * Export Policy
     * Export a policy document in Markdown or HTML format.
     *
     * Returns plain text for Markdown, HTML response for HTML format.
     * @param policyId
     * @param format Export format: 'markdown' or 'html'
     * @returns any Successful Response
     * @throws ApiError
     */
    public static exportPolicyApiV1PolicyGeneratorPoliciesPolicyIdExportGet(
        policyId: string,
        format: string = 'markdown',
    ): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/policy-generator/policies/{policy_id}/export',
            path: {
                'policy_id': policyId,
            },
            query: {
                'format': format,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
