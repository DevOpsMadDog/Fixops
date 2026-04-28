/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__pr_gate_router__EvaluateRequest } from '../models/apps__api__pr_gate_router__EvaluateRequest';
import type { apps__api__pr_gate_router__ReportRequest } from '../models/apps__api__pr_gate_router__ReportRequest';
import type { apps__api__pr_gate_router__ReportResponse } from '../models/apps__api__pr_gate_router__ReportResponse';
import type { apps__api__pr_gate_router__ScanRequest } from '../models/apps__api__pr_gate_router__ScanRequest';
import type { CIGateRequest } from '../models/CIGateRequest';
import type { EvaluateResponse } from '../models/EvaluateResponse';
import type { GatingPolicy } from '../models/GatingPolicy';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class PrGateService {
    /**
     * Evaluate Gate
     * Evaluate findings against the gating policy.
     *
     * Returns a pass/fail/warn verdict with details on blocking findings.
     * Use this to check whether a PR or build should be allowed to proceed.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns EvaluateResponse Successful Response
     * @throws ApiError
     */
    public static evaluateGateApiV1PrGateEvaluatePost(
        requestBody: apps__api__pr_gate_router__EvaluateRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<EvaluateResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/pr-gate/evaluate',
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
     * Report To Pr
     * Post findings to a GitHub PR via check run and/or comment.
     *
     * Creates a GitHub Check Run with inline annotations for each finding,
     * and optionally posts a summary comment on the PR.
     *
     * Requires GITHUB_TOKEN env var with `checks:write` scope.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns apps__api__pr_gate_router__ReportResponse Successful Response
     * @throws ApiError
     */
    public static reportToPrApiV1PrGateReportPost(
        requestBody: apps__api__pr_gate_router__ReportRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<apps__api__pr_gate_router__ReportResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/pr-gate/report',
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
     * Scan And Gate
     * One-shot: trigger native scanners → evaluate → report to GitHub PR.
     *
     * Runs the requested scan types against the repository, evaluates findings
     * against the gating policy, and posts results back to the PR.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static scanAndGateApiV1PrGateScanPost(
        requestBody: apps__api__pr_gate_router__ScanRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/pr-gate/scan',
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
     * Get Policy
     * Get the current PR gating policy for the organisation.
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getPolicyApiV1PrGatePolicyGet(
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/pr-gate/policy',
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
     * Update the PR gating policy for the organisation.
     *
     * Controls what severity levels block merges and builds.
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static updatePolicyApiV1PrGatePolicyPut(
        requestBody: GatingPolicy,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/v1/pr-gate/policy',
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
     * Ci Gate
     * CI/CD gate evaluation endpoint.
     *
     * Call this from your CI/CD pipeline to get a pass/fail verdict.
     * Returns exit_code: 0 (pass), 1 (fail), 2 (warn).
     *
     * Usage in CI:
     * curl -X POST $ALDECI_URL/api/v1/pr-gate/ci-gate \
     * -H 'X-API-Key: $TOKEN' \
     * -d '{"findings": [...]}' | jq '.exit_code'
     * @param requestBody
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static ciGateApiV1PrGateCiGatePost(
        requestBody: CIGateRequest,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/v1/pr-gate/ci-gate',
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
     * Get History
     * Get recent gate evaluation history for the organisation.
     * @param limit Maximum results
     * @param orgId Organization ID (query parameter, overrides header)
     * @param xOrgId Organization ID (header)
     * @returns any Successful Response
     * @throws ApiError
     */
    public static getHistoryApiV1PrGateHistoryGet(
        limit: number = 20,
        orgId?: (string | null),
        xOrgId?: (string | null),
    ): CancelablePromise<Record<string, any>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/v1/pr-gate/history',
            headers: {
                'X-Org-ID': xOrgId,
            },
            query: {
                'limit': limit,
                'org_id': orgId,
            },
            errors: {
                422: `Validation Error`,
            },
        });
    }
}
